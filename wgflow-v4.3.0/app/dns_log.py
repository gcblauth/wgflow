"""DNS query log capture from dnsmasq.

dnsmasq, run with `log-queries=extra`, emits multi-line records per query
with a shared correlation ID. Sample lines:

    Apr 25 14:32:18 dnsmasq[42]: 1234 10.13.13.5/47291 query[A] github.com from 10.13.13.5
    Apr 25 14:32:18 dnsmasq[42]: 1234 10.13.13.5/47291 forwarded github.com to 8.8.8.8
    Apr 25 14:32:18 dnsmasq[42]: 1234 10.13.13.5/47291 reply github.com is 140.82.121.3
    Apr 25 14:32:18 dnsmasq[42]: 1234 10.13.13.5/47291 reply github.com is 140.82.121.4

The `1234` after the pid is dnsmasq's per-query correlation ID. We hold
in-flight queries in a small dict keyed by ID, append answers as they come,
and flush the record once we see the terminal "reply" / "config" / "cached"
event (or after a timeout — some queries never get a reply).

Output goes to:
  - process-global ring buffer (last N records, all peers)
  - per-peer-IP ring buffer (last M records each)
  - sqlite, deduplicated to one row per (peer, name, type) per minute.

The tailer is an asyncio task started in main.py's lifespan.
"""
from __future__ import annotations

import asyncio
import re
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Deque, Dict, List, Optional


# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

LOG_PATH = Path("/var/log/dnsmasq.log")
GLOBAL_RING_SIZE = 1000           # last N queries across all peers
PEER_RING_SIZE = 200              # last M per peer
INFLIGHT_TIMEOUT = 30             # seconds before we give up on a pending query
PERSIST_DEDUP_WINDOW = 60         # seconds — same query within this window aggregates


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

# Match everything after `dnsmasq[pid]: `. Capturing the correlation ID,
# the client IP (may be missing for system-internal queries), and the rest.
# Examples handled:
#   "1234 10.13.13.5/47291 query[A] github.com from 10.13.13.5"
#   "1234 10.13.13.5/47291 forwarded github.com to 8.8.8.8"
#   "1234 10.13.13.5/47291 reply github.com is 140.82.121.3"
#   "1234 10.13.13.5/47291 cached github.com is 140.82.121.3"
#   "1234 10.13.13.5/47291 config github.com is NXDOMAIN-IPv4"
#   "1234 10.13.13.5/47291 /etc/dnsmasq.d/blocklist.hosts ads.example.com is 0.0.0.0"
_LINE_RE = re.compile(
    r"""
    dnsmasq\[\d+\]:\s+
    (?P<qid>\d+)\s+
    (?:(?P<src_ip>[\d.:a-fA-F]+)/(?P<src_port>\d+)\s+)?
    (?P<rest>.+)
    """,
    re.VERBOSE,
)

# query[TYPE] NAME from IP
_QUERY_RE = re.compile(r"^query\[(?P<qtype>\w+)\]\s+(?P<name>\S+)\s+from\s+\S+")
# reply NAME is ANSWER
_REPLY_RE = re.compile(r"^reply\s+(?P<name>\S+)\s+is\s+(?P<answer>.+)$")
# cached NAME is ANSWER
_CACHED_RE = re.compile(r"^cached\s+(?P<name>\S+)\s+is\s+(?P<answer>.+)$")
# config NAME is ANSWER (NXDOMAIN responses come through here)
_CONFIG_RE = re.compile(r"^config\s+(?P<name>\S+)\s+is\s+(?P<answer>.+)$")
# /path/to/blocklist NAME is 0.0.0.0  — local hosts-file match (= blocked)
_HOSTS_RE = re.compile(r"^/\S+\s+(?P<name>\S+)\s+is\s+(?P<answer>.+)$")


@dataclass
class DNSQuery:
    """A single resolved DNS query, joined from multiple log lines."""
    ts: float                       # first-seen unix timestamp
    peer_ip: Optional[str]          # source IP from the log
    query_name: str
    query_type: str                 # A, AAAA, PTR, etc.
    answers: List[str] = field(default_factory=list)
    source: str = "upstream"        # 'upstream' | 'cached' | 'blocked' | 'local'
    completed: bool = False         # True once we've seen the terminal log line


# ---------------------------------------------------------------------------
# Tailer + state
# ---------------------------------------------------------------------------

class DNSLog:
    """Shared runtime state for the DNS log. One instance, attached in main."""

    def __init__(self) -> None:
        self.global_ring: Deque[DNSQuery] = deque(maxlen=GLOBAL_RING_SIZE)
        self.peer_rings: Dict[str, Deque[DNSQuery]] = {}
        self._inflight: Dict[str, DNSQuery] = {}    # qid -> partial query
        self._inflight_seen: Dict[str, float] = {}  # qid -> first-seen ts
        self._task: Optional[asyncio.Task] = None
        self._db = None
        self._peer_id_lookup = None     # callable(peer_ip) -> peer_id|None

    def start(self, db, peer_id_lookup) -> None:
        self._db = db
        self._peer_id_lookup = peer_id_lookup
        self._task = asyncio.get_event_loop().create_task(self._run(), name="wgflow-dns")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    # ---------------- accessors ----------------------------------------------

    def recent_global(self, limit: int = 100) -> List[Dict]:
        items = list(self.global_ring)[-limit:]
        items.reverse()                 # newest first
        return [self._to_dict(q) for q in items]

    def recent_for_peer_ip(self, peer_ip: str, limit: int = 50) -> List[Dict]:
        ring = self.peer_rings.get(peer_ip)
        if not ring:
            return []
        items = list(ring)[-limit:]
        items.reverse()
        return [self._to_dict(q) for q in items]

    def history_for_peer_id(self, peer_id: int, limit: int = 200) -> List[Dict]:
        """Pull from sqlite for older history beyond the in-memory ring."""
        if self._db is None:
            return []
        rows = self._db.conn.execute(
            """SELECT ts, query_name, query_type, answer, source, count
               FROM dns_queries WHERE peer_id = ? ORDER BY ts DESC LIMIT ?""",
            (peer_id, limit),
        ).fetchall()
        return [
            {
                "ts": r["ts"],
                "query_name": r["query_name"],
                "query_type": r["query_type"],
                "answers": r["answer"].split(";") if r["answer"] else [],
                "source": r["source"],
                "count": r["count"],
            }
            for r in rows
        ]

    @staticmethod
    def _to_dict(q: DNSQuery) -> Dict:
        return {
            "ts": q.ts,
            "peer_ip": q.peer_ip,
            "query_name": q.query_name,
            "query_type": q.query_type,
            "answers": q.answers,
            "source": q.source,
        }

    # ---------------- core loop ----------------------------------------------

    async def _run(self) -> None:
        """Tail the dnsmasq log forever. Recover from rotations / truncations."""
        while True:
            try:
                if not LOG_PATH.exists():
                    # Log file may not be there immediately after dnsmasq starts.
                    await asyncio.sleep(1.0)
                    continue
                await self._tail_loop()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                print(f"[dns_log] tailer error: {e!r}", flush=True)
                await asyncio.sleep(2.0)

    async def _tail_loop(self) -> None:
        """One pass over the file; returns when the file disappears or rotates."""
        # asyncio doesn't have a great file-tailing primitive, so we use a
        # thread pool reader. For a low-rate text log this is fine.
        offset = LOG_PATH.stat().st_size       # start at end (we don't replay history)
        last_inode = LOG_PATH.stat().st_ino

        while True:
            await asyncio.sleep(0.3)            # poll cadence

            # Check for log rotation by inode change.
            try:
                st = LOG_PATH.stat()
            except FileNotFoundError:
                return                          # outer loop will recover

            if st.st_ino != last_inode or st.st_size < offset:
                # Rotation or truncation: reset to start.
                offset = 0
                last_inode = st.st_ino

            if st.st_size <= offset:
                # Periodically expire stale in-flight queries even when idle.
                self._reap_inflight()
                continue

            # Read the new chunk.
            new_data = await asyncio.to_thread(self._read_chunk, offset, st.st_size)
            offset = st.st_size

            for line in new_data.splitlines():
                self._handle_line(line)

            self._reap_inflight()

    def _read_chunk(self, start: int, end: int) -> str:
        with open(LOG_PATH, "r", errors="replace") as f:
            f.seek(start)
            return f.read(end - start)

    # ---------------- line handler -------------------------------------------

    def _handle_line(self, line: str) -> None:
        m = _LINE_RE.search(line)
        if not m:
            return
        qid = m.group("qid")
        src_ip = m.group("src_ip")
        rest = m.group("rest")

        # Identify the line stage.
        q_match = _QUERY_RE.match(rest)
        if q_match:
            qry = DNSQuery(
                ts=time.time(),
                peer_ip=src_ip,
                query_name=q_match.group("name"),
                query_type=q_match.group("qtype"),
            )
            self._inflight[qid] = qry
            self._inflight_seen[qid] = qry.ts
            return

        # Try the various reply-shaped lines in order.
        for regex, source in (
            (_HOSTS_RE,  "blocked"),    # local hosts-file match (blocklist)
            (_CACHED_RE, "cached"),
            (_REPLY_RE,  "upstream"),
            (_CONFIG_RE, "local"),      # NXDOMAIN, dnssec config replies
        ):
            rm = regex.match(rest)
            if not rm:
                continue
            qry = self._inflight.get(qid)
            if qry is None:
                # Reply without a matching query — happens after restart, or
                # when the log was rotated mid-query. Skip it.
                return
            qry.answers.append(rm.group("answer"))
            qry.source = source

            # The "reply" / "cached" / "config" / hosts-file lines mark the
            # end of a query in dnsmasq's protocol. Multiple replies (e.g.
            # multi-record answers) repeat this stage with different answers,
            # but we still want to flush after the FIRST so the UI sees it
            # promptly. We mark it complete and continue updating answers
            # in-place via the rings (they hold references).
            if not qry.completed:
                qry.completed = True
                self._publish(qid, qry)
            return

        # Lines we don't care about (e.g. "forwarded ... to ..."); ignore.

    def _publish(self, qid: str, qry: DNSQuery) -> None:
        # Push into rings.
        self.global_ring.append(qry)
        if qry.peer_ip:
            ring = self.peer_rings.setdefault(qry.peer_ip, deque(maxlen=PEER_RING_SIZE))
            ring.append(qry)

        # Persist (deduplicated by minute).
        if self._db is not None:
            self._persist(qry)

        # Drop from in-flight; keep the entry in the ring so subsequent
        # multi-answer reply lines can still .append() to qry.answers.
        self._inflight.pop(qid, None)
        self._inflight_seen.pop(qid, None)

    def _persist(self, qry: DNSQuery) -> None:
        # Resolve peer_id from peer_ip if we know how.
        peer_id = None
        if qry.peer_ip and self._peer_id_lookup:
            try:
                peer_id = self._peer_id_lookup(qry.peer_ip)
            except Exception:
                pass

        # Bucket to the start of the current minute.
        ts_minute = int(qry.ts // 60) * 60
        answer = ";".join(qry.answers) if qry.answers else None

        try:
            with self._db.write() as conn:
                # Upsert: if the same (minute, peer_ip, name, type) exists,
                # bump the count rather than inserting a new row.
                conn.execute(
                    """INSERT INTO dns_queries
                       (ts, peer_id, peer_ip, query_name, query_type, answer, source, count)
                       VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                       ON CONFLICT(ts, peer_ip, query_name, query_type)
                       DO UPDATE SET count = count + 1,
                                     answer = COALESCE(excluded.answer, answer),
                                     peer_id = COALESCE(excluded.peer_id, peer_id)""",
                    (ts_minute, peer_id, qry.peer_ip, qry.query_name,
                     qry.query_type, answer, qry.source),
                )
        except Exception as e:
            # Persistence is best-effort; log and move on so the tailer
            # never falls behind because of a sqlite hiccup.
            print(f"[dns_log] persist error: {e!r}", flush=True)

    def _reap_inflight(self) -> None:
        """Drop in-flight queries that never completed (server didn't reply,
        log line we didn't parse, etc.) so the dict doesn't grow forever."""
        if not self._inflight_seen:
            return
        cutoff = time.time() - INFLIGHT_TIMEOUT
        stale = [qid for qid, ts in self._inflight_seen.items() if ts < cutoff]
        for qid in stale:
            qry = self._inflight.pop(qid, None)
            self._inflight_seen.pop(qid, None)
            # Surface the query even if we never got an answer — it still
            # tells you the lookup happened.
            if qry is not None and not qry.completed:
                qry.completed = True
                qry.source = "no-reply"
                self.global_ring.append(qry)
                if qry.peer_ip:
                    ring = self.peer_rings.setdefault(qry.peer_ip, deque(maxlen=PEER_RING_SIZE))
                    ring.append(qry)

    # ---------------- retention ----------------------------------------------

    def prune(self, retention_seconds: int) -> int:
        """Delete sqlite rows older than the cutoff. Returns rows deleted."""
        if self._db is None:
            return 0
        cutoff = int(time.time() - retention_seconds)
        with self._db.write() as conn:
            cur = conn.execute("DELETE FROM dns_queries WHERE ts < ?", (cutoff,))
            return cur.rowcount or 0
