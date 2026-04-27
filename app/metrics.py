"""Metrics collection.

Runs a single asyncio task (the `collector`) that wakes every 1s and:
    1. Reads host vitals from /proc and /sys (pure file reads)
    2. Shells out to `wg show <if> dump` to get per-peer rx/tx counters
    3. Shells out to `iptables -L <chain> -x -v -n` per peer chain to get
       per-ACL-rule hit counters
    4. Computes per-second deltas from the previous sample
    5. Pushes the snapshot into an in-memory ring buffer (300 samples = 5min)
    6. Every 10 ticks, writes an aggregate row to sqlite
    7. Every hour, prunes sqlite rows older than 24h

The collector is started on FastAPI lifespan startup and cancelled on shutdown.
Every consumer (WS handler, REST endpoints) reads the shared `State` object.
"""
from __future__ import annotations

import asyncio
import re
import subprocess
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Deque, Dict, List, Optional, Tuple

from .config import SETTINGS

# ---------------------------------------------------------------------------
# Data shapes
# ---------------------------------------------------------------------------

@dataclass
class HostVitals:
    cpu_pct: float = 0.0
    mem_pct: float = 0.0
    mem_used_bytes: int = 0
    mem_total_bytes: int = 0
    load1: float = 0.0
    load5: float = 0.0
    load15: float = 0.0
    # wg0 interface stats from /sys/class/net/wg0/statistics/
    if_rx_bytes: int = 0
    if_tx_bytes: int = 0
    if_rx_packets: int = 0
    if_tx_packets: int = 0
    if_rx_errors: int = 0
    if_tx_errors: int = 0
    if_rx_drops: int = 0
    if_tx_drops: int = 0


@dataclass
class PeerMetric:
    public_key: str
    endpoint: Optional[str]
    latest_handshake: int
    rx_bytes: int
    tx_bytes: int
    rx_rate: float = 0.0       # bytes/sec, derived
    tx_rate: float = 0.0


@dataclass
class ACLHit:
    cidr: str
    port: Optional[int]
    proto: Optional[str]
    pkts: int
    bytes: int


@dataclass
class Snapshot:
    """One full tick of measurements."""
    ts: float                                   # unix, fractional seconds
    peers: Dict[str, PeerMetric] = field(default_factory=dict)  # keyed by pubkey
    host: HostVitals = field(default_factory=HostVitals)
    acl_hits: Dict[int, List[ACLHit]] = field(default_factory=dict)  # peer_id -> rules


@dataclass
class ThroughputPoint:
    """Aggregate point for the global throughput chart."""
    ts: float
    rx_rate: float     # bytes/sec
    tx_rate: float
    peers_online: int
    peers_total: int


# ---------------------------------------------------------------------------
# Collectors (all sync; called from a thread via asyncio.to_thread)
# ---------------------------------------------------------------------------

def _read_cpu_times() -> Tuple[int, int]:
    """Return (idle+iowait, total) from /proc/stat's first line."""
    with open("/proc/stat") as f:
        parts = f.readline().split()
    # parts = ['cpu', user, nice, system, idle, iowait, irq, softirq, steal, ...]
    vals = [int(x) for x in parts[1:]]
    idle = vals[3] + vals[4]
    total = sum(vals)
    return idle, total


def _read_meminfo() -> Tuple[int, int]:
    """Return (used_bytes, total_bytes)."""
    info: Dict[str, int] = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, v, *_ = line.split()
            info[k.rstrip(":")] = int(v) * 1024  # kB -> bytes
    total = info.get("MemTotal", 0)
    # MemAvailable is what the kernel recommends using over Free+Cached.
    avail = info.get("MemAvailable", info.get("MemFree", 0))
    return total - avail, total


def _read_loadavg() -> Tuple[float, float, float]:
    with open("/proc/loadavg") as f:
        parts = f.read().split()
    return float(parts[0]), float(parts[1]), float(parts[2])


def _read_if_stat(interface: str, name: str) -> int:
    p = Path(f"/sys/class/net/{interface}/statistics/{name}")
    try:
        return int(p.read_text().strip())
    except FileNotFoundError:
        return 0


def _collect_host(interface: str, prev_cpu: Optional[Tuple[int, int]]) -> Tuple[HostVitals, Tuple[int, int]]:
    """Collect host vitals. Returns (vitals, new_cpu_sample) for next delta."""
    idle, total = _read_cpu_times()
    if prev_cpu is None:
        cpu_pct = 0.0
    else:
        prev_idle, prev_total = prev_cpu
        d_idle = idle - prev_idle
        d_total = total - prev_total
        cpu_pct = 100.0 * (1.0 - d_idle / d_total) if d_total > 0 else 0.0

    mem_used, mem_total = _read_meminfo()
    mem_pct = 100.0 * mem_used / mem_total if mem_total else 0.0
    l1, l5, l15 = _read_loadavg()

    v = HostVitals(
        cpu_pct=cpu_pct,
        mem_pct=mem_pct,
        mem_used_bytes=mem_used,
        mem_total_bytes=mem_total,
        load1=l1, load5=l5, load15=l15,
        if_rx_bytes=_read_if_stat(interface, "rx_bytes"),
        if_tx_bytes=_read_if_stat(interface, "tx_bytes"),
        if_rx_packets=_read_if_stat(interface, "rx_packets"),
        if_tx_packets=_read_if_stat(interface, "tx_packets"),
        if_rx_errors=_read_if_stat(interface, "rx_errors"),
        if_tx_errors=_read_if_stat(interface, "tx_errors"),
        if_rx_drops=_read_if_stat(interface, "rx_dropped"),
        if_tx_drops=_read_if_stat(interface, "tx_dropped"),
    )
    return v, (idle, total)


def _collect_peers(interface: str) -> Dict[str, PeerMetric]:
    """Parse `wg show <if> dump` into a dict keyed by public key."""
    proc = subprocess.run(
        ["wg", "show", interface, "dump"],
        capture_output=True, text=True, check=False,
    )
    out: Dict[str, PeerMetric] = {}
    if proc.returncode != 0:
        return out
    lines = proc.stdout.strip().splitlines()
    for line in lines[1:]:  # skip [Interface] header row
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        pub, _psk, endpoint, _allowed, handshake, rx, tx, _keep = parts[:8]
        out[pub] = PeerMetric(
            public_key=pub,
            endpoint=endpoint if endpoint != "(none)" else None,
            latest_handshake=int(handshake),
            rx_bytes=int(rx),
            tx_bytes=int(tx),
        )
    return out


# iptables -L output for a chain looks like:
#   Chain WGFLOW_PEER_3 (1 references)
#    pkts      bytes target     prot opt in     out     source               destination
#       0        0 ACCEPT     tcp  --  *      *       0.0.0.0/0            10.0.5.22            tcp dpt:5432
#      42     3024 ACCEPT     all  --  *      *       0.0.0.0/0            10.0.5.0/24
#
# We parse the pkts, bytes, destination, proto, and optional dpt.
_IPT_ROW_RE = re.compile(
    r"""
    ^\s*
    (?P<pkts>\d+)\s+
    (?P<bytes>\d+)\s+
    ACCEPT\s+
    (?P<proto>\S+)\s+
    \S+\s+                                # opt
    \S+\s+                                # in
    \S+\s+                                # out
    \S+\s+                                # source
    (?P<dest>\S+)                         # destination
    (?:\s+(?P<proto2>tcp|udp)\s+dpt:(?P<port>\d+))?
    """,
    re.VERBOSE,
)


def _parse_iptables_chain(output: str) -> List[ACLHit]:
    hits: List[ACLHit] = []
    for line in output.splitlines():
        m = _IPT_ROW_RE.match(line)
        if not m:
            continue
        dest = m.group("dest")
        if "/" not in dest:
            dest = f"{dest}/32"
        port = m.group("port")
        proto = m.group("proto2")
        # When no dport is specified and proto is "all", set proto to None.
        if proto is None and m.group("proto") != "all":
            proto = m.group("proto") if m.group("proto") in ("tcp", "udp") else None
        hits.append(ACLHit(
            cidr=dest,
            port=int(port) if port else None,
            proto=proto,
            pkts=int(m.group("pkts")),
            bytes=int(m.group("bytes")),
        ))
    return hits


def _collect_acl_hits(peer_ids: List[int]) -> Dict[int, List[ACLHit]]:
    """Batch-read iptables counters for all peer chains.

    One subprocess per peer. Acceptable for up to a few hundred peers; if you
    expect thousands, replace with `iptables-save -c` and parse the full dump.
    """
    result: Dict[int, List[ACLHit]] = {}
    for pid in peer_ids:
        chain = f"WGFLOW_PEER_{pid}"
        proc = subprocess.run(
            ["iptables", "-L", chain, "-x", "-v", "-n"],
            capture_output=True, text=True, check=False,
        )
        if proc.returncode == 0:
            result[pid] = _parse_iptables_chain(proc.stdout)
        else:
            result[pid] = []
    return result


# ---------------------------------------------------------------------------
# Collector task + shared state
# ---------------------------------------------------------------------------

RING_SIZE = 300            # 5 minutes at 1s
SAMPLE_INTERVAL = 1.0      # seconds
PERSIST_EVERY = 10         # ticks between sqlite writes
PRUNE_EVERY = 3600         # seconds between retention prunes
RETENTION_SECONDS = 24 * 3600


class MetricsState:
    """Shared runtime state. One instance, attached to the FastAPI app."""

    def __init__(self) -> None:
        self.ring: Deque[Snapshot] = deque(maxlen=RING_SIZE)
        self.throughput_ring: Deque[ThroughputPoint] = deque(maxlen=RING_SIZE)
        # Per-peer rx/tx sparkline rings, keyed by public key.
        # 60 samples = 60s at 1s cadence. Enough for sparklines.
        self.peer_rings: Dict[str, Deque[ThroughputPoint]] = {}
        self.latest: Optional[Snapshot] = None
        self._task: Optional[asyncio.Task] = None
        self._db = None        # set by start()

    def start(self, db) -> None:
        self._db = db
        loop = asyncio.get_event_loop()
        self._task = loop.create_task(self._run(), name="wgflow-metrics")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _run(self) -> None:
        """Main collector loop."""
        prev_cpu: Optional[Tuple[int, int]] = None
        prev_peers: Dict[str, PeerMetric] = {}
        prev_ts: Optional[float] = None
        tick = 0
        last_prune = time.time()

        while True:
            try:
                start = time.monotonic()

                # All blocking I/O in a thread so the event loop stays responsive.
                host, prev_cpu = await asyncio.to_thread(
                    _collect_host, SETTINGS.interface, prev_cpu
                )
                peers = await asyncio.to_thread(_collect_peers, SETTINGS.interface)

                # ACL hits: do this less often (every 2s is plenty) since it
                # is the most expensive step. Even ticks only.
                acl_hits: Dict[int, List[ACLHit]] = {}
                if tick % 2 == 0 and self._db is not None:
                    peer_ids = [
                        r["id"] for r in self._db.conn.execute(
                            "SELECT id FROM peers WHERE enabled = 1"
                        ).fetchall()
                    ]
                    acl_hits = await asyncio.to_thread(_collect_acl_hits, peer_ids)
                elif self.latest is not None:
                    # Keep the most recent ACL snapshot so consumers always
                    # have something to show.
                    acl_hits = self.latest.acl_hits

                now = time.time()
                snap = Snapshot(ts=now, peers=peers, host=host, acl_hits=acl_hits)

                # Compute per-peer rates from deltas.
                if prev_ts is not None:
                    dt = max(now - prev_ts, 0.001)
                    for pub, pm in peers.items():
                        prev = prev_peers.get(pub)
                        if prev:
                            pm.rx_rate = max(0.0, (pm.rx_bytes - prev.rx_bytes) / dt)
                            pm.tx_rate = max(0.0, (pm.tx_bytes - prev.tx_bytes) / dt)
                        # Push per-peer point into its sparkline ring.
                        ring = self.peer_rings.setdefault(pub, deque(maxlen=60))
                        ring.append(ThroughputPoint(
                            ts=now,
                            rx_rate=pm.rx_rate,
                            tx_rate=pm.tx_rate,
                            peers_online=0, peers_total=0,  # unused here
                        ))

                # Global aggregates.
                total_rx = sum(p.rx_rate for p in peers.values())
                total_tx = sum(p.tx_rate for p in peers.values())
                online = sum(
                    1 for p in peers.values()
                    if p.latest_handshake > 0 and (now - p.latest_handshake) < 180
                )
                point = ThroughputPoint(
                    ts=now,
                    rx_rate=total_rx,
                    tx_rate=total_tx,
                    peers_online=online,
                    peers_total=len(peers),
                )

                self.ring.append(snap)
                self.throughput_ring.append(point)
                self.latest = snap

                # Persist every PERSIST_EVERY ticks.
                if tick > 0 and tick % PERSIST_EVERY == 0 and self._db is not None:
                    await asyncio.to_thread(
                        self._persist_sample, int(now), point, host
                    )
                    # Update the cumulative-traffic singleton with the
                    # current sum-of-peer counters. We feed in raw totals;
                    # the helper figures out delta + reset detection.
                    raw_rx = sum(p.rx_bytes for p in peers.values())
                    raw_tx = sum(p.tx_bytes for p in peers.values())
                    await asyncio.to_thread(
                        self._update_cumulative, int(now), raw_rx, raw_tx
                    )
                    # Also persist last_handshake_at for any peers we've seen
                    # handshake. This is what survives a container restart so
                    # the UI can distinguish "never connected" from "connected
                    # at some point in the past".
                    handshakes_to_persist = {
                        pub: pm.latest_handshake
                        for pub, pm in peers.items()
                        if pm.latest_handshake > 0
                    }
                    if handshakes_to_persist:
                        await asyncio.to_thread(
                            self._persist_handshakes, handshakes_to_persist
                        )

                # Prune hourly.
                if now - last_prune > PRUNE_EVERY and self._db is not None:
                    await asyncio.to_thread(
                        self._prune_old, int(now - RETENTION_SECONDS)
                    )
                    last_prune = now

                prev_peers = peers
                prev_ts = now
                tick += 1

                elapsed = time.monotonic() - start
                await asyncio.sleep(max(0.0, SAMPLE_INTERVAL - elapsed))
            except asyncio.CancelledError:
                raise
            except Exception as e:
                # Never let one bad tick kill the collector. Log + keep going.
                print(f"[metrics] collector error: {e!r}", flush=True)
                await asyncio.sleep(SAMPLE_INTERVAL)

    def _persist_handshakes(self, handshakes: Dict[str, int]) -> None:
        """Update last_handshake_at for peers we've observed handshaking.

        We only ever advance the value forward (max of current vs observed).
        WireGuard's `latest_handshake` resets to 0 on container restart but
        the persisted value should still reflect the true last-seen time.
        """
        assert self._db is not None
        with self._db.write() as conn:
            for pub, ts in handshakes.items():
                conn.execute(
                    """UPDATE peers
                       SET last_handshake_at = MAX(COALESCE(last_handshake_at, 0), ?)
                       WHERE public_key = ?""",
                    (ts, pub),
                )

    def _persist_sample(self, ts: int, point: ThroughputPoint, host: HostVitals) -> None:
        assert self._db is not None
        with self._db.write() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO metrics_samples
                   (ts, rx_bytes_per_s, tx_bytes_per_s, peers_online, peers_total,
                    cpu_pct, mem_pct, load1)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (ts, point.rx_rate, point.tx_rate, point.peers_online,
                 point.peers_total, host.cpu_pct, host.mem_pct, host.load1),
            )

    def _update_cumulative(self, ts: int, raw_rx: int, raw_tx: int) -> None:
        """Accumulate sum-of-peer raw counters into cumulative_traffic.

        Reset detection: WireGuard's per-peer counters live in the kernel
        and reset whenever wg0 is recreated (container restart, peer
        delete-and-recreate). When that happens the new raw value will be
        LESS than the persisted last_raw — we treat that as "delta is
        whatever the current value is" rather than a huge negative jump.

        Edge case: if peers were deleted between ticks, raw_rx may have
        decreased without an actual interface reset. The treatment is the
        same — we conservatively count the new value as the delta, which
        slightly under-counts (we lose the now-deleted peer's last
        unaccounted traffic). Acceptable: the alternative would be to
        track per-peer cumulative which is expensive and rarely useful.
        """
        assert self._db is not None
        with self._db.write() as conn:
            row = conn.execute(
                "SELECT rx_total, tx_total, last_raw_rx, last_raw_tx "
                "FROM cumulative_traffic WHERE id = 1"
            ).fetchone()
            if row is None:
                # First call after a fresh DB. Insert with current as baseline.
                conn.execute(
                    """INSERT INTO cumulative_traffic
                       (id, rx_total, tx_total, rx_offset, tx_offset,
                        last_raw_rx, last_raw_tx, updated_at)
                       VALUES (1, 0, 0, 0, 0, ?, ?, ?)""",
                    (raw_rx, raw_tx, ts),
                )
                return
            # Compute deltas. Negative → reset, treat as new baseline.
            d_rx = raw_rx - row["last_raw_rx"]
            d_tx = raw_tx - row["last_raw_tx"]
            if d_rx < 0:
                d_rx = raw_rx
            if d_tx < 0:
                d_tx = raw_tx
            new_rx_total = row["rx_total"] + d_rx
            new_tx_total = row["tx_total"] + d_tx
            conn.execute(
                """UPDATE cumulative_traffic
                   SET rx_total = ?, tx_total = ?,
                       last_raw_rx = ?, last_raw_tx = ?,
                       updated_at = ?
                   WHERE id = 1""",
                (new_rx_total, new_tx_total, raw_rx, raw_tx, ts),
            )

    def cumulative(self) -> Dict:
        """Read the visible cumulative counters (total minus offset)."""
        if self._db is None:
            return {"rx_bytes": 0, "tx_bytes": 0, "since": 0}
        row = self._db.conn.execute(
            "SELECT rx_total, tx_total, rx_offset, tx_offset, updated_at "
            "FROM cumulative_traffic WHERE id = 1"
        ).fetchone()
        if row is None:
            return {"rx_bytes": 0, "tx_bytes": 0, "since": 0}
        return {
            "rx_bytes": max(0, row["rx_total"] - row["rx_offset"]),
            "tx_bytes": max(0, row["tx_total"] - row["tx_offset"]),
            "since": row["updated_at"],
        }

    def reset_cumulative(self) -> None:
        """Zero the visible counters by setting offset = total. We keep the
        underlying total so future deltas continue to accumulate correctly."""
        if self._db is None:
            return
        with self._db.write() as conn:
            conn.execute(
                """UPDATE cumulative_traffic
                   SET rx_offset = rx_total, tx_offset = tx_total,
                       updated_at = ?
                   WHERE id = 1""",
                (int(time.time()),),
            )

    def _prune_old(self, cutoff_ts: int) -> None:
        assert self._db is not None
        with self._db.write() as conn:
            conn.execute("DELETE FROM metrics_samples WHERE ts < ?", (cutoff_ts,))

    # ---- accessors used by the API/WS layer -------------------------------

    def history(self, seconds: int) -> List[Dict]:
        """Fetch historical samples from sqlite."""
        if self._db is None:
            return []
        cutoff = int(time.time() - seconds)
        rows = self._db.conn.execute(
            """SELECT ts, rx_bytes_per_s, tx_bytes_per_s, peers_online,
                      peers_total, cpu_pct, mem_pct, load1
               FROM metrics_samples WHERE ts >= ? ORDER BY ts""",
            (cutoff,),
        ).fetchall()
        return [dict(r) for r in rows]

    def live_throughput(self) -> List[Dict]:
        """In-memory ring buffer for the live chart."""
        return [
            {
                "ts": p.ts,
                "rx": p.rx_rate,
                "tx": p.tx_rate,
                "online": p.peers_online,
                "total": p.peers_total,
            }
            for p in self.throughput_ring
        ]

    def peer_sparkline(self, public_key: str) -> List[Dict]:
        ring = self.peer_rings.get(public_key)
        if not ring:
            return []
        return [{"ts": p.ts, "rx": p.rx_rate, "tx": p.tx_rate} for p in ring]
