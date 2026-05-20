"""Multi-source blocklist management (v4.1).

A blocklist source is a URL returning a hosts-format text file. Operators
can subscribe to as many as they want; on refresh, the app fetches every
enabled source, parses entries, deduplicates across all sources, and
writes a single merged file to /etc/dnsmasq.d/blocklist.hosts. dnsmasq
picks up the new file on SIGHUP — `addn-hosts` is reload-friendly,
unlike `address=` directives which are not (see dns_overrides.py for
the corresponding workaround there).

This module is concerned with sources, not with overrides. The two are
distinct: blocklist sources blackhole domains globally for the resolver;
overrides set explicit address mappings (see dns_overrides.py) and run
through a different mechanism (the BEGIN/END marker dance in
/etc/dnsmasq.conf because address= doesn't reload on SIGHUP).
"""
from __future__ import annotations

import os
import re
import signal
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Set, Tuple

import httpx


# Where dnsmasq reads the merged blocklist from. Matches the build-time
# path in the Dockerfile so first-boot behavior is preserved: if the
# operator never clicks "refresh" we keep serving whatever the image
# was built with. The file is rewritten atomically on every refresh.
BLOCKLIST_PATH = Path("/etc/dnsmasq.d/blocklist.hosts")

# What we write at the top of the merged file. Useful for operators
# inspecting the file by hand to confirm wgflow generated it.
HEADER_COMMENT = """\
# wgflow merged blocklist — DO NOT EDIT BY HAND
#
# Regenerated each time the operator clicks "refresh" in the blocklist
# panel. Source entries are deduplicated across every enabled source.
# Merge metadata + per-source counts are persisted in the wgflow
# sqlite under blocklist_sources and network_settings. Operators
# wanting custom permanent entries should use the DNS overrides
# feature (which writes into /etc/dnsmasq.conf via BEGIN/END markers),
# not edit this file.
"""

# HTTP timeout for fetching a single source. Real-world hosts files are
# typically 1-10 MB; 30 seconds is generous for slow links and tight
# enough that a hung CDN doesn't block the operator's refresh forever.
FETCH_TIMEOUT = 30.0

# Maximum size we'll accept from a single source. Defends against an
# operator-supplied URL that returns multi-GB content. 25 MB ≈ 1M
# entries which is well above any realistic hosts list. We could
# enforce via Content-Length, but some servers omit it; we instead
# stream and abort.
MAX_SOURCE_BYTES = 25 * 1024 * 1024


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

# Match a hosts-file line:
#   optional IP prefix, then one or more space-separated hostnames,
#   optional trailing # comment.
# Accepts `0.0.0.0 host`, `127.0.0.1 host`, `::1 host`, `host` (no IP).
_LINE_RE = re.compile(
    r"^\s*"
    r"(?:(?P<ip>[0-9a-fA-F:.]+)\s+)?"   # optional IP prefix
    r"(?P<rest>[^\#\n]+)"                # hostnames + optional whitespace
    r"(?:\#.*)?$"                        # optional trailing comment
)

# Per-hostname validation. Domains we accept must look like real
# fully-qualified domain names: lowercase letters, digits, hyphens,
# dots; non-empty; not all-digits (skip bare IPs); no underscores.
# We're deliberately strict — better to drop a marginal entry than
# to write garbage into dnsmasq's addn-hosts file (which then fails
# to parse and breaks blocking entirely).
_HOSTNAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}(\.[a-z0-9][a-z0-9-]{0,62})+$")

# Hostnames we never want to block. Localhost is the canonical example
# — many hosts files start with `127.0.0.1 localhost` to set up the
# loopback alias, and reading those into our blocklist would blackhole
# the local machine's own resolution.
_NEVER_BLOCK = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "broadcasthost",
}


class AdblockFormatError(ValueError):
    """Raised when a source returns Adblock Plus syntax (||domain^).

    dnsmasq's addn-hosts only understands hosts-format. We reject the
    whole source with a clear error rather than silently dropping
    everything we can't parse — a half-imported list is worse than a
    refused one because the operator thinks blocking is in effect when
    it mostly isn't.
    """


def parse_hosts_text(text: str) -> Set[str]:
    """Parse a hosts-format text into a set of lowercased domain strings.

    Raises AdblockFormatError if the source appears to use Adblock Plus
    syntax (lines starting with `||`). Drops malformed lines silently —
    real-world hosts lists routinely contain commented-out entries,
    trailing whitespace artifacts, and the occasional non-FQDN that
    we don't want polluting the merged file.
    """
    domains: Set[str] = set()
    saw_adblock_marker = False

    # Cheap sniff: if the first 50 non-empty non-comment lines contain
    # `||`, this is an Adblock Plus list. We don't try to convert —
    # the operator gets a clean error and can paste a hosts-format
    # variant of the same blocklist (most popular lists publish both).
    sniffed = 0
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("||"):
            saw_adblock_marker = True
            break
        sniffed += 1
        if sniffed > 50:
            break
    if saw_adblock_marker:
        raise AdblockFormatError(
            "source appears to use Adblock Plus syntax (||domain^); "
            "wgflow's dnsmasq backend only supports hosts-file format"
        )

    for raw in text.splitlines():
        m = _LINE_RE.match(raw)
        if not m:
            continue
        rest = m.group("rest").strip()
        if not rest:
            continue
        # `rest` may contain multiple hostnames separated by whitespace.
        for token in rest.split():
            host = token.lower().strip(".")
            if not host:
                continue
            if host in _NEVER_BLOCK:
                continue
            if not _HOSTNAME_RE.match(host):
                continue
            domains.add(host)

    return domains


# ---------------------------------------------------------------------------
# Presets
# ---------------------------------------------------------------------------

# Curated selection. Seeded on first run if the table is empty. Names
# are operator-facing labels; URLs target the source's "raw" or
# "plain" hosts format. We intentionally don't ship a "kitchen-sink
# everything" preset — operators should think about which categories
# they want to block, not just enable all and discover later that some
# legitimate site is unreachable.

PRESETS: List[Tuple[str, str, bool]] = [
    # name, url, default-enabled
    (
        "stevenblack-ads",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        True,    # default ON to preserve existing v4.0 behavior
    ),
    (
        "stevenblack-ads-porn",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
        False,
    ),
    (
        "stevenblack-ads-gambling",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts",
        False,
    ),
    (
        "urlhaus-malware",
        "https://urlhaus.abuse.ch/downloads/hostfile/",
        False,
    ),
    (
        "oisd-big",
        "https://big.oisd.nl/",
        False,
    ),
]


def seed_presets(conn) -> int:
    """Insert preset rows if the table is empty. Returns rows inserted.

    Idempotent — once seeded, won't re-add even if the operator deletes
    a preset and reseeds via a fresh migration. We check for "is the
    table totally empty?" rather than "is each individual preset
    present?" so deleted presets stay deleted (operator intent
    respected).
    """
    existing = conn.execute(
        "SELECT COUNT(*) FROM blocklist_sources"
    ).fetchone()[0]
    if existing > 0:
        return 0
    inserted = 0
    for name, url, enabled in PRESETS:
        conn.execute(
            "INSERT INTO blocklist_sources "
            "(name, url, enabled, is_preset) VALUES (?, ?, ?, 1)",
            (name, url, 1 if enabled else 0),
        )
        inserted += 1
    return inserted


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------

@dataclass
class FetchResult:
    """Outcome of fetching a single source."""
    status: str                    # 'fetched' | 'unchanged' | 'error'
    domains: Optional[Set[str]]    # None if unchanged or error
    new_etag: Optional[str]
    error: Optional[str]
    raw_bytes: int                 # for diagnostics; 0 on unchanged/error


async def fetch_source(
    url: str,
    last_etag: Optional[str],
    client: httpx.AsyncClient,
) -> FetchResult:
    """Fetch a single source URL.

    Sends If-None-Match if we have an etag from a previous successful
    fetch. On 304 returns status='unchanged' (caller reuses cached
    parse). On 200 returns the parsed domain set plus the new etag.
    On any error returns status='error' with the message.

    The parser runs on the response body before this function returns —
    we don't store raw bodies anywhere. AdblockFormatError surfaces as
    a 'error' result with a friendly message.
    """
    headers = {}
    if last_etag:
        headers["If-None-Match"] = last_etag

    try:
        # Stream so we can enforce MAX_SOURCE_BYTES without holding the
        # whole response in memory if it's enormous (defensive).
        async with client.stream("GET", url, headers=headers,
                                 timeout=FETCH_TIMEOUT,
                                 follow_redirects=True) as resp:
            if resp.status_code == 304:
                return FetchResult(status="unchanged", domains=None,
                                   new_etag=last_etag, error=None,
                                   raw_bytes=0)
            if resp.status_code != 200:
                return FetchResult(
                    status="error", domains=None, new_etag=None,
                    error=f"HTTP {resp.status_code}",
                    raw_bytes=0,
                )
            chunks: List[bytes] = []
            total = 0
            async for chunk in resp.aiter_bytes():
                total += len(chunk)
                if total > MAX_SOURCE_BYTES:
                    return FetchResult(
                        status="error", domains=None, new_etag=None,
                        error=f"source exceeds {MAX_SOURCE_BYTES // (1024*1024)}MB cap",
                        raw_bytes=total,
                    )
                chunks.append(chunk)
            body = b"".join(chunks).decode("utf-8", errors="replace")
            new_etag = resp.headers.get("ETag")
    except httpx.HTTPError as e:
        return FetchResult(
            status="error", domains=None, new_etag=None,
            error=f"{type(e).__name__}: {e}", raw_bytes=0,
        )

    try:
        domains = parse_hosts_text(body)
    except AdblockFormatError as e:
        return FetchResult(
            status="error", domains=None, new_etag=None,
            error=str(e), raw_bytes=total,
        )

    return FetchResult(
        status="fetched", domains=domains, new_etag=new_etag,
        error=None, raw_bytes=total,
    )


# ---------------------------------------------------------------------------
# Merge + write
# ---------------------------------------------------------------------------

@dataclass
class MergeSummary:
    """Returned from refresh_all() for the API to shape into a response."""
    total_sources_attempted: int
    sources_fetched: int
    sources_unchanged: int
    sources_error: int
    merged_unique_count: int
    per_source: List[dict]   # rows for the UI: id, name, status, count, overlap, error


async def refresh_all(conn, client: httpx.AsyncClient) -> MergeSummary:
    """Fetch every enabled source, merge, write file, signal dnsmasq.

    Order of operations matters for safety:
      1. Fetch all sources concurrently (or sequentially — see note).
      2. Compute the union and per-source overlap.
      3. Write the merged file ATOMICALLY (temp + os.replace) so
         dnsmasq never reads a half-finished file even if SIGHUP fires
         during the write.
      4. SIGHUP dnsmasq.
      5. Update DB rows with new metadata.

    If the file write fails (disk full, permissions), we leave the DB
    untouched — better to surface the error than to record success
    against a file that doesn't exist on disk.

    On the concurrency note: we fetch sequentially. Most operators run
    1-3 sources, so the parallelism savings are small; sequential
    keeps error handling simple and avoids burst-fetching that some
    CDNs interpret as abuse.
    """
    rows = conn.execute(
        "SELECT id, name, url, enabled, last_etag "
        "FROM blocklist_sources WHERE enabled = 1 ORDER BY id"
    ).fetchall()

    per_source = []
    fetched_domains: dict[int, Set[str]] = {}   # source_id → domains
    cached_domains: dict[int, Set[str]] = {}    # source_id → previous parse,
                                                # for 304 unchanged path

    sources_fetched = sources_unchanged = sources_error = 0

    for r in rows:
        result = await fetch_source(r["url"], r["last_etag"], client)
        if result.status == "fetched":
            sources_fetched += 1
            fetched_domains[r["id"]] = result.domains or set()
        elif result.status == "unchanged":
            sources_unchanged += 1
            # We don't cache the parsed set across process restarts
            # (would need to persist or re-parse from disk). Simplest:
            # if 304 unchanged, treat it as "we have no fresh data
            # but also no error" — the previous merged file remains
            # whatever it was; we won't include this source in this
            # round's merge. In practice, since we fetch every enabled
            # source on each refresh, an unchanged source means "you
            # ran refresh twice in a row without the upstream changing"
            # and the merged file from the first run is still on disk,
            # untouched. We DO want to update last_fetched_ts though.
            cached_domains[r["id"]] = set()
        else:
            sources_error += 1
        per_source.append({
            "id": r["id"],
            "name": r["name"],
            "status": result.status,
            "count": len(result.domains) if result.domains else None,
            "error": result.error,
            "new_etag": result.new_etag,
        })

    # Decide whether to actually rewrite the merged file.
    # Rewrite if any source returned 'fetched'. If everything was
    # 'unchanged' or 'error', the on-disk file is still correct
    # (modulo the last successful write) and we leave it alone.
    file_written = False
    merged_unique_count = 0
    overlap_per_source: dict[int, int] = {}
    if sources_fetched > 0:
        # Build the union, track per-source overlap. Overlap = how many
        # of this source's entries are ALSO in some other fetched source.
        all_domains: Set[str] = set()
        for sid, domains in fetched_domains.items():
            all_domains |= domains
        for sid, domains in fetched_domains.items():
            others: Set[str] = set()
            for other_sid, other_domains in fetched_domains.items():
                if other_sid == sid:
                    continue
                others |= other_domains
            overlap_per_source[sid] = len(domains & others)

        # Atomic write.
        _write_merged_file(all_domains)
        file_written = True
        merged_unique_count = len(all_domains)

        # Signal dnsmasq to reload its addn-hosts files.
        _signal_dnsmasq_reload()

    # Persist per-source status. Even error rows get an updated
    # last_fetched_ts and last_error so the UI can display "tried 4
    # minutes ago, failed: HTTP 502" rather than a stale success.
    now = int(time.time())
    for ps in per_source:
        sid = ps["id"]
        if ps["status"] == "fetched":
            conn.execute(
                "UPDATE blocklist_sources SET "
                "last_fetched_ts=?, last_entry_count=?, "
                "last_overlap_count=?, last_error=NULL, last_etag=? "
                "WHERE id=?",
                (now, ps["count"], overlap_per_source.get(sid, 0),
                 ps["new_etag"], sid),
            )
        elif ps["status"] == "unchanged":
            conn.execute(
                "UPDATE blocklist_sources SET "
                "last_fetched_ts=?, last_error=NULL WHERE id=?",
                (now, sid),
            )
            # Augment ps for the response — operators want to see "no
            # change" rather than the count being null.
            ps["overlap"] = None
        else:  # error
            conn.execute(
                "UPDATE blocklist_sources SET "
                "last_fetched_ts=?, last_error=? WHERE id=?",
                (now, (ps["error"] or "")[:500], sid),
            )

        # For the response: include overlap so the UI can show "this
        # list adds N net new entries on top of what you already had".
        ps["overlap"] = overlap_per_source.get(sid)

    if file_written:
        conn.execute(
            "INSERT OR REPLACE INTO network_settings(key, value) VALUES (?, ?)",
            ("blocklist_last_merged_ts", str(now)),
        )
        conn.execute(
            "INSERT OR REPLACE INTO network_settings(key, value) VALUES (?, ?)",
            ("blocklist_last_merged_count", str(merged_unique_count)),
        )

    return MergeSummary(
        total_sources_attempted=len(per_source),
        sources_fetched=sources_fetched,
        sources_unchanged=sources_unchanged,
        sources_error=sources_error,
        merged_unique_count=merged_unique_count,
        per_source=per_source,
    )


def _write_merged_file(domains: Set[str]) -> None:
    """Atomic write to BLOCKLIST_PATH. Sorted so diffs between refreshes
    are meaningful for an operator inspecting the file."""
    tmp_path = BLOCKLIST_PATH.with_suffix(BLOCKLIST_PATH.suffix + ".tmp")
    BLOCKLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(HEADER_COMMENT)
        f.write(f"# generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
        f.write(f"# entries:   {len(domains)}\n#\n")
        for d in sorted(domains):
            # 0.0.0.0 is the dnsmasq-friendly sinkhole (returns NXDOMAIN-
            # equivalent behavior; some clients deal better with this
            # than 127.0.0.1).
            f.write(f"0.0.0.0 {d}\n")
    os.replace(tmp_path, BLOCKLIST_PATH)


def _signal_dnsmasq_reload() -> None:
    """SIGHUP dnsmasq so it re-reads addn-hosts files.

    Unlike `address=` directives (where SIGHUP doesn't reload — see
    dns_overrides.py for the kill+respawn workaround), `addn-hosts` is
    properly reload-friendly: dnsmasq re-stats the file on SIGHUP and
    re-reads if mtime changed. atomic-write + SIGHUP is the standard
    pattern.

    If we can't find the dnsmasq pid (container started without dnsmasq
    enabled, or dnsmasq crashed), this is a soft failure: log to stderr
    but don't raise. The file is on disk; whenever dnsmasq next starts
    it will read it.
    """
    pid_paths = (Path("/run/dnsmasq/dnsmasq.pid"),
                 Path("/var/run/dnsmasq/dnsmasq.pid"),
                 Path("/run/dnsmasq.pid"))
    for p in pid_paths:
        if not p.exists():
            continue
        try:
            pid = int(p.read_text().strip())
            os.kill(pid, signal.SIGHUP)
            return
        except (OSError, ValueError) as e:
            print(f"[blocklist] failed to SIGHUP dnsmasq via {p}: {e}",
                  flush=True)
    # Fallback: pgrep-equivalent. We don't shell out — read /proc.
    try:
        for proc in Path("/proc").iterdir():
            if not proc.name.isdigit():
                continue
            comm_path = proc / "comm"
            if not comm_path.exists():
                continue
            try:
                if comm_path.read_text().strip() == "dnsmasq":
                    os.kill(int(proc.name), signal.SIGHUP)
                    return
            except (OSError, ValueError):
                continue
    except Exception as e:
        print(f"[blocklist] /proc scan for dnsmasq failed: {e}", flush=True)
    print("[blocklist] no dnsmasq process found to SIGHUP — "
          "merged file written but not yet active", flush=True)
