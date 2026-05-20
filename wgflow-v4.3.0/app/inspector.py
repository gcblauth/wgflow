"""Connection inspection helpers.

Two responsibilities:
    1. Reverse DNS for endpoint IPs, with a per-process cache. Lookups happen
       in a thread (socket.gethostbyaddr blocks). Cache TTL is 24h; misses are
       cached as None for 5 minutes so we don't re-look-up dead names every
       modal open.

    2. Live flow listing via `conntrack -L -s <peer-ip>`. Filters the host's
       connection tracking table to flows originating at this peer's wg
       address. Output is parsed into structured records.
"""
from __future__ import annotations

import asyncio
import re
import socket
import subprocess
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Reverse DNS with cache
# ---------------------------------------------------------------------------

# ip -> (hostname-or-None, expires_at)
_RDNS_CACHE: Dict[str, Tuple[Optional[str], float]] = {}
_RDNS_TTL_HIT = 24 * 3600    # cache successful lookups for 24h
_RDNS_TTL_MISS = 5 * 60      # don't re-try dead lookups for 5 minutes
_RDNS_TIMEOUT = 1.5          # seconds — we don't want to block the modal


def _do_lookup(ip: str) -> Optional[str]:
    """Synchronous reverse DNS. Called from a thread."""
    socket.setdefaulttimeout(_RDNS_TIMEOUT)
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None
    finally:
        socket.setdefaulttimeout(None)


async def reverse_dns(ip: str) -> Optional[str]:
    """Cached reverse-DNS lookup. Safe to call from async code."""
    now = time.time()
    cached = _RDNS_CACHE.get(ip)
    if cached and cached[1] > now:
        return cached[0]

    host = await asyncio.to_thread(_do_lookup, ip)
    ttl = _RDNS_TTL_HIT if host else _RDNS_TTL_MISS
    _RDNS_CACHE[ip] = (host, now + ttl)
    return host


# ---------------------------------------------------------------------------
# conntrack flow listing
# ---------------------------------------------------------------------------

@dataclass
class Flow:
    proto: str          # 'tcp', 'udp', 'icmp', etc.
    src: str            # original source ip
    src_port: Optional[int]
    dst: str            # original destination ip (= what the peer asked for)
    dst_port: Optional[int]
    state: Optional[str]    # tcp state if applicable
    age_seconds: int        # how long the flow has been tracked
    packets: int            # bytes/packets across both directions if available
    bytes: int


# conntrack -L output for a single flow looks roughly like:
#   tcp      6 86399 ESTABLISHED src=10.13.13.5 dst=10.0.5.22 sport=51234 dport=5432 ...
#   udp      17 29 src=10.13.13.5 dst=8.8.8.8 sport=37123 dport=53 packets=1 bytes=64 ...
#
# Fields after the protocol number are: timeout, then state (tcp only), then
# space-separated key=value pairs. Everything in a single line.
_FLOW_PROTO_RE = re.compile(r"^\s*(tcp|udp|icmp|icmpv6)\s+\d+\s+(\d+)\s+(.+)$")
_KV_RE = re.compile(r"(\w+)=([^\s]+)")
_TCP_STATE_RE = re.compile(
    r"^(ESTABLISHED|SYN_SENT|SYN_RECV|FIN_WAIT|CLOSE_WAIT|LAST_ACK|TIME_WAIT|CLOSE|LISTEN|CLOSING)\s+"
)


def _parse_conntrack_line(line: str) -> Optional[Flow]:
    m = _FLOW_PROTO_RE.match(line)
    if not m:
        return None
    proto = m.group(1)
    timeout = int(m.group(2))
    rest = m.group(3)

    state: Optional[str] = None
    state_m = _TCP_STATE_RE.match(rest)
    if state_m:
        state = state_m.group(1)
        rest = rest[state_m.end():]

    kv = dict(_KV_RE.findall(rest))

    # conntrack prints original tuple first, then reply tuple. We want the
    # original src/dst (what the peer initiated). Both tuples use the same
    # key names so the dict() above keeps the LAST one — we need to bias to
    # the FIRST. Re-find ordered.
    pairs = _KV_RE.findall(rest)
    first_src = first_dst = first_sport = first_dport = None
    for k, v in pairs:
        if k == "src" and first_src is None: first_src = v
        elif k == "dst" and first_dst is None: first_dst = v
        elif k == "sport" and first_sport is None: first_sport = int(v)
        elif k == "dport" and first_dport is None: first_dport = int(v)

    if not first_src or not first_dst:
        return None

    # packets / bytes may appear once per direction; sum them.
    pkts = sum(int(v) for k, v in pairs if k == "packets")
    byt = sum(int(v) for k, v in pairs if k == "bytes")

    # `age` is not directly given. conntrack's first field after proto is
    # the timeout (seconds remaining). Default-conntrack timeouts:
    #   tcp ESTABLISHED: 5 days, others vary; udp: 30s; icmp: 30s.
    # We can derive a rough "age" from (default_timeout - remaining), but
    # the default depends on the kernel. We just expose `timeout` here — it
    # is what most operators actually want anyway ("how long until this dies").
    return Flow(
        proto=proto,
        src=first_src,
        src_port=first_sport,
        dst=first_dst,
        dst_port=first_dport,
        state=state,
        age_seconds=timeout,   # see note above; this is "seconds-until-expire"
        packets=pkts,
        bytes=byt,
    )


def list_flows(source_ip: str, limit: int = 200) -> List[Flow]:
    """Return up to `limit` flows whose original source matches `source_ip`.

    `source_ip` should be the bare peer address ("10.13.13.5", no /32).

    We deliberately do NOT pass `-o extended` because that prepends an L3
    family token ("ipv4 2 tcp 6 ...") which breaks the parser regex. The
    default format is what we want: "tcp 6 86399 ESTABLISHED src=...".
    """
    proc = subprocess.run(
        ["conntrack", "-L", "-s", source_ip],
        capture_output=True, text=True, check=False,
    )
    # conntrack writes the table to stdout and a status summary line
    # ("conntrack v1.x.x: N flow entries have been shown.") to stderr.
    # We only want stdout.
    output = proc.stdout
    flows: List[Flow] = []
    for line in output.splitlines():
        if not line.strip() or line.startswith("conntrack v"):
            continue
        f = _parse_conntrack_line(line)
        if f:
            flows.append(f)
            if len(flows) >= limit:
                break
    return flows


def conntrack_available() -> bool:
    """Quick probe used by the API to skip the conntrack call when the
    binary is missing or the kernel module isn't loaded."""
    try:
        proc = subprocess.run(
            ["conntrack", "--version"],
            capture_output=True, text=True, check=False, timeout=1.0,
        )
        return proc.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# ---------------------------------------------------------------------------
# Raw `wg show` block for one peer (text)
# ---------------------------------------------------------------------------

def wg_peer_block(interface: str, public_key: str) -> str:
    """Return the human-readable `wg show` block for a single peer.

    `wg show` does not have a per-peer flag, but it groups output by peer.
    We grab the full output and slice the relevant section. Cheap.
    """
    proc = subprocess.run(
        ["wg", "show", interface],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        return f"(wg show failed: {proc.stderr.strip()})"

    # Output looks like:
    #   interface: wg0
    #     public key: ...
    #     ...
    #
    #   peer: <pubkey>
    #     endpoint: ...
    #     allowed ips: ...
    #     latest handshake: ...
    #     transfer: 1.23 MiB received, 4.56 MiB sent
    #     persistent keepalive: every 25 seconds
    #
    #   peer: <other>
    #     ...
    sections = re.split(r"\n(?=peer: )", proc.stdout)
    for sect in sections:
        if sect.startswith(f"peer: {public_key}"):
            return sect.strip()
    return f"(no live state for peer {public_key[:16]}...)"
