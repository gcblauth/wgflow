"""Parser for ACL entries.

Accepted forms:
    10.0.5.22                single host, any port/proto
    10.0.5.0/24              network, any port/proto
    10.0.5.22:5432/tcp       host, specific port + proto
    10.0.5.0/24:443/tcp      network, specific port + proto

Hostnames are intentionally unsupported (see design discussion).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import List, Optional

_ENTRY_RE = re.compile(
    r"""
    ^
    (?P<host>[0-9./]+)                   # IP or CIDR
    (?: : (?P<port>\d{1,5})              # optional :port
        / (?P<proto>tcp|udp)             # mandatory /proto when port given
    )?
    $
    """,
    re.VERBOSE | re.IGNORECASE,
)


class ACLParseError(ValueError):
    pass


@dataclass(frozen=True)
class ACLEntry:
    cidr: str               # always in CIDR form, e.g. "10.0.5.22/32"
    port: Optional[int]     # None means any
    proto: Optional[str]    # None means any, else "tcp" or "udp"

    def __str__(self) -> str:
        base = self.cidr
        if self.port is not None:
            base += f":{self.port}/{self.proto}"
        return base


def parse_entry(raw: str) -> ACLEntry:
    raw = raw.strip()
    if not raw:
        raise ACLParseError("empty ACL entry")

    m = _ENTRY_RE.match(raw)
    if not m:
        raise ACLParseError(f"invalid ACL syntax: {raw!r}")

    host = m.group("host")
    port_s = m.group("port")
    proto = m.group("proto")

    # Normalise to CIDR. Bare IPs become /32.
    try:
        if "/" in host:
            net = ipaddress.IPv4Network(host, strict=False)
            cidr = str(net)
        else:
            ip = ipaddress.IPv4Address(host)
            cidr = f"{ip}/32"
    except (ipaddress.AddressValueError, ValueError) as e:
        raise ACLParseError(f"invalid IP/CIDR in {raw!r}: {e}") from e

    port: Optional[int] = None
    if port_s is not None:
        port = int(port_s)
        if not 1 <= port <= 65535:
            raise ACLParseError(f"port out of range in {raw!r}")

    return ACLEntry(cidr=cidr, port=port, proto=proto.lower() if proto else None)


def parse_list(raw: str) -> List[ACLEntry]:
    """Parse a comma-separated list. Blanks are ignored."""
    if not raw:
        return []
    return [parse_entry(p) for p in raw.split(",") if p.strip()]
