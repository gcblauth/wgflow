"""Parser for ACL entries.

Accepted forms:
    10.0.5.22                single host, any port/proto        (allow)
    10.0.5.0/24              network, any port/proto             (allow)
    10.0.5.22:5432/tcp       host, specific port + proto        (allow)
    10.0.5.0/24:443/tcp      network, specific port + proto     (allow)
    !10.0.5.22               single host — DENY                 (deny)
    !10.0.5.0/24:443/tcp     network, port + proto — DENY       (deny)

The ! prefix signals a deny rule. Deny entries are rendered as iptables
DROP rules BEFORE allow rules in the per-peer chain. If any deny entry
exists, a catch-all ACCEPT is appended at the end of the chain so that
everything not explicitly denied is allowed — this is the full-tunnel
model. Without deny entries the chain stays allow-only (split-tunnel).

Hostnames are intentionally unsupported.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import List, Optional

_ENTRY_RE = re.compile(
    r"""
    ^
    (?P<bang>!)?                             # optional deny prefix
    (?P<host>[0-9./]+)                       # IP or CIDR
    (?: : (?P<port>\d{1,5})                  # optional :port
        / (?P<proto>tcp|udp)                 # mandatory /proto when port given
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
    action: str = "allow"   # "allow" or "deny"

    def __str__(self) -> str:
        base = ("!" if self.action == "deny" else "") + self.cidr
        if self.port is not None:
            base += f":{self.port}/{self.proto}"
        return base

    @property
    def is_deny(self) -> bool:
        return self.action == "deny"


def parse_entry(raw: str) -> ACLEntry:
    raw = raw.strip()
    if not raw:
        raise ACLParseError("empty ACL entry")

    m = _ENTRY_RE.match(raw)
    if not m:
        raise ACLParseError(f"invalid ACL syntax: {raw!r}")

    action = "deny" if m.group("bang") else "allow"
    host   = m.group("host")
    port_s = m.group("port")
    proto  = m.group("proto")

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

    return ACLEntry(
        cidr=cidr,
        port=port,
        proto=proto.lower() if proto else None,
        action=action,
    )


def parse_list(raw: str) -> List[ACLEntry]:
    """Parse a comma-separated list. Blanks are ignored."""
    if not raw:
        return []
    return [parse_entry(p) for p in raw.split(",") if p.strip()]


def has_any_deny(entries: List[ACLEntry]) -> bool:
    """True if any entry is a deny — signals full-tunnel ACL intent."""
    return any(e.is_deny for e in entries)
