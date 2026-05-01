"""Parser for ACL entries.

Accepted forms:
    10.0.5.22                single host, any port/proto        (allow)
    10.0.5.0/24              network, any port/proto             (allow)
    10.0.5.22:5432/tcp       host, specific port + proto        (allow)
    10.0.5.0/24:443/tcp      network, specific port + proto     (allow)
    !10.0.5.22               single host — DENY                 (deny)
    !10.0.5.0/24:443/tcp     network, port + proto — DENY       (deny)

Comments (v3.6):
    Each entry may have an optional inline `#` comment for human context.
    Everything from the first `#` to the next comma (or end of input) is
    the comment text, stripped of leading/trailing whitespace, capped at
    80 chars.
        10.0.5.22 # Plex server
        !10.0.5.22:22/tcp #block ssh from this peer
        192.168.0.0/16 # home LAN, 10.0.0.0/8 # office

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
from dataclasses import dataclass, field
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


# Cap on comment length. Long enough for "Plex / Sonarr / arr stack admin
# UI on this host" without being so generous it bloats the DB. 80 is a
# convenient upper bound for what fits visibly in a row.
_COMMENT_MAX_LEN = 80


class ACLParseError(ValueError):
    pass


@dataclass(frozen=True)
class ACLEntry:
    cidr: str               # always in CIDR form, e.g. "10.0.5.22/32"
    port: Optional[int]     # None means any
    proto: Optional[str]    # None means any, else "tcp" or "udp"
    action: str = "allow"   # "allow" or "deny"
    comment: str = ""       # v3.6: optional human label, ≤ 80 chars

    def __str__(self) -> str:
        """Round-trip-safe text form including any comment.

        Used by:
          - serialization for textual config representation
          - the API's response to GET peer ACL list (PeerOut.acl)
          - the migrate-tab preview rendering

        Note: the iptables rule generators (apply_peer_acls et al) use
        the structured fields (cidr/port/proto/action) directly, NOT the
        string form, so comments don't reach the iptables level. They're
        a UI-only artifact.
        """
        base = ("!" if self.action == "deny" else "") + self.cidr
        if self.port is not None:
            base += f":{self.port}/{self.proto}"
        if self.comment:
            base += f" # {self.comment}"
        return base

    @property
    def is_deny(self) -> bool:
        return self.action == "deny"


def _strip_comment(raw: str) -> tuple[str, str]:
    """Split an entry on its first `#`, returning (rule_part, comment_part).

    Both parts are stripped; comment is capped at _COMMENT_MAX_LEN. If the
    string has no `#`, returns (raw, "").

    Note: a stray `#` inside an IP/CIDR/port spec wouldn't parse anyway
    (the rule regex doesn't allow `#`), so splitting on the first `#`
    is safe — anything before it is the rule, anything after is comment.
    """
    if "#" not in raw:
        return raw.strip(), ""
    rule_part, comment_part = raw.split("#", 1)
    comment = comment_part.strip()
    if len(comment) > _COMMENT_MAX_LEN:
        comment = comment[:_COMMENT_MAX_LEN]
    return rule_part.strip(), comment


def parse_entry(raw: str) -> ACLEntry:
    raw = raw.strip()
    if not raw:
        raise ACLParseError("empty ACL entry")

    rule_part, comment = _strip_comment(raw)
    if not rule_part:
        raise ACLParseError(f"comment-only ACL entry: {raw!r}")

    m = _ENTRY_RE.match(rule_part)
    if not m:
        raise ACLParseError(f"invalid ACL syntax: {rule_part!r}")

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
        comment=comment,
    )


def parse_list(raw: str) -> List[ACLEntry]:
    """Parse a comma-separated list. Blanks are ignored.

    Note on comma-vs-comment ambiguity: the parser splits on `,` first,
    THEN extracts `#` comments from each piece. So
        '192.168.0.0/16 # home, 10.0.0.0/8 # office'
    splits into:
        ['192.168.0.0/16 # home', ' 10.0.0.0/8 # office']
    which parses cleanly into two entries with comments.

    A comma INSIDE a comment can't be expressed in this format — the
    comma would split the comment in two. This is by design (commas are
    cheap punctuation; commenters can use other separators like `;` or
    `·` if they really need a comma in their note).
    """
    if not raw:
        return []
    return [parse_entry(p) for p in raw.split(",") if p.strip()]


def has_any_deny(entries: List[ACLEntry]) -> bool:
    """True if any entry is a deny — signals full-tunnel ACL intent."""
    return any(e.is_deny for e in entries)
