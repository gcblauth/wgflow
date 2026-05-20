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

# Alias reference syntax: optional `!`, then `@`, then a name.
# Names are lowercase alphanumeric + underscore, 1-32 chars. We accept
# uppercase here and lowercase at parse time so users can type @Home_LAN
# and have it round-trip cleanly.
_ALIAS_RE = re.compile(
    r"^(?P<bang>!)?@(?P<name>[a-zA-Z0-9_]{1,32})$"
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


@dataclass(frozen=True)
class ACLAliasRef:
    """A reference to a named alias in a peer's ACL list.

    Stored alongside ACLEntry items in a peer's parsed ACL. The iptables
    rule generator detects ACLAliasRef and expands it via the alias
    table; literal ACLEntry items pass through unchanged.

    Why a separate type rather than reusing ACLEntry: aliases don't have
    cidr/port/proto until expanded. Forcing them into ACLEntry's shape
    would require sentinel values and error-prone "is this a real entry
    or a placeholder" checks across every code path. Distinct types make
    the heterogeneity explicit in the type system.
    """
    name: str               # alias name without the leading @, lowercased
    action: str = "allow"   # "allow" or "deny" — applied to the WHOLE expansion
    comment: str = ""       # optional comment on the alias usage line

    def __str__(self) -> str:
        base = ("!" if self.action == "deny" else "") + "@" + self.name
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


def parse_entry(raw: str):
    """Parse a single ACL entry. Returns either:
      - ACLEntry  for a CIDR/host rule, or
      - ACLAliasRef for an `@name` alias reference (v3.7+).

    The caller distinguishes via isinstance() or by inspecting the
    type. Code that needs to flatten aliases into concrete iptables
    rules calls expand_aliases() (below).
    """
    raw = raw.strip()
    if not raw:
        raise ACLParseError("empty ACL entry")

    rule_part, comment = _strip_comment(raw)
    if not rule_part:
        raise ACLParseError(f"comment-only ACL entry: {raw!r}")

    # Try alias reference first. The regex is more specific than
    # _ENTRY_RE (requires the @) so there's no ambiguity.
    m = _ALIAS_RE.match(rule_part)
    if m:
        action = "deny" if m.group("bang") else "allow"
        return ACLAliasRef(
            name=m.group("name").lower(),
            action=action,
            comment=comment,
        )

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


def parse_list(raw: str):
    """Parse a comma-separated list. Returns a heterogeneous list of
    ACLEntry and/or ACLAliasRef items (in source order). Blanks ignored.

    Note on comma-vs-comment ambiguity: the parser splits on `,` first,
    THEN extracts `#` comments from each piece. So
        '192.168.0.0/16 # home, 10.0.0.0/8 # office'
    splits into:
        ['192.168.0.0/16 # home', ' 10.0.0.0/8 # office']
    which parses cleanly into two entries with comments.

    A comma INSIDE a comment can't be expressed in this format — the
    comma would split the comment in two. By design.
    """
    if not raw:
        return []
    return [parse_entry(p) for p in raw.split(",") if p.strip()]


def expand_aliases(items, alias_lookup) -> "List[ACLEntry]":
    """Flatten a heterogeneous parsed ACL list to literal ACLEntry items.

    Args:
      items: list returned by parse_list() — mix of ACLEntry + ACLAliasRef
      alias_lookup: dict {name -> list of ACLEntry} from the alias store

    Returns:
      A flat list of ACLEntry. Alias references expand IN ORDER at the
      position they appeared (so ordering relative to other rules is
      preserved). Each expanded entry's action is set from the
      ACLAliasRef.action — not from the alias body's stored action,
      because aliases are allow-only and the deny prefix on the
      reference is what triggers deny semantics.

    Raises ACLParseError if a referenced alias doesn't exist in
    alias_lookup. Caller is responsible for catching this and reporting
    to the operator (e.g. "alias @home_lan was deleted; remove from
    peer's ACL before saving").
    """
    out: List[ACLEntry] = []
    for item in items:
        if isinstance(item, ACLAliasRef):
            body = alias_lookup.get(item.name)
            if body is None:
                raise ACLParseError(
                    f"alias @{item.name} not defined; "
                    f"create it on the aliases tab or remove the reference"
                )
            for entry in body:
                # Body entries are always 'allow' in the alias table.
                # The alias usage's action ("allow" or "deny") wins.
                # Comment from the alias-usage line propagates to every
                # expanded entry so the operator sees their context in
                # the stats panel.
                out.append(ACLEntry(
                    cidr=entry.cidr,
                    port=entry.port,
                    proto=entry.proto,
                    action=item.action,
                    comment=item.comment or entry.comment,
                ))
        else:
            out.append(item)
    return out


def collect_alias_refs(items) -> "List[str]":
    """Return the unique alias names referenced in a parsed list.

    Used by the persistence layer to refresh acl_alias_refs index when
    a peer's ACL is saved.
    """
    seen: List[str] = []
    for item in items:
        if isinstance(item, ACLAliasRef) and item.name not in seen:
            seen.append(item.name)
    return seen


def has_any_deny(entries) -> bool:
    """True if any entry is a deny — signals full-tunnel ACL intent.

    Accepts either ACLEntry or ACLAliasRef items (or a mix). The
    mode-detection logic that calls this needs to work pre-expansion
    too, so deny-prefixed alias references count.
    """
    return any(getattr(e, 'is_deny', False) for e in entries)
