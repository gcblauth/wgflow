"""Universal intermediate representation for imported WireGuard data.

Every parser (wg_easy, pivpn, bare_wg) produces a `ParsedImport` so the
preview UI and commit logic don't care about the source format.

Status taxonomy for a parsed peer
---------------------------------
After parsing, each peer is paired with a `PeerStatus` describing its
relationship to the current wgflow state. The frontend uses this to
render badges and toggle defaults.

  ok               — no conflicts; safe to import
  name-conflict    — a wgflow peer with this name already exists
  pubkey-conflict  — a wgflow peer with this public key already exists
                     (most likely re-importing the same source)
  address-conflict — the source's address is already used by another wgflow peer
  address-out-of-range
                   — source's address isn't inside the wgflow subnet;
                     commit will reassign from the free pool if accepted
  invalid          — the row failed shape validation; will not be imported
                     (excluded from selectable list, surfaced in warnings)

Empty-string conventions
------------------------
`private_key` is "" for bare-WG peers (operator's clients have the keys,
the wgflow server only knows pubkeys). `has_private_key=False` is the
authoritative flag — gate "download config" buttons on that, not on the
private_key string being empty, in case future formats want different
sentinel choices.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


# Source format strings used for telemetry / notes / UI labels. Keep these
# stable — the UI may key off them, and we'd rather not version-skew.
SOURCE_WG_EASY_V14 = "wg-easy-v14"   # wg0.json, full keypairs
SOURCE_WG_EASY_V15 = "wg-easy-v15"   # wg-easy.db sqlite, full keypairs
SOURCE_PIVPN       = "pivpn"          # tarball of /etc/wireguard/configs
SOURCE_BARE_WG     = "bare-wg"        # single wg0.conf, pubkeys only

# All recognized status values. Keep in sync with frontend rendering.
STATUS_OK                  = "ok"
STATUS_NAME_CONFLICT       = "name-conflict"
STATUS_PUBKEY_CONFLICT     = "pubkey-conflict"
STATUS_ADDRESS_CONFLICT    = "address-conflict"
STATUS_ADDRESS_OUT_OF_RANGE = "address-out-of-range"
STATUS_INVALID             = "invalid"


@dataclass(frozen=True)
class ParsedKeyPair:
    """A WireGuard keypair extracted from the source.

    private_key is "" iff the source didn't provide one (bare-WG).
    Both fields are base64-encoded strings as produced by `wg genkey`/`wg pubkey`.
    """
    private_key: str
    public_key: str


@dataclass
class ParsedPeer:
    """One peer's worth of importable data, post-parse and pre-commit.

    Mutable on purpose — the `status` and `assigned_address` fields are
    populated AFTER parsing, by `commit._compute_statuses()`, once we
    know what the existing wgflow state looks like. Keeping them on the
    same dataclass avoids a parallel "status list" that has to stay in
    lock-step with the peer list.
    """
    # --- intrinsic to the source -----------------------------------------
    name: str
    public_key: str            # always present
    private_key: str           # "" for bare-WG
    preshared_key: str         # generated if the source had none
    address: str               # CIDR like "10.13.13.5/32"
    has_private_key: bool      # False only for bare-WG
    enabled: bool = True       # honors source's enabled flag where present
    dns: Optional[str] = None  # passed through if source set it
    notes: str = ""            # free-form, populated with "imported from <source>"

    # --- populated post-parse, by status computation ---------------------
    status: str = STATUS_OK
    # If the source's address was out-of-range and the user accepts the
    # peer anyway, this holds the address we'll actually insert (chosen
    # from the wgflow free pool at commit time). None until then.
    assigned_address: Optional[str] = None
    # Human-readable reason for `invalid` status, surfaced in the UI.
    invalid_reason: str = ""


@dataclass
class ParsedImport:
    """Everything one upload produces.

    `server_keypair` is None when the source didn't provide one (bare-WG)
    or when we couldn't extract it (corrupt source). The frontend hides
    the "adopt server keypair" toggle in those cases.

    `warnings` collects per-row parser issues that didn't rise to the
    level of a fatal error. They're surfaced in a banner above the
    preview list.
    """
    source: str
    server_keypair: Optional[ParsedKeyPair]
    peers: List[ParsedPeer] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


# --- shape validation helpers, shared by all parsers ----------------------
# Every value pulled out of an upload goes through these. The contract is
# "raise ValueError on bad input; return the cleaned value on good input."
# Parsers catch these and demote the row to STATUS_INVALID with the error
# message captured in `invalid_reason`.

import base64
import ipaddress
import re

_NAME_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\- ]{0,63}$")


def validate_wg_key(b64: str, *, label: str) -> str:
    """A WireGuard public/private/preshared key is 32 random bytes,
    base64-encoded (44 chars including the trailing '=' padding). We don't
    validate the bytes are on Curve25519 — `wg pubkey` would catch that
    later — but we DO check the length so the string can't sneak into a
    SQL row as an unrelated payload.
    """
    s = b64.strip()
    if not s:
        raise ValueError(f"{label} is empty")
    try:
        raw = base64.b64decode(s, validate=True)
    except Exception as e:
        raise ValueError(f"{label} is not valid base64: {e}")
    if len(raw) != 32:
        raise ValueError(f"{label} must decode to 32 bytes, got {len(raw)}")
    return s


def validate_peer_name(name: str) -> str:
    """Stricter than the existing /api/peers route on purpose. Imports
    can come from sources that allow ':' or '/' in names (UUID-style),
    which would render confusingly in the UI table. We restrict to
    visible ASCII, dots/dashes/underscores/spaces, and bound the length.
    """
    s = name.strip()
    if not _NAME_RX.match(s):
        raise ValueError(
            "peer name must be 1-64 ASCII chars (letters/digits/._- /space) "
            "starting with a letter or digit"
        )
    return s


def validate_address(addr: str) -> str:
    """Accepts '10.13.13.5' or '10.13.13.5/32'. Always returns CIDR form.
    Rejects /0 and other prefixes that don't make sense for a single peer.
    """
    s = addr.strip()
    if not s:
        raise ValueError("address is empty")
    # Accept the host-only form and pad to /32 — common in wg-easy data.
    if "/" not in s:
        s = f"{s}/32"
    try:
        iface = ipaddress.IPv4Interface(s)
    except (ipaddress.AddressValueError, ValueError) as e:
        raise ValueError(f"address {addr!r}: {e}")
    if iface.network.prefixlen != 32:
        raise ValueError(
            f"address {addr!r} must be a /32 (got /{iface.network.prefixlen})"
        )
    return f"{iface.ip}/32"


def validate_dns(dns: Optional[str]) -> Optional[str]:
    """Accept None (inherit), '' (split-tunnel), or comma-separated IPs.
    Anything else is rejected, including hostnames — wgflow only renders
    IP literals into the client config's DNS line.
    """
    if dns is None:
        return None
    s = dns.strip()
    if s == "":
        return ""
    parts = [p.strip() for p in s.split(",")]
    for p in parts:
        try:
            ipaddress.ip_address(p)
        except ValueError:
            raise ValueError(f"DNS entry {p!r} is not a valid IP address")
    return ",".join(parts)
