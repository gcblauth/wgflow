"""Multisite federation (v4.2-rebuild, registration-then-bundle).

Symmetric peering on wg0 between two wgflows. No separate kernel
interface, no new UDP port. The 10.99.0.0/24 overlay rides as a
secondary address on wg0.

Pairing protocol — two copy-pastes, no callback:

    1. wgB (importer) "+ import" → "start": this module's
       build_registration() makes a registration text block. wgB's
       wgflow generates a fresh keypair locally and stores the
       private key on the federation_links row. The registration
       carries the *public* half plus wgB's wg0 endpoint and overlay
       address candidate. Operator copies the registration string.

    2. wgA (creator) "+ create from registration": parses the
       registration via parse_registration(), generates a PSK,
       picks its own overlay address, inserts wgB as a wg0 peer
       (multisite peer_type) immediately. Returns a bundle text
       block via build_bundle() containing wgA's pubkey + endpoint
       + PSK + overlay addresses + creator advertised. Operator
       copies the bundle.

    3. wgB "+ import" → "complete": parses the bundle via
       parse_bundle(), inserts wgA as a wg0 peer using the privkey
       it stashed in step 1. Both sides now have peer entries; wg0
       handshakes within ~5 seconds.

The auth was always "operator pasted these strings by hand" —
nothing else. We made that explicit instead of inventing tokens
that didn't add security.

What this module owns:
    * Registration text gen + parse (step 1)
    * Bundle text gen + parse (step 2)
    * Overlay address allocation (used by both sides)
    * wg0 secondary-address reconcile
    * wg-keypair helpers (shells out to `wg`)

What lives elsewhere:
    * API endpoints → app/main.py
    * Peer table inserts and wg syncconf → app/main.py + wg_manager.py
    * iptables ACL rules → app/iptables_manager.py
"""
from __future__ import annotations

import base64
import ipaddress
import re
import secrets
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Tuple

from . import upstream as _upstream


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OVERLAY_SUBNET = ipaddress.IPv4Network("10.99.0.0/24")

# The wgflow that generates the registration (importer side) defaults
# to .2 (so the creator side, conventionally first to deploy, gets .1).
# Either side can override; allocate_overlay_addr handles collisions.
DEFAULT_IMPORTER_OVERLAY_ADDR = "10.99.0.2"
DEFAULT_CREATOR_OVERLAY_ADDR = "10.99.0.1"


class MultisiteError(ValueError):
    """Operator-safe error during text parsing/generation."""


# ---------------------------------------------------------------------------
# Crypto helpers (shared with v4.2-pre)
# ---------------------------------------------------------------------------

def generate_keypair() -> Tuple[str, str]:
    """Returns (privkey, pubkey) as base64 strings."""
    priv = subprocess.run(
        ["wg", "genkey"], capture_output=True, text=True, check=True
    ).stdout.strip()
    pub = pubkey_from_privkey(priv)
    return priv, pub


def pubkey_from_privkey(privkey: str) -> str:
    return subprocess.run(
        ["wg", "pubkey"], input=privkey,
        capture_output=True, text=True, check=True,
    ).stdout.strip()


def generate_psk() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


# ---------------------------------------------------------------------------
# Address allocation
# ---------------------------------------------------------------------------

def allocate_overlay_addr(conn, prefer: Optional[str] = None) -> str:
    """Pick an overlay address not already used by any federation_links row.

    Args:
        conn: sqlite connection
        prefer: address to return if free (importer typically prefers .2,
            creator typically prefers .1). Falls back to next-free if
            taken.

    Returns the bare address ("10.99.0.5"), no /32. Caller adds mask.
    """
    used: set = set()
    rows = conn.execute(
        "SELECT local_overlay_addr, remote_overlay_addr FROM federation_links"
    ).fetchall()
    for r in rows:
        for col in ("local_overlay_addr", "remote_overlay_addr"):
            v = (r[col] or "").split("/", 1)[0].strip()
            if v:
                used.add(v)

    if prefer and prefer not in used:
        return prefer
    for last_octet in range(1, 255):
        candidate = f"10.99.0.{last_octet}"
        if candidate not in used:
            return candidate
    raise MultisiteError("overlay address pool exhausted (10.99.0.1-254 in use)")


# ---------------------------------------------------------------------------
# Registration text (step 1: importer → creator)
# ---------------------------------------------------------------------------
#
# Plain-text format (so operators can read what they're pasting), with
# wgflow-multisite-registration-* metadata in `# ` comments. This is
# NOT a wg conf — it's a registration request. wg-quick won't try to
# parse it because there are no [Interface]/[Peer] sections.

@dataclass
class ParsedRegistration:
    """Result of parsing a registration block on the creator side."""
    suggested_link_name: str
    importer_pubkey: str
    importer_endpoint: str            # "host:port"
    importer_overlay_addr: str        # bare IP, no mask
    importer_advertised: List[str]    # CIDRs


_REG_NAME_RE     = re.compile(r"^\s*#\s*wgflow-multisite-registration-name:\s*(\S.*?)\s*$", re.MULTILINE)
_REG_PUBKEY_RE   = re.compile(r"^\s*#\s*wgflow-multisite-registration-pubkey:\s*(\S+)\s*$", re.MULTILINE)
_REG_ENDPOINT_RE = re.compile(r"^\s*#\s*wgflow-multisite-registration-endpoint:\s*(\S+)\s*$", re.MULTILINE)
_REG_OVERLAY_RE  = re.compile(r"^\s*#\s*wgflow-multisite-registration-overlay:\s*(\S+)\s*$", re.MULTILINE)
_REG_ADV_RE      = re.compile(r"^\s*#\s*wgflow-multisite-registration-advertised:\s*(.*?)\s*$", re.MULTILINE)


def build_registration(
    *,
    suggested_link_name: str,
    importer_pubkey: str,
    importer_endpoint: str,
    importer_overlay_addr: str,
    importer_advertised: List[str],
) -> str:
    """Render the registration text block on the importer side.

    Returned string is what the operator copies and pastes into the
    creator side's "+ create from registration" form.

    The link name is a *suggestion* — the creator side can override
    it (operator picks a label that makes sense to them).
    """
    # Defensive filter on advertised — refuse 0.0.0.0/0 (lockout
    # prevention same as bundle path). Malformed CIDRs are dropped.
    safe_adv: List[str] = []
    for cidr in importer_advertised:
        cidr = cidr.strip()
        if not cidr or cidr in ("0.0.0.0/0", "::/0"):
            continue
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if cidr not in safe_adv:
            safe_adv.append(cidr)

    lines = [
        "# wgflow multisite REGISTRATION — DO NOT EDIT",
        "# paste this into the OTHER wgflow's '+ create from registration' form.",
        f"# wgflow-multisite-registration-name: {suggested_link_name}",
        f"# wgflow-multisite-registration-pubkey: {importer_pubkey}",
        f"# wgflow-multisite-registration-endpoint: {importer_endpoint}",
        f"# wgflow-multisite-registration-overlay: {importer_overlay_addr}",
        f"# wgflow-multisite-registration-advertised: {','.join(safe_adv)}",
        "",
    ]
    return "\n".join(lines)


def parse_registration(text: str) -> ParsedRegistration:
    """Parse a registration block. Validates required fields are present.

    Raises MultisiteError on missing/malformed fields, including
    importer overlay address not on 10.99.0.0/24.
    """
    m_pk = _REG_PUBKEY_RE.search(text)
    if not m_pk:
        raise MultisiteError(
            "this is not a wgflow registration block "
            "(missing wgflow-multisite-registration-pubkey). "
            "make sure you copied the registration from the OTHER "
            "wgflow's '+ import' → 'start' flow, not the bundle."
        )
    m_ep = _REG_ENDPOINT_RE.search(text)
    if not m_ep:
        raise MultisiteError("registration missing endpoint")
    m_ovl = _REG_OVERLAY_RE.search(text)
    if not m_ovl:
        raise MultisiteError("registration missing overlay address")

    overlay = m_ovl.group(1)
    try:
        if ipaddress.IPv4Address(overlay) not in OVERLAY_SUBNET:
            raise MultisiteError(
                f"importer overlay {overlay} is not on {OVERLAY_SUBNET}"
            )
    except ValueError:
        raise MultisiteError(f"importer overlay malformed: {overlay}")

    m_name = _REG_NAME_RE.search(text)
    suggested = m_name.group(1) if m_name else "imported"

    m_adv = _REG_ADV_RE.search(text)
    advertised: List[str] = []
    if m_adv:
        for cidr in m_adv.group(1).split(","):
            cidr = cidr.strip()
            if cidr and cidr not in ("0.0.0.0/0", "::/0"):
                advertised.append(cidr)

    endpoint = m_ep.group(1)
    if ":" not in endpoint:
        raise MultisiteError(f"registration endpoint must be host:port, got {endpoint!r}")

    return ParsedRegistration(
        suggested_link_name=suggested,
        importer_pubkey=m_pk.group(1),
        importer_endpoint=endpoint,
        importer_overlay_addr=overlay,
        importer_advertised=advertised,
    )


# ---------------------------------------------------------------------------
# Bundle text (step 2: creator → importer)
# ---------------------------------------------------------------------------
#
# Same general shape as v4.2-pre — looks like a wg conf with metadata
# comments — but the [Interface] PrivateKey is NOT present this time.
# The importer already generated its privkey at registration time and
# kept it locally. The bundle just carries what the importer needs to
# install wgA as a peer: wgA's pubkey + endpoint + PSK + overlay
# addresses + creator advertised networks.

@dataclass
class ParsedBundle:
    """Result of parsing the bundle text on the importer side."""
    link_name: str
    creator_pubkey: str
    creator_endpoint: str
    creator_overlay_addr: str        # bare IP
    importer_overlay_addr: str       # echoed back so importer can verify
    psk: str
    creator_advertised: List[str]


_BND_NAME_RE        = re.compile(r"^\s*#\s*wgflow-multisite-bundle-name:\s*(\S.*?)\s*$", re.MULTILINE)
_BND_PUBKEY_RE      = re.compile(r"^\s*#\s*wgflow-multisite-bundle-pubkey:\s*(\S+)\s*$", re.MULTILINE)
_BND_ENDPOINT_RE    = re.compile(r"^\s*#\s*wgflow-multisite-bundle-endpoint:\s*(\S+)\s*$", re.MULTILINE)
_BND_PSK_RE         = re.compile(r"^\s*#\s*wgflow-multisite-bundle-psk:\s*(\S+)\s*$", re.MULTILINE)
_BND_CREATOR_OVL_RE = re.compile(r"^\s*#\s*wgflow-multisite-bundle-creator-overlay:\s*(\S+)\s*$", re.MULTILINE)
_BND_IMPORT_OVL_RE  = re.compile(r"^\s*#\s*wgflow-multisite-bundle-importer-overlay:\s*(\S+)\s*$", re.MULTILINE)
_BND_ADV_RE         = re.compile(r"^\s*#\s*wgflow-multisite-bundle-creator-advertised:\s*(.*?)\s*$", re.MULTILINE)


def build_bundle(
    *,
    link_name: str,
    creator_pubkey: str,
    creator_endpoint: str,
    creator_overlay_addr: str,
    importer_overlay_addr: str,
    psk: str,
    creator_advertised: List[str],
) -> str:
    """Render the bundle text block on the creator side. Operator
    copies this and pastes into the importer's '+ import' → 'complete'
    form.
    """
    safe_adv: List[str] = []
    for cidr in creator_advertised:
        cidr = cidr.strip()
        if not cidr or cidr in ("0.0.0.0/0", "::/0"):
            continue
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if cidr not in safe_adv:
            safe_adv.append(cidr)

    lines = [
        "# wgflow multisite BUNDLE — DO NOT EDIT",
        "# paste this back into the OTHER wgflow's '+ import' → 'complete' form.",
        f"# wgflow-multisite-bundle-name: {link_name}",
        f"# wgflow-multisite-bundle-pubkey: {creator_pubkey}",
        f"# wgflow-multisite-bundle-endpoint: {creator_endpoint}",
        f"# wgflow-multisite-bundle-psk: {psk}",
        f"# wgflow-multisite-bundle-creator-overlay: {creator_overlay_addr}",
        f"# wgflow-multisite-bundle-importer-overlay: {importer_overlay_addr}",
        f"# wgflow-multisite-bundle-creator-advertised: {','.join(safe_adv)}",
        "",
    ]
    return "\n".join(lines)


def parse_bundle(text: str) -> ParsedBundle:
    """Parse the bundle text block on the importer side. Validates
    required fields are present and overlay addresses are on the
    correct subnet.
    """
    m_pk = _BND_PUBKEY_RE.search(text)
    if not m_pk:
        raise MultisiteError(
            "this is not a wgflow bundle "
            "(missing wgflow-multisite-bundle-pubkey). "
            "make sure you copied the BUNDLE from the OTHER wgflow's "
            "'+ create from registration' result, not the registration."
        )
    m_ep = _BND_ENDPOINT_RE.search(text)
    if not m_ep:
        raise MultisiteError("bundle missing endpoint")
    m_psk = _BND_PSK_RE.search(text)
    if not m_psk:
        raise MultisiteError("bundle missing PSK")
    m_creator_ovl = _BND_CREATOR_OVL_RE.search(text)
    m_importer_ovl = _BND_IMPORT_OVL_RE.search(text)
    if not m_creator_ovl or not m_importer_ovl:
        raise MultisiteError("bundle missing overlay addresses")

    creator_overlay = m_creator_ovl.group(1)
    importer_overlay = m_importer_ovl.group(1)
    try:
        if (ipaddress.IPv4Address(creator_overlay) not in OVERLAY_SUBNET
                or ipaddress.IPv4Address(importer_overlay) not in OVERLAY_SUBNET):
            raise MultisiteError(
                f"bundle overlay addresses must be on {OVERLAY_SUBNET}"
            )
    except ValueError:
        raise MultisiteError("overlay addresses malformed in bundle")

    m_name = _BND_NAME_RE.search(text)
    link_name = m_name.group(1) if m_name else "imported"

    m_adv = _BND_ADV_RE.search(text)
    advertised: List[str] = []
    if m_adv:
        for cidr in m_adv.group(1).split(","):
            cidr = cidr.strip()
            if cidr and cidr not in ("0.0.0.0/0", "::/0"):
                advertised.append(cidr)

    endpoint = m_ep.group(1)
    if ":" not in endpoint:
        raise MultisiteError(f"bundle endpoint must be host:port, got {endpoint!r}")

    return ParsedBundle(
        link_name=link_name,
        creator_pubkey=m_pk.group(1),
        creator_endpoint=endpoint,
        creator_overlay_addr=creator_overlay,
        importer_overlay_addr=importer_overlay,
        psk=m_psk.group(1),
        creator_advertised=advertised,
    )


# ---------------------------------------------------------------------------
# wg0 overlay address reconciliation (unchanged from previous v4.2-rebuild)
# ---------------------------------------------------------------------------
#
# wg0 gets a secondary 10.99.0.X/32 added/removed dynamically based on
# whether any federation_links row is enabled. Reuses primary wg0
# without tearing it down.

def _wg0_addresses_on_overlay(interface: str = "wg0") -> List[str]:
    """List overlay-subnet addresses currently bound to wg0."""
    res = subprocess.run(
        ["ip", "-o", "-4", "addr", "show", "dev", interface],
        capture_output=True, text=True,
    )
    if res.returncode != 0:
        return []
    addrs: List[str] = []
    for line in res.stdout.splitlines():
        m = re.search(r"\binet\s+(\S+)", line)
        if not m:
            continue
        ip_str = m.group(1).split("/", 1)[0]
        try:
            if ipaddress.IPv4Address(ip_str) in OVERLAY_SUBNET:
                addrs.append(ip_str)
        except ValueError:
            continue
    return addrs


def reconcile_overlay_address(conn, interface: str = "wg0") -> None:
    """Ensure wg0 has exactly the right overlay /32 bound, no more.

    Reads federation_links to find the desired overlay address — all
    rows on this wgflow share the same local_overlay_addr (it's our
    box's identity on the overlay), so we use whichever is in the
    first enabled row.
    """
    desired_row = conn.execute(
        "SELECT local_overlay_addr FROM federation_links "
        "WHERE enabled=1 LIMIT 1"
    ).fetchone()
    desired = None
    if desired_row and desired_row["local_overlay_addr"]:
        desired = desired_row["local_overlay_addr"].split("/", 1)[0]

    current = _wg0_addresses_on_overlay(interface)

    for addr in current:
        if addr != desired:
            subprocess.run(
                ["ip", "address", "del", f"{addr}/32", "dev", interface],
                capture_output=True, text=True, check=False,
            )

    if desired and desired not in current:
        subprocess.run(
            ["ip", "address", "add", f"{desired}/32", "dev", interface],
            capture_output=True, text=True, check=False,
        )


# ---------------------------------------------------------------------------
# Route reconciliation
# ---------------------------------------------------------------------------
#
# `wg syncconf` does NOT install IP routes — only `wg-quick up` does, and
# only for the AllowedIPs of peers present in the conf at bring-up time.
# Multisite peers are added via syncconf AFTER wg0 is up, so the kernel's
# IP routing table has no entry for the remote overlay address or any
# advertised network. Without an explicit route, packets to those
# destinations fall back to the default route (eth0 → docker bridge →
# host → internet) and never reach the tunnel.
#
# We reconcile routes alongside addresses on every replay. The kernel
# state of interest is "all routes via wg0 with src on the overlay." We
# diff against what the DB says should exist; add missing, remove stale.
#
# Routes installed per multisite link:
#   - <remote_overlay_addr>/32 dev wg0 src <local_overlay_addr>
#     (so we can ping the other wgflow's overlay IP)
#   - <each remote_advertised CIDR> dev wg0 src <local_overlay_addr>
#     (so we can reach networks the remote advertised through the tunnel)
#
# We use `src <local_overlay>` so the source-IP is correct — without it
# the kernel picks the primary wg0 address (e.g. 10.169.1.1) and the
# return packet goes to the wrong AllowedIPs entry on the other side.

def _routes_on_wg0(interface: str = "wg0") -> List[Tuple[str, str]]:
    """List routes currently going via the given interface.

    Returns a list of (destination_with_mask, src_address) tuples. Only
    routes that have a `src` field set are returned — those are the
    ones we manage. Routes without `src` (e.g. the connected /24 for
    wg0's primary address) are kernel-managed and we don't touch them.
    """
    res = subprocess.run(
        ["ip", "-4", "route", "show", "dev", interface],
        capture_output=True, text=True,
    )
    if res.returncode != 0:
        return []
    out: List[Tuple[str, str]] = []
    for line in res.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        # Format: "<dst> [proto kernel] [scope link] [src <addr>]"
        # We care about lines with `src` set.
        parts = line.split()
        if not parts:
            continue
        dst = parts[0]
        src = None
        for i, tok in enumerate(parts):
            if tok == "src" and i + 1 < len(parts):
                src = parts[i + 1]
                break
        if src is None:
            continue
        # Normalize: a bare host gets /32 treatment for diff purposes.
        if "/" not in dst and dst not in ("default",):
            dst = dst + "/32"
        out.append((dst, src))
    return out


def _desired_routes(conn) -> List[Tuple[str, str]]:
    """Compute the set of routes that should exist via wg0 to support
    multisite. Returns (destination_with_mask, src_address) tuples.
    """
    rows = conn.execute(
        "SELECT local_overlay_addr, remote_overlay_addr, remote_advertised "
        "FROM federation_links WHERE enabled=1"
    ).fetchall()
    desired: List[Tuple[str, str]] = []
    seen: set = set()
    for r in rows:
        local = (r["local_overlay_addr"] or "").split("/", 1)[0]
        remote = (r["remote_overlay_addr"] or "").split("/", 1)[0]
        if not local or not remote:
            continue
        # Route to the remote overlay /32.
        key = (f"{remote}/32", local)
        if key not in seen:
            seen.add(key)
            desired.append(key)
        # Routes to each advertised network.
        adv = (r["remote_advertised"] or "").strip()
        if adv:
            for cidr in adv.split(","):
                cidr = cidr.strip()
                if not cidr or cidr in ("0.0.0.0/0", "::/0"):
                    continue
                # Normalize CIDR to host form for diff matching.
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    norm = str(net)
                except ValueError:
                    continue
                k = (norm, local)
                if k not in seen:
                    seen.add(k)
                    desired.append(k)
    return desired


def reconcile_routes(conn, interface: str = "wg0") -> None:
    """Sync IP routes via wg0 to match desired multisite state.

    Idempotent. Adds missing routes, removes stale ones (overlay subnet
    routes only — never touches the connected /24 for the primary
    address, never touches non-overlay routes).

    Logs failures from `ip route add/del` but doesn't raise — a bad
    route addition shouldn't tear down the whole replay (e.g. if the
    operator shut down a remote and the route already got cleaned up
    by the kernel for some reason).
    """
    desired = set(_desired_routes(conn))
    current = set(_routes_on_wg0(interface))

    # Filter current to only routes whose src is on the overlay subnet.
    # Anything else (the kernel-installed connected /24 for wg0's
    # primary address, etc.) is not ours to manage.
    current_overlay = set()
    for dst, src in current:
        try:
            if ipaddress.IPv4Address(src) in OVERLAY_SUBNET:
                current_overlay.add((dst, src))
        except ValueError:
            continue

    # Remove stale: in current_overlay but not desired.
    for dst, src in current_overlay - desired:
        proc = subprocess.run(
            ["ip", "route", "del", dst, "dev", interface, "src", src],
            capture_output=True, text=True, check=False,
        )
        if proc.returncode != 0:
            print(f"[multisite] route del {dst} src {src} via {interface} "
                  f"failed: {proc.stderr.strip()}", flush=True)

    # Add missing: in desired but not current_overlay.
    for dst, src in desired - current_overlay:
        proc = subprocess.run(
            ["ip", "route", "add", dst, "dev", interface, "src", src],
            capture_output=True, text=True, check=False,
        )
        if proc.returncode != 0:
            # Route may already exist with different attributes — try
            # `ip route replace` as a fallback. Idempotent under load.
            proc2 = subprocess.run(
                ["ip", "route", "replace", dst, "dev", interface, "src", src],
                capture_output=True, text=True, check=False,
            )
            if proc2.returncode != 0:
                print(f"[multisite] route add {dst} src {src} via "
                      f"{interface} failed: {proc.stderr.strip()} "
                      f"(replace also failed: {proc2.stderr.strip()})",
                      flush=True)
