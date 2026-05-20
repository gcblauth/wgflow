"""Upstream WireGuard client connections (v4.1.1).

This wgflow can be a *client* of one or more upstream WG endpoints
(Mullvad, ProtonVPN, corporate VPN, another wgflow, etc). Each upstream
gets its own kernel interface (wg1, wg2, ...) — distinct from wg0 which
is the gateway interface where client peers terminate. Server-role and
client-role traffic stay isolated at the kernel level so AllowedIPs
collisions are impossible.

The risky part is routing. A typical full-tunnel client config has
`AllowedIPs = 0.0.0.0/0`, which when applied as a route would route
ALL of this box's outbound traffic through the upstream tunnel —
including the panel itself, locking out the operator. We filter
declared AllowedIPs into a safe applied set on import (see
_filter_allowed_ips), keep both values in DB, and surface the
difference clearly in the UI. Operators can override the filter, but
not by accident.

Module split:
- parse_wg_conf: text → ParsedConf (declared AllowedIPs preserved)
- _filter_allowed_ips: declared CIDRs → applied CIDRs (safety logic)
- _allocate_interface: pick the next free wgN
- bring_up / tear_down: kernel-side via ip + wg setconf
- replay_to_kernel: rebuild every enabled upstream's interface from DB

Doesn't shell out to wg-quick. Same pattern as the rest of wgflow:
generate the WG conf in memory, write to a temp file, `wg setconf`,
then `ip` for addresses + routes. Deterministic, scriptable, matches
how server-side wg0 reload works.
"""
from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .config import SETTINGS


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

@dataclass
class ParsedConf:
    """Result of parsing a WireGuard client conf.

    All fields come from the conf as written. AllowedIPs filtering
    happens after parsing (in _filter_allowed_ips). DNS is captured
    but not applied — see the v4.1 design notes; the override-our-
    resolver behavior is a separate decision deferred to a later
    release.
    """
    # [Interface]
    private_key: str
    address: str                          # "10.5.0.42/32" or "10.5.0.42/24"
    dns: List[str] = field(default_factory=list)
    mtu: Optional[int] = None
    # [Peer]
    public_key: str = ""
    preshared_key: Optional[str] = None
    allowed_ips: List[str] = field(default_factory=list)
    endpoint: str = ""                    # "host:port"
    persistent_keepalive: Optional[int] = None


class ConfParseError(ValueError):
    """Raised on malformed WG conf text. Message is operator-safe."""


# WireGuard conf is INI-ish but with quirks: section headers can repeat
# (multiple [Peer] blocks), keys are case-insensitive, values can have
# trailing comments (`# ...`), comma-separated lists with whitespace.
# We don't use configparser because of the case-sensitivity and
# repeated-section issues.

_SECTION_RE = re.compile(r"^\s*\[\s*([A-Za-z]+)\s*\]\s*$")
_KEYVAL_RE  = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


def parse_wg_conf(text: str) -> ParsedConf:
    """Parse a WireGuard client conf into a ParsedConf.

    Accepts exactly one [Interface] and one [Peer] section. Multiple
    [Peer] sections are an error in v4.1 — wgflow doesn't yet support
    multi-peer upstream configs (rare in client-role: a client config
    almost always has exactly one peer = the upstream server).

    Trailing `# ...` comments on values are stripped. Leading/trailing
    whitespace ignored. Empty lines ignored.

    Raises ConfParseError with a friendly message on any structural
    problem the operator should fix in their conf.
    """
    iface_kv: dict[str, str] = {}
    peer_kv: dict[str, str] = {}
    section: Optional[str] = None
    peer_count = 0

    for raw_line in text.splitlines():
        # Strip trailing # comments. WG configs sometimes use # for
        # comments and sometimes don't tolerate them; we strip
        # defensively. NOTE: PreSharedKey values are pure base64 so
        # they never contain a literal '#'.
        line = raw_line.split("#", 1)[0]
        line = line.strip()
        if not line:
            continue

        m_sec = _SECTION_RE.match(line)
        if m_sec:
            section = m_sec.group(1).lower()
            if section == "peer":
                peer_count += 1
                if peer_count > 1:
                    raise ConfParseError(
                        "multiple [Peer] sections — wgflow upstream import "
                        "supports exactly one peer per conf"
                    )
            continue

        m_kv = _KEYVAL_RE.match(line)
        if not m_kv:
            # Tolerate junk lines rather than fail. Most real-world
            # configs have stray content (PostUp/PostDown directives
            # we don't support, comments without leading #, blank
            # values from copy-paste artifacts).
            continue
        key = m_kv.group(1).lower()
        value = m_kv.group(2).strip()

        if section == "interface":
            iface_kv[key] = value
        elif section == "peer":
            peer_kv[key] = value
        # else: key outside any section — ignore

    if peer_count == 0:
        raise ConfParseError("no [Peer] section found")

    # Required fields with operator-friendly errors.
    privkey = iface_kv.get("privatekey")
    if not privkey:
        raise ConfParseError("[Interface] missing PrivateKey")
    address = iface_kv.get("address")
    if not address:
        raise ConfParseError("[Interface] missing Address")
    pubkey = peer_kv.get("publickey")
    if not pubkey:
        raise ConfParseError("[Peer] missing PublicKey")
    endpoint = peer_kv.get("endpoint")
    if not endpoint:
        raise ConfParseError("[Peer] missing Endpoint")

    # Optional fields.
    dns_raw = iface_kv.get("dns", "")
    dns_list = [d.strip() for d in dns_raw.split(",") if d.strip()] if dns_raw else []
    mtu = _parse_int(iface_kv.get("mtu"))

    psk = peer_kv.get("presharedkey")
    allowed_ips_raw = peer_kv.get("allowedips", "")
    allowed_ips = [c.strip() for c in allowed_ips_raw.split(",") if c.strip()]
    if not allowed_ips:
        raise ConfParseError("[Peer] missing AllowedIPs")
    keepalive = _parse_int(peer_kv.get("persistentkeepalive"))

    # Address may have been comma-separated (multi-stack v4+v6); take
    # only the first one — wgflow's upstream model is currently single-
    # address, and the routing table only supports a single source IP
    # per interface anyway.
    address_first = address.split(",", 1)[0].strip()
    # Validate the address is parseable. We accept /32 (single host)
    # and /N (subnet). The kernel side uses ip addr add <local_address>
    # so whatever the operator's upstream gave them flows through.
    try:
        ipaddress.ip_interface(address_first)
    except ValueError as e:
        raise ConfParseError(f"[Interface] Address malformed: {e}")

    # Endpoint shape check.
    if ":" not in endpoint:
        raise ConfParseError("[Peer] Endpoint must be host:port")

    return ParsedConf(
        private_key=privkey,
        address=address_first,
        dns=dns_list,
        mtu=mtu,
        public_key=pubkey,
        preshared_key=psk,
        allowed_ips=allowed_ips,
        endpoint=endpoint,
        persistent_keepalive=keepalive,
    )


def _parse_int(s: Optional[str]) -> Optional[int]:
    if s is None or not s.strip():
        return None
    try:
        return int(s.strip())
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# AllowedIPs filter (lockout-prevention safety net)
# ---------------------------------------------------------------------------

# RFC1918 + carrier-grade NAT space + link-local. When an upstream
# declares 0.0.0.0/0 (full tunnel), we replace with these by default.
# Operator can override after import; this is the safe-by-default value.
_RFC1918 = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]


@dataclass
class FilterReport:
    """What the safety filter changed, for surfacing in the UI."""
    full_tunnel_replaced: bool
    stripped_overlaps: List[str]   # CIDRs we removed and why
    final_applied: List[str]       # what we'll route through


def _our_protected_networks() -> List[ipaddress.IPv4Network]:
    """Networks we defend against being routed through an upstream.

    Includes:
      - WG_SUBNET (our client peer subnet — routing this through an
        upstream would dead-end client traffic at the upstream)
      - the federation overlay subnet (would break wgflow↔wgflow
        peering)
      - the host's primary panel-reachable interface — best-effort,
        derived from `ip route get 1.1.1.1` and we filter the source
        address. Most-likely-wrong if the host has multi-homing or
        custom routing, but covers the common case (panel reached
        from the LAN side).
    """
    nets: List[ipaddress.IPv4Network] = []

    # Client subnet.
    try:
        nets.append(ipaddress.IPv4Network(SETTINGS.subnet, strict=False))
    except (ValueError, AttributeError):
        pass

    # Federation overlay.
    try:
        if SETTINGS.multisite_enabled:
            nets.append(SETTINGS.federation_subnet)
    except AttributeError:
        pass

    # Host's primary interface network — best effort. We resolve
    # via `ip route get 1.1.1.1` which returns the route the kernel
    # would actually use to reach the public internet, including the
    # source address. We then look up the network of that source addr.
    # On failure we silently skip — the other safeties are sufficient.
    try:
        out = subprocess.run(
            ["ip", "-o", "route", "get", "1.1.1.1"],
            capture_output=True, text=True, timeout=2,
        )
        if out.returncode == 0:
            # Output looks like: "1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.42 ..."
            m = re.search(r"\bsrc\s+(\S+)", out.stdout)
            if m:
                src = m.group(1)
                # Look up the interface that owns that src to find its
                # network mask. `ip -o addr show` lists each address
                # with its prefix.
                addr_out = subprocess.run(
                    ["ip", "-o", "-4", "addr", "show"],
                    capture_output=True, text=True, timeout=2,
                )
                if addr_out.returncode == 0:
                    for line in addr_out.stdout.splitlines():
                        m2 = re.search(r"\binet\s+(\S+)", line)
                        if not m2:
                            continue
                        if m2.group(1).split("/", 1)[0] == src:
                            iface = ipaddress.IPv4Interface(m2.group(1))
                            nets.append(iface.network)
                            break
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return nets


def _filter_allowed_ips(declared: List[str]) -> FilterReport:
    """Apply Model 2 safety filter: full-tunnel → RFC1918, strip
    overlaps with our protected networks.

    Pure function aside from `_our_protected_networks()` which calls
    out to `ip` subprocess. Returns both the final list and a report
    suitable for the UI to display the diff.

    The operator can override the applied set after import via the
    edit endpoint (PUT). The filter just sets sensible defaults.
    """
    full_tunnel = "0.0.0.0/0" in declared
    starting: List[str]
    if full_tunnel:
        # Replace full-tunnel with RFC1918. Keep IPv6 entries from
        # declared (we don't filter those — wgflow's client subnet is
        # IPv4-only, the protection logic doesn't apply).
        starting = [c for c in declared if c != "0.0.0.0/0" and c != "::/0"]
        starting += _RFC1918
    else:
        starting = list(declared)

    protected = _our_protected_networks()
    stripped: List[str] = []
    final: List[str] = []
    for cidr in starting:
        # IPv6 entries pass through — we don't have IPv6 protected
        # networks defined yet (v4 is IPv4-only on the wg side).
        if ":" in cidr:
            final.append(cidr)
            continue
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
        except ValueError:
            stripped.append(f"{cidr} (malformed)")
            continue
        # Drop if it overlaps with any protected network.
        overlap = False
        for prot in protected:
            if net.overlaps(prot):
                stripped.append(f"{cidr} (overlaps {prot})")
                overlap = True
                break
        if not overlap:
            final.append(cidr)

    return FilterReport(
        full_tunnel_replaced=full_tunnel,
        stripped_overlaps=stripped,
        final_applied=final,
    )


# ---------------------------------------------------------------------------
# Interface name allocation
# ---------------------------------------------------------------------------

def allocate_interface_name(conn) -> str:
    """Pick the next free wgN. wg0 is always reserved for the gateway,
    wg1 is reserved for v4.2-pre multisite federation. Upstream
    interfaces start at wg2."""
    used = {
        r["interface_name"]
        for r in conn.execute(
            "SELECT interface_name FROM upstream_connections"
        ).fetchall()
    }
    # wg0 = gateway, wg1 = multisite federation, wg2+ = upstream
    for n in range(2, 100):
        candidate = f"wg{n}"
        if candidate not in used:
            return candidate
    raise RuntimeError("upstream interface allocation exhausted (wg2-wg99 in use)")


# ---------------------------------------------------------------------------
# Kernel-side bring-up / tear-down
# ---------------------------------------------------------------------------

def _run(cmd: list, check: bool = True) -> subprocess.CompletedProcess:
    """Subprocess helper that captures output and surfaces errors.

    On failure raises with stderr in the message — we want the
    underlying iproute2/wg error visible to the operator, not a
    generic CalledProcessError.
    """
    res = subprocess.run(cmd, capture_output=True, text=True)
    if check and res.returncode != 0:
        raise RuntimeError(
            f"command failed: {' '.join(cmd)}: {res.stderr.strip() or res.stdout.strip()}"
        )
    return res


def _render_peer_conf(row) -> str:
    """Generate the wg setconf input — only the [Peer] portion plus the
    interface privkey. The address + routes are managed by `ip`, not
    by wg setconf, so they don't appear here."""
    lines = [
        "[Interface]",
        f"PrivateKey = {row['local_privkey']}",
        "",
        "[Peer]",
        f"PublicKey = {row['remote_pubkey']}",
    ]
    if row["remote_psk"]:
        lines.append(f"PresharedKey = {row['remote_psk']}")
    # AllowedIPs in wg setconf is the *cryptokey routing table* — what
    # source IPs the kernel accepts from this peer. For client mode
    # this should be the same set we route through (anything the
    # upstream might send us).
    applied = row["remote_allowed_ips_applied"]
    lines.append(f"AllowedIPs = {applied}")
    lines.append(f"Endpoint = {row['remote_endpoint']}")
    if row["persistent_keepalive"]:
        lines.append(f"PersistentKeepalive = {row['persistent_keepalive']}")
    return "\n".join(lines) + "\n"


def bring_up(row) -> None:
    """Create the wgN interface, set its config, address, routes, mark up.

    Idempotent at the level of "after this returns, the interface is
    in the desired state." If the interface already exists, we
    tear it down first, which is how _replay_state_to_kernel handles
    config changes.
    """
    iface = row["interface_name"]

    # If an interface by this name already exists (from a previous
    # incarnation), nuke it. `ip link del` is no-op-safe with `|| true`
    # but we'd rather see the result, so check exists first.
    existing = subprocess.run(
        ["ip", "link", "show", "dev", iface],
        capture_output=True, text=True,
    )
    if existing.returncode == 0:
        _run(["ip", "link", "del", iface], check=False)

    _run(["ip", "link", "add", iface, "type", "wireguard"])

    # Set the wg config. wg setconf reads from a file; use a tempfile
    # because the privkey is sensitive and we don't want it on stderr
    # if anything goes wrong.
    conf = _render_peer_conf(row)
    with tempfile.NamedTemporaryFile(
        mode="w", delete=False, suffix=".conf",
        # Keep the file out of /tmp world-readable land.
        dir="/run" if os.path.isdir("/run") else "/tmp",
    ) as f:
        f.write(conf)
        f.flush()
        os.chmod(f.name, 0o600)
        tmppath = f.name
    try:
        _run(["wg", "setconf", iface, tmppath])
    finally:
        try:
            os.unlink(tmppath)
        except OSError:
            pass

    # Set the local address and bring up.
    _run(["ip", "address", "add", row["local_address"], "dev", iface])
    if row["mtu"]:
        _run(["ip", "link", "set", "mtu", str(row["mtu"]), "dev", iface])
    _run(["ip", "link", "set", iface, "up"])

    # Add routes for each AllowedIPs CIDR. We DO NOT add a default
    # route even if the applied set somehow contains 0.0.0.0/0 (the
    # filter should have caught it, but this is belt-and-braces).
    applied = [c.strip() for c in (row["remote_allowed_ips_applied"] or "").split(",") if c.strip()]
    for cidr in applied:
        if cidr in ("0.0.0.0/0", "::/0"):
            print(f"[upstream] refusing to add default route for {iface} "
                  f"— filter should have stripped this; check DB", flush=True)
            continue
        # `ip route add` errors if the route already exists. We use
        # `replace` to be idempotent across replays.
        _run(["ip", "route", "replace", cidr, "dev", iface], check=False)


def tear_down(interface_name: str) -> None:
    """Remove the wgN interface. Routes go away with the interface."""
    existing = subprocess.run(
        ["ip", "link", "show", "dev", interface_name],
        capture_output=True, text=True,
    )
    if existing.returncode == 0:
        _run(["ip", "link", "del", interface_name], check=False)


def replay_to_kernel(conn) -> None:
    """Rebuild every enabled upstream interface from DB.

    Called from main.py:_replay_state_to_kernel after the wg0 + iptables
    state is reconciled. Same shape as the federation peer replay:
    DB is canonical, kernel state is rebuilt from scratch every time.

    Disabled rows have their interface torn down (if it exists) so a
    toggle from enabled→disabled cleans up.
    """
    rows = conn.execute(
        "SELECT * FROM upstream_connections ORDER BY id"
    ).fetchall()
    for r in rows:
        if r["enabled"]:
            try:
                bring_up(r)
            except Exception as e:
                # Don't let one upstream's failure block the others.
                # Surface the error in the DB so the UI can show it.
                conn.execute(
                    "UPDATE upstream_connections SET last_error=? WHERE id=?",
                    (str(e)[:500], r["id"]),
                )
                print(f"[upstream] bring_up failed for {r['name']}: {e}",
                      flush=True)
        else:
            try:
                tear_down(r["interface_name"])
            except Exception as e:
                print(f"[upstream] tear_down failed for {r['name']}: {e}",
                      flush=True)


# ---------------------------------------------------------------------------
# Status reconciliation
# ---------------------------------------------------------------------------

def reconcile_handshakes(conn) -> None:
    """Read `wg show wgN dump` for each upstream's interface, update
    last_handshake_ts. Cheap; called from the metrics persist tick.
    """
    rows = conn.execute(
        "SELECT id, interface_name FROM upstream_connections WHERE enabled=1"
    ).fetchall()
    for r in rows:
        try:
            res = subprocess.run(
                ["wg", "show", r["interface_name"], "dump"],
                capture_output=True, text=True, timeout=2,
            )
            if res.returncode != 0:
                continue
            # Lines after the first (interface line) are peer lines.
            # Format: pubkey psk endpoint allowed_ips latest_handshake rx tx keepalive
            for line in res.stdout.strip().splitlines()[1:]:
                parts = line.split("\t")
                if len(parts) < 5:
                    continue
                hs = int(parts[4]) if parts[4].isdigit() else 0
                if hs > 0:
                    conn.execute(
                        "UPDATE upstream_connections "
                        "SET last_handshake_ts=? WHERE id=?",
                        (hs, r["id"]),
                    )
                break  # one peer per upstream
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            continue
