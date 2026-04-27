"""Subprocess wrappers around `wg` and `wg-quick`.

Every function here shells out; none of them use shell=True. Arguments are
passed as lists so there is no injection surface.
"""
from __future__ import annotations

import ipaddress
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from .config import SETTINGS


class WGError(RuntimeError):
    pass


def _run(cmd: List[str], *, input_text: Optional[str] = None) -> str:
    proc = subprocess.run(
        cmd,
        input=input_text,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise WGError(
            f"{' '.join(cmd)} failed (rc={proc.returncode}): {proc.stderr.strip()}"
        )
    return proc.stdout


def genkey() -> str:
    return _run(["wg", "genkey"]).strip()


def pubkey(private: str) -> str:
    return _run(["wg", "pubkey"], input_text=private).strip()


def genpsk() -> str:
    return _run(["wg", "genpsk"]).strip()


def server_public_key() -> str:
    return SETTINGS.server_public_key_path.read_text().strip()


@dataclass
class PeerConfig:
    """Server-side representation of a peer, used to render wg0.conf."""
    name: str
    public_key: str
    preshared_key: str
    address: str  # "10.13.13.5/32"


def render_server_conf(peers: List[PeerConfig]) -> str:
    """Render the full wg0.conf the kernel should have.

    We feed this into `wg syncconf` so changes apply without dropping tunnels.
    """
    private = SETTINGS.server_private_key_path.read_text().strip()
    lines: List[str] = [
        "[Interface]",
        f"Address = {SETTINGS.server_address}",
        f"ListenPort = {SETTINGS.listen_port}",
        f"PrivateKey = {private}",
        "",
    ]
    for p in peers:
        lines += [
            f"# {p.name}",
            "[Peer]",
            f"PublicKey = {p.public_key}",
            f"PresharedKey = {p.preshared_key}",
            # AllowedIPs here is the server's notion of which source addresses
            # are valid for this peer. It is the cryptokey routing table; it
            # is NOT the ACL for what the peer is allowed to reach. ACLs live
            # in iptables.
            f"AllowedIPs = {p.address}",
            "",
        ]
    return "\n".join(lines)


def syncconf(peers: List[PeerConfig]) -> None:
    """Apply a new peer set to the running interface with no disconnects."""
    rendered = render_server_conf(peers)
    # wg-quick strip reads from /etc/wireguard/<if>.conf and removes
    # wg-quick-specific directives. We write a temp file, then pipe through
    # strip, then hand the result to `wg syncconf`.
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as tf:
        tf.write(rendered)
        tmp_path = Path(tf.name)
    try:
        stripped = _run(["wg-quick", "strip", str(tmp_path)])
        # syncconf wants a file path, not stdin, so another temp.
        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as tf2:
            tf2.write(stripped)
            stripped_path = Path(tf2.name)
        try:
            _run(["wg", "syncconf", SETTINGS.interface, str(stripped_path)])
        finally:
            stripped_path.unlink(missing_ok=True)
        # Also rewrite the canonical file so a container restart reproduces
        # the current state even before the app replays it.
        Path(f"/etc/wireguard/{SETTINGS.interface}.conf").write_text(rendered)
    finally:
        tmp_path.unlink(missing_ok=True)


def show_dump() -> List[Dict]:
    """Return a list of peer runtime records parsed from `wg show <if> dump`.

    The dump format is tab-separated. The first line describes the interface
    itself; every subsequent line is one peer:
        public_key  preshared  endpoint  allowed_ips  latest_handshake  rx  tx  keepalive
    """
    out = _run(["wg", "show", SETTINGS.interface, "dump"])
    lines = out.strip().splitlines()
    peers: List[Dict] = []
    for line in lines[1:]:  # skip interface header row
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        pub, _psk, endpoint, allowed_ips, handshake, rx, tx, keepalive = parts[:8]
        peers.append({
            "public_key": pub,
            "endpoint": endpoint if endpoint != "(none)" else None,
            "allowed_ips": allowed_ips,
            "latest_handshake": int(handshake),  # unix ts, 0 = never
            "rx_bytes": int(rx),
            "tx_bytes": int(tx),
            "persistent_keepalive": keepalive if keepalive != "off" else None,
        })
    return peers


def render_client_conf(
    *,
    peer_private_key: str,
    peer_preshared_key: str,
    peer_address: str,
    allowed_ips: List[str],
    dns_override: Optional[str] = None,
) -> str:
    """Render the .conf the end user imports into their WireGuard client.

    `allowed_ips` here is from the client's perspective: which destinations
    they should route through the tunnel. We set this to the same list as the
    server-side ACL so the client does not even try to send non-whitelisted
    traffic through the tunnel (which would just get dropped anyway).

    `dns_override` controls the DNS line:
      - None     → fall back to SETTINGS.peer_dns (server default)
      - ""       → omit the DNS line entirely (let the OS keep its DNS;
                   useful for split-tunnel where forcing all DNS through
                   the VPN would cause local DNS resolution to fail)
      - non-empty → use this string verbatim as the DNS value
    """
    lines = [
        "[Interface]",
        f"PrivateKey = {peer_private_key}",
        f"Address = {peer_address}",
    ]
    # Three-state DNS handling — the empty string is a sentinel for
    # "explicitly disabled" and is kept distinct from None ("inherit
    # server default").
    if dns_override is None:
        lines.append(f"DNS = {SETTINGS.peer_dns}")
    elif dns_override.strip() != "":
        lines.append(f"DNS = {dns_override}")
    # else: empty-string sentinel → no DNS line at all
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {server_public_key()}",
        f"PresharedKey = {peer_preshared_key}",
        f"Endpoint = {SETTINGS.endpoint}",
        f"AllowedIPs = {', '.join(allowed_ips) if allowed_ips else '0.0.0.0/32'}",
        "PersistentKeepalive = 25",
        "",
    ]
    return "\n".join(lines)


def qr_png(conf_text: str) -> bytes:
    """Render a config as a QR code PNG. Useful for mobile clients."""
    proc = subprocess.run(
        ["qrencode", "-t", "PNG", "-o", "-"],
        input=conf_text.encode(),
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise WGError(f"qrencode failed: {proc.stderr.decode().strip()}")
    return proc.stdout


def next_peer_address(used: List[str]) -> str:
    """Pick the next free /32 in the WG subnet, skipping the server address."""
    server_ip = SETTINGS.server_address.ip
    used_ips = {ipaddress.IPv4Interface(a).ip for a in used}
    used_ips.add(server_ip)
    for host in SETTINGS.subnet.hosts():
        if host not in used_ips:
            return f"{host}/32"
    raise WGError("address pool exhausted")
