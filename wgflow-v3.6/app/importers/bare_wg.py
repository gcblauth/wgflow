"""Bare WireGuard importer (single wg0.conf with [Interface] + [Peer]s).

The server wg0.conf knows everything about itself (privkey, listen port)
but only knows peer PUBLIC keys. The peers' private keys live with the
clients — we cannot regenerate client configs for them.

This is the lowest-fidelity import:
  - Each peer ends up with `has_private_key=False` so the UI hides the
    "download config" button.
  - Names come from the `### name` comment line that wg-quick supports
    (no formal way to name peers in bare wg, but operators commonly add
    these as comments above each [Peer] block).
  - Peers without a name comment get auto-named `imported-N` where N
    is the position in the file.

The peer keypair situation is the trade-off the operator is making by
choosing this import path: they keep their existing tunnels alive
(client configs continue to work, since wgflow adopts the server's
private key) but accept that wgflow-managed re-issuing of these clients
isn't possible.
"""
from __future__ import annotations

import re
from typing import List, Optional

from . import parsed as P


# Same INI-ish parser as pivpn.py but here we also track preceding
# comments so we can attach them as peer names.
_SECTION_RX = re.compile(r"^\[([^\]]+)\]\s*$")
_KV_RX = re.compile(r"^\s*([A-Za-z]+)\s*=\s*(.+?)\s*$")
_NAME_COMMENT_RX = re.compile(r"^###?\s*(?:Client|Peer|Name)?\s*[:\-]?\s*(.+)$")


def parse(content: bytes) -> P.ParsedImport:
    """Parse a bare WireGuard wg0.conf."""
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("wg0.conf is not valid UTF-8")

    out = P.ParsedImport(source=P.SOURCE_BARE_WG, server_keypair=None)

    interface, peer_blocks = _parse_with_names(text)

    priv = interface.get("PrivateKey", "").strip()
    if priv:
        try:
            P.validate_wg_key(priv, label="server.PrivateKey")
            # Bare-WG: we have privkey, no pubkey in conf. Public derives
            # at commit time via `wg pubkey`. IR convention: public_key=""
            # signals "needs derivation".
            out.server_keypair = P.ParsedKeyPair(
                private_key=priv, public_key="",
            )
        except ValueError as e:
            out.warnings.append(f"server PrivateKey invalid: {e}")
    else:
        out.warnings.append(
            "no [Interface] PrivateKey found — server keypair will not be "
            "available for adoption"
        )

    if not peer_blocks:
        out.warnings.append("no [Peer] blocks found in wg0.conf")
        return out

    for idx, (name_hint, peer_block) in enumerate(peer_blocks, start=1):
        name = name_hint or f"imported-{idx}"
        peer = _build_peer(name, peer_block)
        if peer is not None:
            out.peers.append(peer)

    return out


def _parse_with_names(text: str):
    """Like _parse_wg_conf in pivpn.py but tracks the most recent comment
    line to use as a peer name.

    Returns ([Interface] dict, [(name_hint, peer_dict), ...]).
    """
    interface = {}
    peers = []
    current = None
    current_name_hint: Optional[str] = None
    pending_name_hint: Optional[str] = None
    section: Optional[str] = None

    for raw in text.splitlines():
        stripped = raw.strip()
        # Catch name-comment lines BEFORE we strip the comment for parsing.
        # These are lines starting with '#' or '##'/'###'.
        if stripped.startswith("#"):
            # Strip leading hashes and whitespace, then try the name regex.
            comment = stripped.lstrip("#").strip()
            if comment:
                m = _NAME_COMMENT_RX.match("### " + comment)
                if m:
                    pending_name_hint = m.group(1).strip()
            continue

        line = raw.split("#", 1)[0].strip()
        if not line:
            continue

        m = _SECTION_RX.match(line)
        if m:
            # Flush the previous [Peer] block if any.
            if section == "Peer" and current:
                peers.append((current_name_hint, current))
            section = m.group(1)
            if section == "Interface":
                current = interface
                current_name_hint = None
            elif section == "Peer":
                current = {}
                current_name_hint = pending_name_hint
                pending_name_hint = None
            else:
                current = None
            continue

        if current is None:
            continue
        kvm = _KV_RX.match(line)
        if not kvm:
            continue
        key, val = kvm.group(1), kvm.group(2)
        if key in current:
            current[key] = current[key] + ", " + val
        else:
            current[key] = val

    # Flush trailing peer block.
    if section == "Peer" and current:
        peers.append((current_name_hint, current))

    return interface, peers


def _build_peer(name: str, block: dict) -> Optional[P.ParsedPeer]:
    """One [Peer] block → one ParsedPeer (pubkey-only)."""
    peer = P.ParsedPeer(
        name="", public_key="", private_key="", preshared_key="",
        address="", has_private_key=False,
        notes="imported from bare WireGuard wg0.conf (pubkey-only)",
    )
    try:
        peer.name = P.validate_peer_name(name)
        peer.public_key = P.validate_wg_key(
            block.get("PublicKey", "").strip(),
            label=f"{name}.PublicKey",
        )
        # Bare WG peers don't have private keys server-side — that's the
        # whole point. private_key="" is the sentinel; has_private_key=False
        # is the authoritative flag for the UI.
        peer.private_key = ""

        psk = block.get("PresharedKey", "").strip()
        if psk:
            peer.preshared_key = P.validate_wg_key(psk, label=f"{name}.PSK")
        else:
            peer.preshared_key = ""

        # Address comes from AllowedIPs. Bare-WG conventions:
        # `AllowedIPs = 10.6.0.2/32` is a single peer at that address.
        # Take the first IPv4 entry.
        allowed = block.get("AllowedIPs", "").strip()
        if not allowed:
            raise ValueError("[Peer] block has no AllowedIPs")
        first = allowed.split(",")[0].strip()
        peer.address = P.validate_address(first)

    except ValueError as e:
        peer.status = P.STATUS_INVALID
        peer.invalid_reason = str(e)
    return peer
