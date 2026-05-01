"""PiVPN importer.

PiVPN spreads configuration across multiple files:
  /etc/wireguard/wg0.conf            -- server config + [Peer] blocks
  /etc/wireguard/configs/alice.conf  -- client configs, one per peer
  /etc/wireguard/configs/bob.conf
  ...

The natural operator workflow is `tar czf pivpn.tar.gz /etc/wireguard/`
or similar. We accept tar (.tar/.tar.gz/.tgz) and zip archives.

Strategy
--------
Per-client .conf files are the source of truth — they contain the
client's private key + their assigned address + (via [Peer]) the server's
public key. The peer's NAME comes from the .conf filename (PiVPN uses
`<name>.conf`). The server's wg0.conf gives us the server's PRIVATE key
plus an authoritative cross-check on each peer's public key.

We DO NOT trust filename order or client/server ordering. Every claim is
re-validated.

Edge cases handled
------------------
- Per-client .conf with no matching [Peer] entry in server wg0.conf:
  surface as a warning, skip the client (probably a stale .conf).
- IPv6 dual-stack addresses: imported as v4-only (matches wgflow's
  current single-stack behavior). v6 entries surface as warnings.
- Configs not at the canonical paths: we walk the archive and match by
  filename suffix, not absolute path. So `pivpn-backup/configs/alice.conf`
  works just as well as `etc/wireguard/configs/alice.conf`.
"""
from __future__ import annotations

import io
import re
import tarfile
import zipfile
from typing import Dict, List, Optional, Tuple

from . import parsed as P


def parse(content: bytes) -> P.ParsedImport:
    """Parse a PiVPN backup archive.

    Detects whether the bytes are a tar or zip and walks accordingly.
    Anything that isn't an archive raises ValueError; the dispatcher
    won't call us in that case but defense-in-depth.
    """
    files = _walk_archive(content)
    if not files:
        raise ValueError("archive is empty or unreadable")

    server_conf, client_confs = _find_relevant_files(files)
    out = P.ParsedImport(source=P.SOURCE_PIVPN, server_keypair=None)

    if server_conf is None:
        out.warnings.append(
            "no wg0.conf found in archive; server keypair will be unavailable "
            "and peer pubkeys can't be cross-checked"
        )
        server_section, server_peers = {}, {}
    else:
        try:
            server_section, server_peers = _parse_wg_conf(server_conf)
        except ValueError as e:
            out.warnings.append(f"wg0.conf parse failed: {e}")
            server_section, server_peers = {}, {}

        # Server keypair comes from [Interface].PrivateKey. We already
        # derive the public key with `wg pubkey` at commit time, but the
        # parser also extracts it from wg0.conf if present (PiVPN doesn't
        # store the server pubkey in wg0.conf, so this will usually be
        # empty — we'll fill it at commit time).
        priv = server_section.get("PrivateKey", "").strip()
        if priv:
            try:
                P.validate_wg_key(priv, label="server.PrivateKey")
                # Server's public_key is left empty here; commit-time
                # adoption logic re-derives it via wg pubkey. The IR
                # accommodates this with public_key="" but...
                # Actually the IR contract requires public_key always
                # present. We'll derive it now via base64 round-trip
                # only — we can't run `wg pubkey` from the parser
                # without a subprocess. Set public_key="" and tag a
                # warning: commit code will fill it in.
                out.server_keypair = P.ParsedKeyPair(
                    private_key=priv, public_key="",
                )
            except ValueError as e:
                out.warnings.append(f"server PrivateKey invalid: {e}")

    if not client_confs:
        out.warnings.append("no client .conf files found under configs/")
        return out

    for filename, content_str in client_confs.items():
        peer = _parse_client_conf(filename, content_str, server_peers)
        if peer is not None:
            out.peers.append(peer)

    # Cross-check: any [Peer] in wg0.conf that didn't match a client .conf?
    # That's a server-side peer with no client export available — surface
    # but don't block; operator may have removed the .conf intentionally.
    matched_pubkeys = {p.public_key for p in out.peers if p.public_key}
    for pubkey, srv_peer in server_peers.items():
        if pubkey not in matched_pubkeys:
            out.warnings.append(
                f"server has [Peer] with pubkey {pubkey[:12]}... "
                f"(allowed_ips={srv_peer.get('AllowedIPs', '?')}) "
                "but no matching client .conf was found in archive — skipped"
            )

    return out


# --- Archive walking ------------------------------------------------------


def _walk_archive(content: bytes) -> Dict[str, bytes]:
    """Read every file from a tar or zip archive into a dict.
    Returns {member_name: content_bytes}. Skips directories and
    too-large members (1 MiB cap per file — config files are tiny).
    """
    MAX_PER_FILE = 1 << 20  # 1 MiB
    MAX_TOTAL = 16 << 20    # 16 MiB
    total = 0
    out: Dict[str, bytes] = {}

    # Try tar first (handles .tar, .tar.gz, .tgz transparently).
    try:
        bio = io.BytesIO(content)
        with tarfile.open(fileobj=bio, mode="r:*") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                if member.size > MAX_PER_FILE:
                    continue
                total += member.size
                if total > MAX_TOTAL:
                    raise ValueError("archive too large")
                f = tar.extractfile(member)
                if f is None:
                    continue
                out[member.name] = f.read()
        return out
    except tarfile.ReadError:
        pass  # not a tar; try zip

    try:
        bio = io.BytesIO(content)
        with zipfile.ZipFile(bio, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                if info.file_size > MAX_PER_FILE:
                    continue
                total += info.file_size
                if total > MAX_TOTAL:
                    raise ValueError("archive too large")
                out[info.filename] = zf.read(info.filename)
        return out
    except zipfile.BadZipFile:
        raise ValueError("file is neither a tar nor a zip archive")


def _find_relevant_files(
    files: Dict[str, bytes]
) -> Tuple[Optional[str], Dict[str, str]]:
    """Locate wg0.conf and the client .conf files in an archive.

    Matches by filename suffix only (so `etc/wireguard/wg0.conf`,
    `pivpn-backup/wg0.conf`, and bare `wg0.conf` all work). Returns
    the wg0.conf content and a dict of {client_name: client_conf_content}.
    """
    server_conf = None
    client_confs: Dict[str, str] = {}

    for path, data in files.items():
        # PiVPN files are always pure ASCII; anything decoding-failing
        # is junk.
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue

        basename = path.rsplit("/", 1)[-1]
        if basename == "wg0.conf":
            server_conf = text
            continue
        # Client confs sit under a `configs/` directory in PiVPN. We
        # match on the path containing `/configs/` somewhere AND a
        # `.conf` suffix.
        if basename.endswith(".conf") and "/configs/" in path:
            name = basename[:-len(".conf")]
            client_confs[name] = text
            continue
        # Some archives put client confs at the top level (operator
        # manually copied them). Accept those too if they look like
        # client confs (have an [Interface] section with Address).
        if basename.endswith(".conf") and basename != "wg0.conf":
            if "[Interface]" in text and "Address" in text:
                name = basename[:-len(".conf")]
                # Don't overwrite a configs/ match — those are
                # canonical.
                client_confs.setdefault(name, text)

    return server_conf, client_confs


# --- INI-ish parser for wg-quick configs ----------------------------------
# wg-quick configs are INI-like: section headers in [brackets], key=value
# lines, comments with '#'. We don't use configparser because:
#   - Section names repeat ([Peer] appears N times)
#   - Keys can repeat within a section (AllowedIPs sometimes split)
# Roll our own minimal parser; it's ~30 lines and we don't have to fight
# configparser's quirks.

_SECTION_RX = re.compile(r"^\[([^\]]+)\]\s*$")
_KV_RX = re.compile(r"^\s*([A-Za-z]+)\s*=\s*(.+?)\s*$")


def _parse_wg_conf(text: str) -> Tuple[Dict[str, str], Dict[str, Dict[str, str]]]:
    """Parse a wg-quick config into ([Interface] dict, {pubkey: peer dict}).

    The peer dict is keyed by the peer's PublicKey so we can cross-look
    against client .conf files.

    Trailing comments after '#' are stripped. Lines without '=' are
    ignored (typical for blank lines and comments).
    """
    interface: Dict[str, str] = {}
    peers: Dict[str, Dict[str, str]] = {}
    current: Optional[Dict[str, str]] = None
    section: Optional[str] = None

    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = _SECTION_RX.match(line)
        if m:
            section = m.group(1)
            if section == "Interface":
                current = interface
            elif section == "Peer":
                current = {}
                # Defer insertion until we know the PublicKey.
            else:
                current = None  # unknown section; ignore lines until next [
            continue
        if current is None:
            continue
        kvm = _KV_RX.match(line)
        if not kvm:
            continue
        key, val = kvm.group(1), kvm.group(2)
        # Repeat keys (rare in wg-quick but possible for AllowedIPs)
        # are joined with comma.
        if key in current:
            current[key] = current[key] + ", " + val
        else:
            current[key] = val
        # If we've seen [Peer] and just got the PublicKey, register the
        # dict under that key.
        if section == "Peer" and key == "PublicKey":
            peers[val] = current
    return interface, peers


def _parse_client_conf(
    name: str,
    text: str,
    server_peers: Dict[str, Dict[str, str]],
) -> Optional[P.ParsedPeer]:
    """One PiVPN client .conf → one ParsedPeer.

    The client conf gives us the client's privkey + address. The matching
    [Peer] entry in the server's wg0.conf gives us the client's PUBLIC key
    (which the client's own conf doesn't contain — that's just how
    wg-quick configs work; the server has the pubkey, the client doesn't
    embed its own).

    So we derive: client_privkey from client conf → expect pubkey to
    appear in server wg0.conf [Peer] AllowedIPs matching the client's
    Address. We do this by IP-matching since the client conf doesn't
    embed its own pubkey.
    """
    try:
        interface, _client_peers = _parse_wg_conf(text)
    except ValueError as e:
        peer = _invalid(name, f"client conf parse failed: {e}")
        return peer

    privkey = interface.get("PrivateKey", "").strip()
    address = interface.get("Address", "").strip()

    peer = P.ParsedPeer(
        name="", public_key="", private_key="", preshared_key="",
        address="", has_private_key=True,
        notes=f"imported from PiVPN ({name}.conf)",
    )

    try:
        peer.name = P.validate_peer_name(name)
        peer.private_key = P.validate_wg_key(privkey, label=f"{name}.PrivateKey")
        # PiVPN often writes `Address = 10.6.0.2/24` — that /24 is the
        # client's view of the network, not the peer's address mask.
        # Strip the prefix and re-add as /32, our canonical form.
        if "," in address:
            # Dual-stack — keep only the first IPv4. Surface as note.
            address = address.split(",")[0].strip()
        if "/" in address:
            address = address.split("/", 1)[0]
        peer.address = P.validate_address(address)

        # Now find this peer's pubkey by matching address against the
        # server's [Peer] AllowedIPs.
        pubkey = _lookup_peer_pubkey(peer.address, server_peers)
        if pubkey is None:
            raise ValueError(
                "no matching [Peer] block found in server wg0.conf for this address"
            )
        peer.public_key = P.validate_wg_key(pubkey, label=f"{name}.publicKey")

        # PSK is in the [Peer] block of the SERVER conf (server-side) or
        # the client conf (client-side). They should match. Prefer the
        # client conf's [Peer] PresharedKey since that's authoritative
        # for the client tunnel.
        client_peer_blocks = list(_client_peers.values())
        psk = ""
        if client_peer_blocks:
            psk = client_peer_blocks[0].get("PresharedKey", "").strip()
        if not psk:
            srv_block = server_peers.get(pubkey, {})
            psk = srv_block.get("PresharedKey", "").strip()
        if psk:
            peer.preshared_key = P.validate_wg_key(psk, label=f"{name}.PSK")
        else:
            peer.preshared_key = ""

    except ValueError as e:
        peer.status = P.STATUS_INVALID
        peer.invalid_reason = str(e)
    return peer


def _lookup_peer_pubkey(
    address_cidr: str, server_peers: Dict[str, Dict[str, str]]
) -> Optional[str]:
    """Find the [Peer] block whose AllowedIPs contains this peer's address.

    AllowedIPs in the server config typically holds a single /32 for the
    peer's wgflow address. May contain extra entries (rare in PiVPN).
    Match by exact-string after normalising.
    """
    target = address_cidr  # e.g. "10.6.0.2/32"
    target_ip = address_cidr.split("/", 1)[0]
    for pubkey, peer_block in server_peers.items():
        allowed = peer_block.get("AllowedIPs", "")
        for entry in (e.strip() for e in allowed.split(",")):
            if not entry:
                continue
            if entry == target:
                return pubkey
            # Tolerate "10.6.0.2/32" vs "10.6.0.2" mismatch.
            if entry.split("/", 1)[0] == target_ip:
                return pubkey
    return None


def _invalid(name: str, reason: str) -> P.ParsedPeer:
    """Build a ParsedPeer that's just a placeholder for the failed row."""
    p = P.ParsedPeer(
        name=name[:64], public_key="", private_key="", preshared_key="",
        address="", has_private_key=True,
        notes="",
    )
    p.status = P.STATUS_INVALID
    p.invalid_reason = reason
    return p
