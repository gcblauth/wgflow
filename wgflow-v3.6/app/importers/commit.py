"""Commit logic for an import.

Two entry points:

  compute_statuses(parsed, db_conn, subnet) — populates `peer.status` and
    optionally `peer.assigned_address` for each peer in `parsed`. Pure
    function w.r.t. the DB (read-only). Called when serving a preview.

  apply(parsed, accepted_indices, adopt_server_keypair, db, ...) —
    actually inserts the chosen peers, rewrites the server keypair if
    requested, and triggers a kernel replay. Transactional: any failure
    rolls back the DB write and leaves files untouched.

The commit step is the only place that runs `wg pubkey` to derive a
public key when the parser left it empty (PiVPN and bare-WG can't run
subprocesses safely from inside the parser).
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Set, Tuple

from .. import wg_manager as wg
from . import parsed as P


# ---------------------------------------------------------------------------
# Status computation (read-only against the DB)
# ---------------------------------------------------------------------------


@dataclass
class _ExistingState:
    """Snapshot of the bits of wgflow state we need to detect conflicts."""
    used_names: Set[str]
    used_pubkeys: Set[str]
    used_addresses: Set[str]   # CIDR strings, e.g. "10.13.13.5/32"
    subnet: ipaddress.IPv4Network


def compute_statuses(
    parsed: P.ParsedImport,
    db_conn,
    subnet: ipaddress.IPv4Network,
    server_address: Optional[ipaddress.IPv4Address] = None,
) -> None:
    """Annotate every peer in `parsed` with a status reflecting how it
    compares to the current wgflow state. Mutates `parsed` in place.

    `server_address` (if supplied) is added to the "used" set so the
    auto-reassignment never hands out the wgflow server's own /32. In
    production callers should always pass it; the param is optional so
    unit tests can run without poking SETTINGS.

    Status precedence (highest first):
      1. STATUS_INVALID — parser already rejected it, leave alone
      2. STATUS_PUBKEY_CONFLICT — same pubkey already in DB (re-import)
      3. STATUS_NAME_CONFLICT — different pubkey, same name
      4. STATUS_ADDRESS_CONFLICT — pubkey & name OK, but IP collides
      5. STATUS_ADDRESS_OUT_OF_RANGE — IP fine in source's subnet, not in ours
      6. STATUS_OK — clean

    For peers whose only issue is address-out-of-range, we precompute an
    `assigned_address` from the wgflow free pool so the preview can show
    "alice → will be reassigned to 10.13.13.42 (was 10.6.0.5)".
    """
    state = _snapshot_existing(db_conn, subnet)
    if server_address is not None:
        state.used_addresses = state.used_addresses | {f"{server_address}/32"}

    # Track addresses we'll auto-assign during this import so two
    # incoming peers don't both get the same fresh /32.
    pending_assignments: Set[str] = set()

    for peer in parsed.peers:
        if peer.status == P.STATUS_INVALID:
            continue

        if peer.public_key and peer.public_key in state.used_pubkeys:
            peer.status = P.STATUS_PUBKEY_CONFLICT
            continue

        if peer.name in state.used_names:
            peer.status = P.STATUS_NAME_CONFLICT
            continue

        # Is the source address in our subnet?
        try:
            iface = ipaddress.IPv4Interface(peer.address)
        except ValueError:
            # Shouldn't happen — parser validated this — but defensive.
            peer.status = P.STATUS_INVALID
            peer.invalid_reason = f"address {peer.address!r} unparseable at commit"
            continue

        if iface.ip not in state.subnet:
            # Out of range. Try to reassign from our free pool.
            assigned = _pick_free_address(
                state.subnet,
                state.used_addresses | pending_assignments,
            )
            if assigned is None:
                peer.status = P.STATUS_INVALID
                peer.invalid_reason = (
                    f"source address {peer.address} not in wgflow subnet "
                    f"({state.subnet}) and free pool is exhausted"
                )
            else:
                peer.status = P.STATUS_ADDRESS_OUT_OF_RANGE
                peer.assigned_address = assigned
                pending_assignments.add(assigned)
            continue

        if peer.address in state.used_addresses or peer.address in pending_assignments:
            peer.status = P.STATUS_ADDRESS_CONFLICT
            continue

        peer.status = P.STATUS_OK
        pending_assignments.add(peer.address)


def _snapshot_existing(db_conn, subnet: ipaddress.IPv4Network) -> _ExistingState:
    rows = db_conn.execute(
        "SELECT name, public_key, address FROM peers"
    ).fetchall()
    return _ExistingState(
        used_names={r["name"] for r in rows},
        used_pubkeys={r["public_key"] for r in rows},
        used_addresses={r["address"] for r in rows},
        subnet=subnet,
    )


def _pick_free_address(
    subnet: ipaddress.IPv4Network, used: Set[str]
) -> Optional[str]:
    """Find the first /32 in `subnet` not in `used`. Returns None if the
    subnet is full. Skips the network and broadcast addresses; does NOT
    skip the server's own /32 because that's already in `used`.
    """
    used_ips = set()
    for cidr in used:
        try:
            used_ips.add(ipaddress.IPv4Interface(cidr).ip)
        except ValueError:
            continue
    for host in subnet.hosts():
        if host not in used_ips:
            return f"{host}/32"
    return None


# ---------------------------------------------------------------------------
# Apply (write to DB + replay to kernel)
# ---------------------------------------------------------------------------


@dataclass
class CommitResult:
    """Summary of what apply() did. Surfaced in the API response so the
    UI can show 'imported 12 peers, skipped 3 conflicts'."""
    imported: int
    skipped_conflict: int
    skipped_invalid: int
    server_keypair_adopted: bool
    new_server_pubkey: Optional[str]  # if adopted


def apply(
    parsed: P.ParsedImport,
    accepted_indices: List[int],
    adopt_server_keypair: bool,
    db,
    server_private_key_path,
    server_public_key_path,
    default_acl: list,
    create_peer_chain: Callable,
    apply_peer_acls: Callable,
    sync_wg: Callable,
    load_peer_acls: Callable,
) -> CommitResult:
    """Apply the chosen peers from `parsed` to the wgflow DB, optionally
    adopting the source's server keypair, then push state to the kernel.

    The function takes its dependencies as parameters (the iptables/wg
    helpers and the keypair file paths) rather than importing main.py
    directly, to avoid a circular import. main.py wires them up at the
    call site.

    Transactional structure:
      1. Validate accepted peer indices + recompute statuses defensively
      2. Derive any missing server-side public keys via `wg pubkey`
      3. Open a write transaction:
         a. INSERT peers (with default ACL)
         b. UPDATE peers if anything goes wrong → rollback automatically
      4. Outside the transaction:
         a. Rewrite server keypair files atomically (tmp → rename)
         b. Replay state to kernel (iptables + wg syncconf)

    If step 4 fails, the DB is consistent — the new peers are present
    and `_replay_state_to_kernel` can be invoked again later to push
    them through. We don't try to roll back the DB on a kernel-replay
    failure because the operator's tunnels were already serving traffic
    with the previous state, and partial-rollback would leave a worse
    mess than just letting them retry.
    """
    # 1. Recompute statuses to pick up anything that changed since the
    # preview was generated (rare, but possible if the operator added a
    # peer in another tab between preview and commit).
    import ipaddress as _ipaddress
    subnet_attr = _peek_subnet(db.conn)
    if subnet_attr is None:
        raise RuntimeError("wgflow subnet not available")
    server_addr = _peek_server_address()
    compute_statuses(parsed, db.conn, subnet_attr, server_address=server_addr)

    # 2. Filter to accepted + import-eligible peers.
    eligible_statuses = {
        P.STATUS_OK,
        P.STATUS_ADDRESS_OUT_OF_RANGE,  # we'll use assigned_address
    }
    skipped_invalid = 0
    skipped_conflict = 0
    chosen: List[P.ParsedPeer] = []

    for idx in accepted_indices:
        if idx < 0 or idx >= len(parsed.peers):
            continue
        peer = parsed.peers[idx]
        if peer.status == P.STATUS_INVALID:
            skipped_invalid += 1
            continue
        if peer.status not in eligible_statuses:
            skipped_conflict += 1
            continue
        chosen.append(peer)

    # 3. Derive a missing server pubkey if we're adopting the keypair.
    new_server_pub: Optional[str] = None
    if adopt_server_keypair:
        if parsed.server_keypair is None:
            raise RuntimeError(
                "adopt_server_keypair=True but source has no server keypair"
            )
        priv = parsed.server_keypair.private_key
        pub = parsed.server_keypair.public_key
        if not pub:
            # Parser couldn't derive (PiVPN, bare-WG). Do it now via wg pubkey.
            pub = wg.pubkey(priv)
            P.validate_wg_key(pub, label="derived server.publicKey")
        new_server_pub = pub

    # 4. Insert peers in one transaction.
    inserted_ids: List[int] = []
    with db.write() as conn:
        for peer in chosen:
            address = peer.assigned_address or peer.address
            # Generate a PSK on the fly if the source didn't provide one.
            psk = peer.preshared_key or wg.genpsk()

            cur = conn.execute(
                """INSERT INTO peers
                   (name, public_key, private_key, preshared_key, address,
                    enabled, dns, has_private_key)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    peer.name,
                    peer.public_key,
                    peer.private_key,                  # "" for bare-WG
                    psk,
                    address,
                    1 if peer.enabled else 0,
                    peer.dns,
                    1 if peer.has_private_key else 0,
                ),
            )
            new_id = cur.lastrowid
            inserted_ids.append(new_id)

            # Default ACL on every imported peer. We deliberately do NOT
            # try to translate the source's AllowedIPs into wgflow ACLs:
            # AllowedIPs is a routing concept, ACLs are a firewall concept,
            # they don't map cleanly. Operator can adjust ACLs after import.
            for entry in default_acl:
                # comment column added in v3.6; default ACL entries from
                # importers don't carry comments (they're machine-generated
                # from AllowedIPs, no operator label exists yet). Stored
                # as NULL; operator can add comments later via the editor.
                conn.execute(
                    "INSERT INTO peer_acls (peer_id, cidr, port, proto, action, comment) "
                    "VALUES (?, ?, ?, ?, ?, NULL)",
                    (new_id, entry.cidr, entry.port, entry.proto, entry.action),
                )

    # 5. If we're adopting the server keypair, swap the on-disk files
    # atomically. tmp → rename pattern guarantees we never have a
    # half-written privkey on disk.
    server_keypair_adopted = False
    if adopt_server_keypair and new_server_pub:
        _replace_server_keypair(
            server_private_key_path,
            server_public_key_path,
            parsed.server_keypair.private_key,
            new_server_pub,
        )
        server_keypair_adopted = True

    # 6. Replay state to kernel. iptables + wg syncconf.
    for pid in inserted_ids:
        row = db.conn.execute(
            "SELECT address FROM peers WHERE id = ?", (pid,)
        ).fetchone()
        if row is None:
            continue
        create_peer_chain(pid, row["address"])
        apply_peer_acls(pid, load_peer_acls(pid), peer_address=row["address"])
    sync_wg()

    return CommitResult(
        imported=len(inserted_ids),
        skipped_conflict=skipped_conflict,
        skipped_invalid=skipped_invalid,
        server_keypair_adopted=server_keypair_adopted,
        new_server_pubkey=new_server_pub if server_keypair_adopted else None,
    )


def _peek_subnet(conn) -> Optional[ipaddress.IPv4Network]:
    """Pull the wgflow subnet from SETTINGS without importing main.

    We don't actually need the DB here — SETTINGS is a module global.
    Reading it via this indirection keeps `apply()` testable.
    """
    from ..config import SETTINGS  # local import to avoid cycles
    return SETTINGS.subnet


def _peek_server_address() -> Optional[ipaddress.IPv4Address]:
    """Same indirection trick: get the wgflow server's /32 host address
    so the address-reassignment pool excludes it."""
    from ..config import SETTINGS
    try:
        return SETTINGS.server_address.ip
    except (AttributeError, ValueError):
        return None


def _replace_server_keypair(
    priv_path,
    pub_path,
    new_priv: str,
    new_pub: str,
) -> None:
    """Rewrite the server's keypair files atomically.

    Each file is written to a sibling .tmp path, fsynced, and then
    renamed over the original. POSIX rename is atomic within a single
    filesystem, so a crash mid-write leaves the OLD file intact, never
    a half-written one.
    """
    import os
    from pathlib import Path

    priv_path = Path(priv_path)
    pub_path = Path(pub_path)

    for path, content in [(priv_path, new_priv + "\n"),
                          (pub_path, new_pub + "\n")]:
        tmp = path.with_suffix(path.suffix + ".tmp")
        with open(tmp, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
