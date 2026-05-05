"""FastAPI application for wgflow."""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Optional

from fastapi import (
    FastAPI,
    File,
    HTTPException,
    Request,
    Response,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import HTMLResponse, JSONResponse

from . import acl as acl_mod
from . import auth
from . import dns_log as dns_log_mod
from . import dns_overrides
from . import multisite as multisite_mod
from . import blocklist as blocklist_mod
from . import upstream as upstream_mod
from . import inspector
from . import installer_script
from . import iptables_manager as ipt
from . import log_streams
from . import network_diag
from . import wg_manager as wg
from .config import SETTINGS
from .db import DB
from .importers import commit as importer_commit
from .importers import detector as importer_detector
from .importers import preview_store as importer_store
from .importers import serialize as importer_serialize
from .telemetry import run_telemetry_loop
from .metrics import MetricsState
from .models import (
    ACLUpdate,
    BatchByCount,
    BatchByNames,
    MultisiteCreateLinkRequest,
    MultisiteImportCompleteRequest,
    MultisiteRegistrationRequest,
    MultisiteUpdateRequest,
    BlocklistSourceCreate,
    BlocklistSourceUpdate,
    BlocklistSourceOut,
    UpstreamPreviewRequest,
    UpstreamCreateRequest,
    UpstreamConnectionOut,
    UpstreamPreviewOut,
    UpstreamUpdateRequest,
    ImportCommit,
    InstanceConfig,
    MigrationToggle,
    PanelOrder,
    PeerCreate,
    PeerEnabledUpdate,
    PeerLive,
    PeerOut,
    TunnelSettings,
)

# ---------------------------------------------------------------------------
# Startup / DB singleton
# ---------------------------------------------------------------------------

db: Optional[DB] = None
metrics: MetricsState = MetricsState()
dns_log: dns_log_mod.DNSLog = dns_log_mod.DNSLog()


def get_db() -> DB:
    assert db is not None, "DB not initialised"
    return db


def _row_to_peer_out(conn, row) -> PeerOut:
    acl_rows = conn.execute(
        "SELECT cidr, port, proto, action, comment, alias_ref "
        "FROM peer_acls WHERE peer_id = ? ORDER BY id",
        (row["id"],),
    ).fetchall()
    entries = []
    for r in acl_rows:
        action = r["action"] if (r["action"] in ("allow", "deny")) else "allow"
        comment = r["comment"] or ""
        # v3.7: rows can be alias references (alias_ref column populated,
        # cidr NULL) or literal CIDR rules (cidr populated, alias_ref NULL).
        # The `alias_ref` column was added in v3.7 migration, so it may
        # not exist on rows from pre-3.7 DBs that haven't gone through
        # the schema reload — defensive lookup.
        alias_ref = None
        if "alias_ref" in r.keys():
            alias_ref = r["alias_ref"]
        if alias_ref:
            entries.append(acl_mod.ACLAliasRef(
                name=alias_ref,
                action=action,
                comment=comment,
            ))
        else:
            entries.append(acl_mod.ACLEntry(
                cidr=r["cidr"],
                port=r["port"],
                proto=r["proto"],
                action=action,
                comment=comment,
            ))
    dns_val = row["dns"] if "dns" in row.keys() else None
    # has_private_key may be missing on rows from databases that haven't
    # run the 3.3 migration yet (defensive — startup migration should
    # have populated it, but we don't want a KeyError if some path
    # bypasses it).
    has_priv = bool(row["has_private_key"]) if "has_private_key" in row.keys() else True
    # `enabled` is in the original schema (3.0+) so it should always be
    # present, but be defensive here too. Default to True so an
    # accidentally-NULL row gets safe behavior (visible + active).
    enabled_val = bool(row["enabled"]) if "enabled" in row.keys() and row["enabled"] is not None else True
    # peer_type may be missing on databases pre-v4.2-rebuild migration
    # — defensive default to 'client' so untagged rows render as
    # ordinary peers (which is the right interpretation: anything
    # that existed before peer_type was introduced is a client).
    peer_type_val = row["peer_type"] if "peer_type" in row.keys() and row["peer_type"] else "client"
    return PeerOut(
        id=row["id"],
        name=row["name"],
        public_key=row["public_key"],
        address=row["address"],
        created_at=row["created_at"],
        acl=[str(e) for e in entries],
        dns=dns_val,
        has_private_key=has_priv,
        enabled=enabled_val,
        peer_type=peer_type_val,
    )


_WG_CONF_NAME_UNSAFE = re.compile(r"[^A-Za-z0-9_\-]")


def _wg_conf_safe_name(name: str, fallback: str) -> str:
    """Sanitize a peer name so it can safely appear as a `# {name}`
    comment in a rendered wg conf.

    `wg syncconf` parses what looks like a section header (`[Foo]`)
    even when it follows a `#` — and operator-supplied names can
    contain brackets, spaces, etc. We replace any character outside
    the wg-conf-safe alphabet with underscore. If the result is
    empty, use `fallback` (e.g. `multisite-link-7` keyed by row id).

    The DB row keeps the original pretty name (the panel UI shows
    that). Only the rendered conf uses the sanitized form.
    """
    safe = _WG_CONF_NAME_UNSAFE.sub("_", name or "")
    return safe if safe else fallback


def _local_instance_name() -> str:
    """Read this wgflow's local instance name from network_settings.

    Used by the multisite registration/bundle builders so the OTHER
    side learns what we call ourselves. Falls back to the container
    hostname when nothing is set in the panel — better than empty
    string, makes paired peers identifiable out of the box.

    Sanitised: max 64 chars, no control characters, no quotes (the
    string lands in a `# ...` comment line in registration/bundle
    text and gets parsed back out — control chars would break the
    regex and quote chars would confuse logs).
    """
    name = ""
    try:
        conn = get_db().conn
        row = conn.execute(
            "SELECT value FROM network_settings WHERE key = 'instance_name'"
        ).fetchone()
        if row and row["value"]:
            name = row["value"]
    except Exception:
        # DB unavailable / table missing — return hostname fallback.
        pass
    if not name:
        try:
            name = socket.gethostname()
        except Exception:
            name = ""
    name = (name or "").strip()
    name = re.sub(r"[\r\n\t'\"]", " ", name)
    return name[:64]


def _live_wg0_pubkey() -> str:
    """Return wg0's actual server pubkey by querying the kernel.

    Falls back to SETTINGS.server_public_key_path if the kernel query
    fails (interface not up yet, wg binary missing — neither expected
    in production but we want this to fail gracefully). Logs a loud
    warning if the file disagrees with the kernel; the kernel value
    always wins because that's what packets are signed with on the
    wire.

    This is the SINGLE SOURCE OF TRUTH for wgflow's wg0 server
    pubkey. Used by both the multisite registration (step 1) and
    bundle (step 2) endpoints. Symmetric: both ends of a multisite
    link peer with each other using their respective wg0 server
    keypairs — there is NO per-link keypair.
    """
    pubkey = None
    try:
        proc = subprocess.run(
            ["wg", "show", SETTINGS.interface, "public-key"],
            capture_output=True, text=True, check=True,
        )
        pubkey = proc.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"[multisite] warn: kernel pubkey lookup failed ({e!r}), "
              f"falling back to {SETTINGS.server_public_key_path}",
              flush=True)

    if not pubkey:
        try:
            pubkey = SETTINGS.server_public_key_path.read_text().strip()
        except FileNotFoundError:
            raise HTTPException(
                500,
                "server public key not found at "
                f"{SETTINGS.server_public_key_path} — has the wg keypair "
                "been generated?",
            )

    # Defensive: warn if the file disagrees with the kernel.
    try:
        file_pubkey = SETTINGS.server_public_key_path.read_text().strip()
        if file_pubkey and file_pubkey != pubkey:
            print(f"[multisite] WARNING: server_public.key "
                  f"({file_pubkey[:16]}...) does NOT match live wg0 "
                  f"pubkey ({pubkey[:16]}...). Using kernel value. "
                  f"Consider regenerating the file: "
                  f"wg show {SETTINGS.interface} public-key > "
                  f"{SETTINGS.server_public_key_path}",
                  flush=True)
    except FileNotFoundError:
        pass

    return pubkey


def _load_all_peers_for_sync() -> List[wg.PeerConfig]:
    """Build the wg0 [Peer] list from sqlite for `wg syncconf`.

    Two flavors of peer end up on wg0:

      1. Client peers (peer_type='client'). Their AllowedIPs is just
         their tunnel /32 — the cryptokey routing table that the
         server uses to validate incoming source addresses.

      2. Mgmt peers (peer_type='multisite', v4.2-rebuild). Their
         AllowedIPs is their overlay /32 PLUS any networks the remote
         wgflow advertised through this link (so traffic destined for
         those networks gets routed through this peer's tunnel).
         The advertised networks are stored on federation_links.
         remote_advertised, joined here.

    Both are returned as the same wg.PeerConfig shape — the
    distinction matters only for AllowedIPs construction.
    """
    conn = get_db().conn

    # Client peers: simple shape, AllowedIPs = just the /32.
    client_rows = conn.execute(
        "SELECT id, name, public_key, preshared_key, address "
        "FROM peers WHERE enabled = 1 AND peer_type = 'client'"
    ).fetchall()
    out: List[wg.PeerConfig] = [
        wg.PeerConfig(
            name=_wg_conf_safe_name(r["name"], f"peer-{r['id']}"),
            public_key=r["public_key"],
            preshared_key=r["preshared_key"],
            address=r["address"],
        )
        for r in client_rows
    ]

    # Mgmt peers: AllowedIPs = overlay /32 + remote_advertised CIDRs.
    # Joined to federation_links to pick up the per-link advertised
    # networks. The peer.address column already holds the overlay /32;
    # we extend it with advertised networks for the AllowedIPs render.
    mgmt_rows = conn.execute(
        "SELECT p.id, p.name, p.public_key, p.preshared_key, p.address, "
        "       fl.remote_advertised, fl.remote_endpoint "
        "FROM peers p "
        "LEFT JOIN federation_links fl ON fl.peer_id = p.id "
        "WHERE p.enabled = 1 AND p.peer_type = 'multisite'"
    ).fetchall()
    for r in mgmt_rows:
        aips = [r["address"]]   # overlay /32 first
        adv = (r["remote_advertised"] or "").strip()
        if adv:
            for cidr in adv.split(","):
                cidr = cidr.strip()
                if cidr and cidr not in aips and cidr not in ("0.0.0.0/0", "::/0"):
                    aips.append(cidr)
        safe_name = _wg_conf_safe_name(r["name"], f"multisite-link-{r['id']}")
        out.append(wg.PeerConfig(
            name=safe_name,
            public_key=r["public_key"],
            preshared_key=r["preshared_key"],
            address=", ".join(aips),
            endpoint=r["remote_endpoint"],
            # Keep the tunnel alive across NAT — multisite is meant to
            # survive idle periods (panel federation polls only every
            # 5s; without keepalive a NAT mapping could expire).
            persistent_keepalive=25,
        ))

    return out


def _load_federation_peers_for_sync() -> List[wg.PeerConfig]:
    """Returns [] in v4.2+. Kept as a function rather than removing
    callers because there might still be one or two; safe-empty
    behavior makes the migration boring.

    v4.0 used this to inject federation peers into wg0's peer list,
    sharing one kernel interface for client + federation traffic.
    v4.2-pre moved federation to wg1; v4.2-rebuild moves it back to
    wg0 but as peer_type='multisite' rows in the peers table, which
    are now picked up by _load_all_peers_for_sync above.
    """
    return []


def _load_acl_alias_lookup(conn=None) -> dict:
    """Read all ACL aliases from the DB and return a {name -> [ACLEntry]} map.

    Body is stored as JSON in acl_aliases.body; we deserialize and
    re-construct ACLEntry objects so the iptables generator can consume
    them directly. Aliases are allow-only (the body's stored entries
    have action='allow'); the deny semantics come from the alias usage.
    """
    if conn is None:
        conn = get_db().conn
    out: dict = {}
    rows = conn.execute("SELECT name, body FROM acl_aliases").fetchall()
    for r in rows:
        try:
            body_list = json.loads(r["body"])
        except (json.JSONDecodeError, TypeError):
            # Corrupt body — skip this alias so it doesn't crash the
            # iptables apply path. Operator can fix on the aliases tab.
            continue
        entries = []
        for item in body_list:
            try:
                entries.append(acl_mod.ACLEntry(
                    cidr=item.get("cidr", ""),
                    port=item.get("port"),
                    proto=item.get("proto"),
                    action="allow",   # always — see schema comment
                    comment="",
                ))
            except Exception:
                continue
        out[r["name"]] = entries
    return out


def _load_peer_acls(peer_id: int) -> List[acl_mod.ACLEntry]:
    """Return the FLATTENED ACLEntry list for iptables consumption.

    Alias references in peer_acls (rows with alias_ref set) are
    expanded via the alias table here, before the list reaches the
    iptables generator. Missing aliases are silently skipped (the
    operator-facing error happens at save time, not apply time —
    we don't want a deleted alias to break startup replay).
    """
    rows = get_db().conn.execute(
        "SELECT cidr, port, proto, action, comment, alias_ref "
        "FROM peer_acls WHERE peer_id = ? ORDER BY id",
        (peer_id,),
    ).fetchall()
    items = []
    for r in rows:
        action = r["action"] if (r["action"] in ("allow", "deny")) else "allow"
        comment = r["comment"] or ""
        alias_ref = r["alias_ref"] if "alias_ref" in r.keys() else None
        if alias_ref:
            items.append(acl_mod.ACLAliasRef(
                name=alias_ref, action=action, comment=comment,
            ))
        else:
            items.append(acl_mod.ACLEntry(
                cidr=r["cidr"],
                port=r["port"],
                proto=r["proto"],
                action=action,
                comment=comment,
            ))

    # Expand. Use the resilient mode (silently drop missing aliases) so
    # a deleted alias doesn't break startup. Save-path validation
    # (in update_peer_acl) catches the same case earlier and surfaces it.
    alias_lookup = _load_acl_alias_lookup()
    flat = []
    for item in items:
        if isinstance(item, acl_mod.ACLAliasRef):
            body = alias_lookup.get(item.name)
            if body is None:
                # Skip — log somewhere? For now, silent. The peer's
                # iptables chain will be slightly different from what
                # the operator intended, but the WG tunnel still works.
                # The aliases tab UI will flag the broken reference.
                continue
            for entry in body:
                flat.append(acl_mod.ACLEntry(
                    cidr=entry.cidr,
                    port=entry.port,
                    proto=entry.proto,
                    action=item.action,
                    comment=item.comment or entry.comment,
                ))
        else:
            flat.append(item)
    return flat


def _cleanup_orphan_multisite_peers() -> None:
    """Remove any peers row of type='multisite' that no
    federation_links row references via peer_id.

    These rows exist when a federation_links row was deleted (or
    its schema was re-migrated, dropping the row) but the paired
    peer entry was left behind — the kernel keeps using the old
    peer entry until the next replay, the live-peers panel shows
    a peer that doesn't correspond to any link, and the operator
    sees ghost connections.

    Self-healing: every replay drops orphans. Idempotent (a clean
    state is a no-op).

    Also detects multisite peer rows whose address is the same as
    our OWN local overlay address (a peer record for ourselves —
    impossible from a working pairing flow, but operators have
    accidentally pasted their own bundle into their own import-
    complete during development thrash). Drops those too and logs
    loudly so the operator sees what happened.
    """
    conn = get_db().conn
    orphans = conn.execute(
        """SELECT p.id, p.name, p.public_key, p.address
           FROM peers p
           WHERE p.peer_type = 'multisite'
             AND NOT EXISTS (
               SELECT 1 FROM federation_links f
               WHERE f.peer_id = p.id
             )"""
    ).fetchall()

    # Detect self-referencing multisite peers (address overlaps with
    # the wgflow's own local_overlay_addr from any link).
    own_overlays = set()
    for r in conn.execute(
        "SELECT local_overlay_addr FROM federation_links"
    ).fetchall():
        v = (r["local_overlay_addr"] or "").split("/", 1)[0].strip()
        if v:
            own_overlays.add(v)
    self_refs = []
    if own_overlays:
        for r in conn.execute(
            "SELECT id, name, public_key, address FROM peers "
            "WHERE peer_type = 'multisite'"
        ).fetchall():
            addr = (r["address"] or "").split("/", 1)[0].strip()
            if addr in own_overlays:
                self_refs.append(r)

    to_drop = list(orphans) + [r for r in self_refs
                               if r["id"] not in {o["id"] for o in orphans}]
    if not to_drop:
        return

    with get_db().write() as c:
        for row in to_drop:
            kind = ("self-reference" if row in self_refs else "orphan")
            print(
                f"[multisite] cleaning {kind} peer "
                f"id={row['id']} name={row['name']!r} "
                f"address={row['address']} pubkey={(row['public_key'] or '')[:16]}…",
                flush=True,
            )
            c.execute("DELETE FROM peers WHERE id = ?", (row["id"],))
            # Also clear any federation_links.peer_id pointing at the
            # row we just dropped — keeps the link row but it'll
            # display as "no paired peer" until repair (which the
            # operator does by repairing or deleting the link).
            c.execute(
                "UPDATE federation_links SET peer_id = NULL WHERE peer_id = ?",
                (row["id"],),
            )


def _replay_state_to_kernel() -> None:
    """On startup, push the DB state to wg + iptables.

    WireGuard state is volatile across container restarts; iptables chains we
    create are also volatile. We must rebuild both from sqlite.
    """
    ipt.ensure_base_chain()

    # Clean up orphan multisite peers BEFORE we read the peer set
    # for sync — otherwise syncconf would re-install ghosts.
    _cleanup_orphan_multisite_peers()

    peers = _load_all_peers_for_sync()
    wg.syncconf(peers)

    conn = get_db().conn
    rows = conn.execute("SELECT id, address FROM peers WHERE enabled = 1").fetchall()
    for row in rows:
        ipt.create_peer_chain(row["id"], row["address"])
        ipt.apply_peer_acls(row["id"], _load_peer_acls(row["id"]),
                            peer_address=row["address"])

    # MSS clamp (v3.6): the iptables mangle rule isn't part of the per-peer
    # chains so it doesn't get cleared by apply_peer_acls's flush. We sync
    # it explicitly here against the persisted toggle so a container/host
    # restart restores the toggle's last known state.
    mss_row = conn.execute(
        "SELECT value FROM network_settings WHERE key = 'mss_clamp'"
    ).fetchone()
    mss_enabled = (mss_row and mss_row["value"] == "1")
    if mss_enabled:
        ipt.enable_mss_clamp()
    else:
        ipt.disable_mss_clamp()

    # v4.2-rebuild: multisite no longer has a separate wg1 kernel
    # interface. Mgmt peers are regular wg0 peers tagged
    # peer_type='multisite' — they're already accounted for above by
    # the same syncconf/iptables path as client peers (see
    # _load_peers_for_sync). The only kernel-side multisite work
    # left is reconciling wg0's secondary overlay address — wg0
    # gets a 10.99.0.X/32 added alongside its primary address when
    # any multisite link is enabled, removed otherwise.
    multisite_mod.reconcile_overlay_address(conn, interface=SETTINGS.interface)
    # Routes for multisite: `wg syncconf` doesn't install routes for
    # AllowedIPs (only `wg-quick up` does), and we add multisite peers
    # via syncconf after the initial bring-up. Without explicit routes
    # the kernel default-routes overlay packets out eth0 and they never
    # reach the tunnel. Idempotent — see reconcile_routes for details.
    multisite_mod.reconcile_routes(conn, interface=SETTINGS.interface)

    # Re-run the multisite iptables baseline (overlay↔overlay,
    # overlay→tcp/8080) with the live conn so per-link advertised-
    # network ACCEPT rules are installed alongside. Idempotent —
    # _exists check inside the helper short-circuits if already
    # present.
    ipt.ensure_multisite_baseline_rules(conn=conn)

    # v4.1.1: upstream WG client connections. Each enabled row gets
    # its own kernel interface (wg2, wg3, ... — wg1 is reserved for
    # potential future use). Disabled rows have their interface torn
    # down. Errors on a single upstream don't block the others —
    # they're caught inside replay_to_kernel and stamped into the
    # row's last_error column for the UI to show.
    upstream_mod.replay_to_kernel(conn)


def _peer_id_for_ip(peer_ip: str) -> Optional[int]:
    """Used by dns_log.persist to associate logged queries with a peer row.

    `peer_ip` is the bare IP from dnsmasq (e.g. '10.13.13.5'). Our peer
    addresses are stored as '10.13.13.5/32', so we match on prefix.
    """
    if db is None:
        return None
    row = db.conn.execute(
        "SELECT id FROM peers WHERE address LIKE ?", (peer_ip + "/%",)
    ).fetchone()
    return row["id"] if row else None


async def _dns_prune_loop():
    """Background task: prune dns_queries older than 24h, hourly."""
    while True:
        try:
            await asyncio.sleep(3600)
            deleted = await asyncio.to_thread(dns_log.prune, 24 * 3600)
            if deleted:
                print(f"[dns_log] pruned {deleted} rows older than 24h", flush=True)
        except asyncio.CancelledError:
            return
        except Exception as e:
            print(f"[dns_log] prune error: {e!r}", flush=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global db
    auth.init_from_env()

    # Capture uvicorn access logs into our in-memory ring so the access
    # log stream can serve them on demand without a subprocess.
    import logging as _logging
    _access_logger = _logging.getLogger("uvicorn.access")
    _access_logger.addHandler(log_streams.access_log_handler())

    db = DB(SETTINGS.db_path)
    _replay_state_to_kernel()

    # DNS-related subsystems only run when the local resolver is enabled.
    # When WG_LOCAL_DNS=0 we skip dnsmasq entirely, so the override file
    # would never be read and the query log would never see any traffic.
    # The dns_prune_loop also has nothing to prune in that case.
    if SETTINGS.local_dns_enabled:
        try:
            dns_overrides.replay_to_dnsmasq(db.conn)
        except Exception as e:
            print(f"[wgflow] dns_overrides replay failed: {e!r}", flush=True)
        dns_log.start(db, _peer_id_for_ip)
        prune_task = asyncio.get_event_loop().create_task(
            _dns_prune_loop(), name="wgflow-dns-prune"
        )
    else:
        prune_task = None
        print("[wgflow] WG_LOCAL_DNS=0 — DNS query log + overrides disabled",
              flush=True)

    metrics.start(db)

    # Auto-speedtest scheduler — wakes every 60s, checks the configured
    # interval (stored in network_settings), runs a test if due. Skipping
    # the very first cycle so a startup burst doesn't run a speedtest
    # before the operator has had a chance to disable the schedule.
    speedtest_task = asyncio.get_event_loop().create_task(
        _speedtest_scheduler_loop(), name="wgflow-speedtest-sched"
    )

    # Anonymous telemetry. Off-by-default would be more privacy-forward but
    # leaves the project blind; the README is upfront about what's sent and
    # how to disable. The loop has its own internal first-tick delay so
    # operators have time to disable on first boot if they choose.
    if SETTINGS.telemetry_enabled:
        telemetry_task = asyncio.get_event_loop().create_task(
            run_telemetry_loop(db), name="wgflow-telemetry"
        )
        print("[wgflow] telemetry ENABLED — see README#telemetry to opt out",
              flush=True)
    else:
        telemetry_task = None
        print("[wgflow] telemetry DISABLED via WGFLOW_TELEMETRY_ENABLED",
              flush=True)

    try:
        yield
    finally:
        speedtest_task.cancel()
        try:
            await speedtest_task
        except asyncio.CancelledError:
            pass
        if telemetry_task is not None:
            telemetry_task.cancel()
            try:
                await telemetry_task
            except asyncio.CancelledError:
                pass
        if prune_task is not None:
            prune_task.cancel()
            try:
                await prune_task
            except asyncio.CancelledError:
                pass
        if SETTINGS.local_dns_enabled:
            await dns_log.stop()
        await metrics.stop()


async def _speedtest_scheduler_loop() -> None:
    """Background loop that runs an automatic speedtest at the configured
    interval. Reads the interval setting from network_settings each cycle,
    so toggling the schedule via the API takes effect immediately on the
    next loop iteration. Setting the interval to 0 disables auto-tests.

    The interval is in minutes. Minimum effective is 5 minutes — anything
    lower is clamped to prevent running tests in tight loops by accident.
    """
    # Skip the first cycle so a freshly-restarted container doesn't burn
    # bandwidth running a test the operator may not want.
    last_run = time.time()
    try:
        while True:
            await asyncio.sleep(60)
            try:
                conn = get_db().conn
                row = conn.execute(
                    "SELECT value FROM network_settings WHERE key = 'auto_interval_min'"
                ).fetchone()
                interval_min = int(row["value"]) if row else 0
                ep_row = conn.execute(
                    "SELECT value FROM network_settings WHERE key = 'auto_endpoint'"
                ).fetchone()
                auto_endpoint = ep_row["value"] if ep_row else "cloudflare"
                # Validate the persisted endpoint is still in the catalog —
                # if a wgflow upgrade renamed it, fall back to default rather
                # than silently failing every cycle.
                if auto_endpoint not in network_diag.ENDPOINTS:
                    auto_endpoint = "cloudflare"
            except Exception:
                interval_min = 0
                auto_endpoint = "cloudflare"

            if interval_min <= 0:
                last_run = time.time()      # while disabled, anchor to now
                continue
            interval_min = max(interval_min, 5)        # minimum 5 minutes

            now = time.time()
            if (now - last_run) < (interval_min * 60):
                continue

            print(f"[wgflow] auto-speedtest: running endpoint={auto_endpoint} interval={interval_min}m", flush=True)
            try:
                result = await network_diag.run_speedtest(auto_endpoint)
                _persist_speedtest(result)
                last_run = time.time()
            except Exception as e:
                print(f"[wgflow] auto-speedtest failed: {e!r}", flush=True)
                last_run = time.time()
    except asyncio.CancelledError:
        return


def _persist_speedtest(result: dict) -> None:
    """Insert one speedtest row into the DB. Idempotent on (ts) — if two
    runs happen in the same wallclock second, the second is ignored."""
    with get_db().write() as c:
        c.execute(
            """INSERT OR IGNORE INTO speedtest_history
               (ts, ping_ms, jitter_ms, down_mbps, up_mbps, duration_s, error, endpoint)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                int(result["ts"]),
                float(result["ping_ms"]),
                float(result["jitter_ms"]),
                float(result["down_mbps"]),
                float(result["up_mbps"]),
                float(result["duration_s"]),
                result.get("error"),
                result.get("endpoint"),
            ),
        )


app = FastAPI(title="wgflow", lifespan=lifespan)


# ---------------------------------------------------------------------------
# WebSocket counter (v3.6 in-place patch)
# ---------------------------------------------------------------------------
# Tracks how many WebSocket connections are currently open, broken down by
# source ("/ws/status" vs "/ws/logs/<source>"). Surfaced to the UI via the
# /ws/status payload so the live indicator can show a tooltip with the
# count + breakdown.
#
# Threading model: WebSocket handlers all run on the asyncio event loop,
# so we don't need locks here — increments and decrements are atomic from
# the perspective of any single coroutine. A simple dict + int counters
# suffice.
#
# Why this exists at all: diagnosing the v3.5 WS leak required `lsof | grep
# wgflow` from outside the container. Surfacing the count in the UI makes
# leaks visible at a glance — if the operator sees the count growing
# without bound while only one tab is open, that's a regression we can
# react to immediately.

class _WSCounter:
    """Thread-safe-ish (single-loop) WebSocket connection accounting."""

    def __init__(self):
        # Maps source_label → current open connection count. We use
        # a flat dict keyed by string, not a separate counter per
        # endpoint, because new WS endpoints may be added later and
        # we want them to register without code changes elsewhere.
        self._counts: Dict[str, int] = {}

    def increment(self, source: str) -> None:
        self._counts[source] = self._counts.get(source, 0) + 1

    def decrement(self, source: str) -> None:
        if source in self._counts:
            self._counts[source] -= 1
            if self._counts[source] <= 0:
                # Drop zero-count entries so the breakdown stays clean.
                # No use to the operator for "/ws/logs/dnsmasq: 0".
                del self._counts[source]

    def snapshot(self) -> Dict[str, Any]:
        """Returns {'total': int, 'breakdown': {source: count}}."""
        # dict copy so the consumer can't mutate our state by accident.
        return {
            "total": sum(self._counts.values()),
            "breakdown": dict(self._counts),
        }


ws_counter = _WSCounter()


# Auth middleware. Runs on every HTTP request; WebSocket handshakes bypass
# this (Starlette's BaseHTTPMiddleware only intercepts HTTP scope), which
# is what we want — the WS handler does its own cookie check via
# auth.is_authenticated_ws() before accepting the connection.
@app.middleware("http")
async def auth_middleware(request, call_next):
    if not auth.STATE.enabled:
        return await call_next(request)

    path = request.url.path
    # v4.0.1: static assets at the root pass through auth — the icons
    # need to be reachable before login, the manifest needs to be
    # reachable for the browser to enable the install affordance, and
    # /favicon.svg has been there since the earlier patch. We list them
    # explicitly rather than wildcarding because the path namespace at
    # the root is not exclusively static (the panel itself is at /).
    if (path in auth.PUBLIC_PATHS
            or path == "/"
            or path == "/favicon.svg"
            or path == "/apple-touch-icon.png"
            or path == "/icon-192.png"
            or path == "/icon-512.png"
            or path == "/manifest.json"
            or path.startswith("/static/")):
        return await call_next(request)

    # Extract token from cookie or Authorization header.
    token = request.cookies.get(auth.COOKIE_NAME)
    if not token:
        authz = request.headers.get("authorization", "")
        parts = authz.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1].strip()

    if not auth.is_valid_token(token):
        from fastapi.responses import JSONResponse as _JR
        return _JR(
            {"detail": "authentication required"},
            status_code=401,
            headers={"X-WGFlow-Auth": "required"},
        )

    return await call_next(request)


# ---------------------------------------------------------------------------
# Peer CRUD
# ---------------------------------------------------------------------------

def _default_acl() -> List[acl_mod.ACLEntry]:
    return acl_mod.parse_list(SETTINGS.default_acl_raw)


def _resolve_acl(supplied) -> List[acl_mod.ACLEntry]:
    """Turn the optional incoming ACL into a concrete entry list.

    None  => use server default
    []    => empty (peer can reach nothing; rarely what you want, but valid)
    list  => parse each entry
    """
    if supplied is None:
        return _default_acl()
    return [acl_mod.parse_entry(e.raw) for e in supplied]


def _create_peer_row(
    name: str,
    acl_entries: List[acl_mod.ACLEntry],
    dns: Optional[str] = None,
) -> int:
    """Insert a peer + its ACL rows. Does NOT touch the kernel.

    `dns` is the per-peer DNS preference for generated configs:
      - None: inherit server default
      - "":   omit DNS line entirely
      - else: use this DNS value

    Returns the new peer id. Caller is responsible for calling
    `_apply_peer_to_kernel` after committing a batch, to minimise syncconf calls.
    """
    priv = wg.genkey()
    pub = wg.pubkey(priv)
    psk = wg.genpsk()

    database = get_db()
    with database.write() as conn:
        used = [r["address"] for r in conn.execute("SELECT address FROM peers").fetchall()]
        address = wg.next_peer_address(used)
        cur = conn.execute(
            """INSERT INTO peers (name, public_key, private_key, preshared_key, address, dns)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (name, pub, priv, psk, address, dns),
        )
        peer_id = cur.lastrowid
        for e in acl_entries:
            _insert_peer_acl_row(conn, peer_id, e)
    return peer_id


def _insert_peer_acl_row(conn, peer_id: int, entry) -> None:
    """Insert one peer_acls row from an ACLEntry or ACLAliasRef.

    Centralised so the create-peer, update-acl, and import paths all
    use the same shape and don't drift out of sync as the schema
    evolves. Distinguishes the two row variants by entry type:
      - ACLEntry      → cidr/port/proto populated, alias_ref NULL
      - ACLAliasRef   → alias_ref populated, cidr/port/proto NULL
    """
    if isinstance(entry, acl_mod.ACLAliasRef):
        conn.execute(
            "INSERT INTO peer_acls (peer_id, cidr, port, proto, action, comment, alias_ref) "
            "VALUES (?, NULL, NULL, NULL, ?, ?, ?)",
            (peer_id, entry.action, entry.comment or None, entry.name),
        )
    else:
        conn.execute(
            "INSERT INTO peer_acls (peer_id, cidr, port, proto, action, comment, alias_ref) "
            "VALUES (?, ?, ?, ?, ?, ?, NULL)",
            (peer_id, entry.cidr, entry.port, entry.proto,
             entry.action, entry.comment or None),
        )


def _apply_peer_to_kernel(peer_id: int) -> None:
    row = get_db().conn.execute(
        "SELECT address FROM peers WHERE id = ?", (peer_id,)
    ).fetchone()
    ipt.create_peer_chain(peer_id, row["address"])
    ipt.apply_peer_acls(peer_id, _load_peer_acls(peer_id),
                        peer_address=row["address"])


def _sync_wg() -> None:
    wg.syncconf(_load_all_peers_for_sync())


@app.get("/api/peers", response_model=List[PeerOut])
def list_peers():
    """List ALL peers — both client peers and multisite mgmt peers.

    v4.2-rebuild (initial): multisite peers were filtered out so
    they only appeared in the multisite panel.
    Updated: include them, but the frontend distinguishes via
    peer_type and renders multisite peers with a badge + restricted
    affordances (no ACL editor, no downloadable conf, delete refuses
    and redirects to the multisite panel).

    The reasoning for showing them here: operators want a single
    place to see "what's actually connected to my wg0 right now"
    without flipping between two panels for the same kernel state.
    """
    conn = get_db().conn
    rows = conn.execute(
        "SELECT * FROM peers ORDER BY peer_type, id"
    ).fetchall()
    return [_row_to_peer_out(conn, r) for r in rows]


@app.post("/api/peers", response_model=PeerOut, status_code=201)
def create_peer(body: PeerCreate):
    try:
        entries = _resolve_acl(body.acl)
    except acl_mod.ACLParseError as e:
        raise HTTPException(422, str(e))

    # Uniqueness on name; surface a clean error instead of a 500.
    if get_db().conn.execute(
        "SELECT 1 FROM peers WHERE name = ?", (body.name,)
    ).fetchone():
        raise HTTPException(409, f"peer {body.name!r} already exists")

    peer_id = _create_peer_row(body.name, entries, dns=body.dns)
    _apply_peer_to_kernel(peer_id)
    _sync_wg()

    row = get_db().conn.execute("SELECT * FROM peers WHERE id = ?", (peer_id,)).fetchone()
    return _row_to_peer_out(get_db().conn, row)


@app.post("/api/peers/batch/names", response_model=List[PeerOut], status_code=201)
def create_peers_by_names(body: BatchByNames):
    try:
        entries = _resolve_acl(body.acl)
    except acl_mod.ACLParseError as e:
        raise HTTPException(422, str(e))

    # Validate uniqueness up front.
    existing = {
        r["name"]
        for r in get_db().conn.execute(
            f"SELECT name FROM peers WHERE name IN ({','.join('?' * len(body.names))})",
            body.names,
        ).fetchall()
    }
    if existing:
        raise HTTPException(409, f"peers already exist: {sorted(existing)}")

    ids: List[int] = []
    for name in body.names:
        ids.append(_create_peer_row(name, entries, dns=body.dns))

    for pid in ids:
        _apply_peer_to_kernel(pid)
    _sync_wg()

    rows = get_db().conn.execute(
        f"SELECT * FROM peers WHERE id IN ({','.join('?' * len(ids))}) ORDER BY id",
        ids,
    ).fetchall()
    return [_row_to_peer_out(get_db().conn, r) for r in rows]


@app.post("/api/peers/batch/count", response_model=List[PeerOut], status_code=201)
def create_peers_by_count(body: BatchByCount):
    try:
        entries = _resolve_acl(body.acl)
    except acl_mod.ACLParseError as e:
        raise HTTPException(422, str(e))

    # Generate names like "client-0042" starting from the next free number
    # for that prefix so repeated batch runs do not collide.
    conn = get_db().conn
    rows = conn.execute(
        "SELECT name FROM peers WHERE name LIKE ?", (f"{body.prefix}-%",)
    ).fetchall()
    used_nums = set()
    for r in rows:
        suffix = r["name"].split("-")[-1]
        if suffix.isdigit():
            used_nums.add(int(suffix))

    names: List[str] = []
    n = 1
    while len(names) < body.count:
        if n not in used_nums:
            names.append(f"{body.prefix}-{n:04d}")
        n += 1

    ids: List[int] = [_create_peer_row(name, entries, dns=body.dns) for name in names]
    for pid in ids:
        _apply_peer_to_kernel(pid)
    _sync_wg()

    rows = conn.execute(
        f"SELECT * FROM peers WHERE id IN ({','.join('?' * len(ids))}) ORDER BY id",
        ids,
    ).fetchall()
    return [_row_to_peer_out(conn, r) for r in rows]


@app.delete("/api/peers/{peer_id}", status_code=204)
def delete_peer(peer_id: int):
    conn = get_db().conn
    row = conn.execute(
        "SELECT address, peer_type FROM peers WHERE id = ?", (peer_id,)
    ).fetchone()
    if not row:
        raise HTTPException(404, "peer not found")
    # v4.2-rebuild: multisite peers can't be deleted via the live-peers
    # endpoint. They're paired with a federation_links row, and
    # deleting just one half leaves dangling state. The multisite
    # panel's delete flow handles both correctly. Surface the
    # restriction with a clear error so the operator knows where to
    # look.
    if "peer_type" in row.keys() and row["peer_type"] == "multisite":
        raise HTTPException(
            409,
            "this is a multisite peer — delete via the Multisite panel "
            "instead. deleting it from here would leave the paired "
            "federation_links row in an inconsistent state.",
        )

    with get_db().write() as c:
        c.execute("DELETE FROM peers WHERE id = ?", (peer_id,))

    ipt.destroy_peer_chain(peer_id, row["address"])
    _sync_wg()
    return Response(status_code=204)


@app.delete("/api/peers", status_code=200)
def delete_all_peers(confirm: str = ""):
    """Wipe ALL peers from the system.

    Requires `?confirm=DELETE` as a query parameter — a small server-side
    interlock so a casual `curl -X DELETE /api/peers` cannot nuke everything
    by accident. The UI sends this after the user types the word in a
    second-step confirmation dialog.

    What this removes:
      - every peer row (peers + peer_acls cascade)
      - every WGFLOW_PEER_<id> iptables chain + its jump rule
      - every generated .conf file in /data/peers/
      - every dns_queries row associated with these peers (you chose
        "wipe everything" semantics; the metrics_samples table is
        aggregate-only with no per-peer rows so it stays)

    Returns: {"deleted": N}
    """
    if confirm != "DELETE":
        raise HTTPException(
            400,
            "missing or invalid confirmation token. "
            "Pass ?confirm=DELETE to actually delete all peers.",
        )

    conn = get_db().conn
    rows = conn.execute("SELECT id, address, name FROM peers").fetchall()
    if not rows:
        return {"deleted": 0}

    # Tear down kernel state per peer. We do this BEFORE the DB delete so
    # that if iptables fails halfway through, the DB still reflects reality
    # and we can retry. (If the DB delete went first and iptables errored
    # later, we'd have orphan chains pointing at deleted peer IDs.)
    for r in rows:
        try:
            ipt.destroy_peer_chain(r["id"], r["address"])
        except Exception as e:
            print(f"[wgflow] failed to clean iptables for peer {r['id']}: {e!r}",
                  flush=True)

    # Wipe DB rows (peer_acls cascades via FK). Also clear DNS history
    # since the user picked "wipe everything" semantics.
    with get_db().write() as c:
        c.execute("DELETE FROM dns_queries")
        c.execute("DELETE FROM peers")

    # Sync wireguard so the kernel has zero peers.
    _sync_wg()

    # Remove any generated .conf files we may have left around. We don't
    # currently write per-peer files (configs are rendered on demand) but
    # the data dir is the agreed location for them, so clean it just in
    # case operators have manually saved any.
    try:
        for f in SETTINGS.peers_dir.glob("*.conf"):
            f.unlink()
    except Exception as e:
        print(f"[wgflow] cleanup of {SETTINGS.peers_dir} failed: {e!r}", flush=True)

    return {"deleted": len(rows)}


@app.put("/api/peers/{peer_id}/acl", response_model=PeerOut)
def update_peer_acl(peer_id: int, body: ACLUpdate):
    conn = get_db().conn
    row = conn.execute(
        "SELECT peer_type FROM peers WHERE id = ?", (peer_id,)
    ).fetchone()
    if not row:
        raise HTTPException(404, "peer not found")
    # Multisite peers don't have hand-managed ACLs — their reach is
    # controlled by the federation_links advertised-networks fields,
    # edited via the Multisite panel.
    if "peer_type" in row.keys() and row["peer_type"] == "multisite":
        raise HTTPException(
            409,
            "ACLs aren't editable on multisite peers — use the "
            "advertised-networks fields on the multisite link instead.",
        )

    try:
        entries = [acl_mod.parse_entry(e.raw) for e in body.acl]
    except acl_mod.ACLParseError as e:
        raise HTTPException(422, str(e))

    # v3.7: validate that any alias references actually resolve. Doing
    # this at save-time (rather than apply-time) means the operator
    # gets immediate feedback "alias @home_lan doesn't exist" when they
    # type a typo, instead of a silent skip later.
    alias_lookup = _load_acl_alias_lookup(conn)
    for item in entries:
        if isinstance(item, acl_mod.ACLAliasRef):
            if item.name not in alias_lookup:
                raise HTTPException(
                    422,
                    f"alias @{item.name} is not defined; "
                    f"create it on the aliases tab before referencing it",
                )

    with get_db().write() as c:
        c.execute("DELETE FROM peer_acls WHERE peer_id = ?", (peer_id,))
        for e in entries:
            _insert_peer_acl_row(c, peer_id, e)
        # Refresh the alias_refs index for this peer. We delete the
        # whole peer's set first (cheap, scoped) and re-insert from the
        # collected refs in the new ACL list.
        c.execute("DELETE FROM acl_alias_refs WHERE peer_id = ?", (peer_id,))
        for alias_name in acl_mod.collect_alias_refs(entries):
            c.execute(
                "INSERT OR IGNORE INTO acl_alias_refs (alias_name, peer_id) "
                "VALUES (?, ?)",
                (alias_name, peer_id),
            )

    # Expand aliases for the iptables apply call. Pass the flattened
    # ACLEntry list, not the raw heterogeneous parsed list. _load_peer_acls
    # would do the same expansion if we re-loaded; doing it inline saves
    # the round-trip.
    flat_entries = []
    for item in entries:
        if isinstance(item, acl_mod.ACLAliasRef):
            for body_entry in alias_lookup.get(item.name, []):
                flat_entries.append(acl_mod.ACLEntry(
                    cidr=body_entry.cidr,
                    port=body_entry.port,
                    proto=body_entry.proto,
                    action=item.action,
                    comment=item.comment or body_entry.comment,
                ))
        else:
            flat_entries.append(item)

    peer_row = conn.execute("SELECT address FROM peers WHERE id = ?", (peer_id,)).fetchone()
    ipt.apply_peer_acls(peer_id, flat_entries,
                        peer_address=peer_row["address"] if peer_row else "")

    row = conn.execute("SELECT * FROM peers WHERE id = ?", (peer_id,)).fetchone()
    return _row_to_peer_out(conn, row)


@app.put("/api/peers/{peer_id}/enabled", response_model=PeerOut)
def update_peer_enabled(peer_id: int, body: PeerEnabledUpdate):
    """Toggle a peer's enabled state.

    Disabled peers stay in the DB (with their ACLs and config preserved)
    but are excluded from `wg syncconf` so the kernel has no [Peer] block
    for them — they can't connect. Re-enabling reverses this fully.

    iptables chains aren't touched: when the peer is disabled, no traffic
    can reach the chain anyway (kernel doesn't have the source IP
    associated with this peer). When re-enabled, the chain is already
    in place and ACLs apply immediately.
    """
    conn = get_db().conn
    row = conn.execute("SELECT id, enabled FROM peers WHERE id = ?", (peer_id,)).fetchone()
    if not row:
        raise HTTPException(404, "peer not found")

    new_value = 1 if body.enabled else 0
    if int(row["enabled"]) == new_value:
        # No-op — return current state without touching the kernel.
        # Avoids a redundant `wg syncconf` shell-out for a click that
        # didn't change anything.
        full_row = conn.execute("SELECT * FROM peers WHERE id = ?", (peer_id,)).fetchone()
        return _row_to_peer_out(conn, full_row)

    with get_db().write() as c:
        c.execute("UPDATE peers SET enabled = ? WHERE id = ?", (new_value, peer_id))

    # Push the change to the kernel. _sync_wg renders the full server
    # config from `_load_all_peers_for_sync` (which filters by enabled=1)
    # and runs `wg syncconf`. A disabled peer's [Peer] block disappears,
    # killing any active session immediately.
    _sync_wg()

    full_row = conn.execute("SELECT * FROM peers WHERE id = ?", (peer_id,)).fetchone()
    return _row_to_peer_out(conn, full_row)


# ---------------------------------------------------------------------------
# Config downloads
# ---------------------------------------------------------------------------

def _peer_client_conf(
    peer_id: int,
    dns_override: Optional[str] = None,
    dns_override_provided: bool = False,
) -> tuple[str, str]:
    """Return (filename, config text) for a peer.

    DNS resolution priority:
      1. Caller's dns_override (if dns_override_provided=True)
      2. Peer's stored DNS preference (NULL = inherit, "" = disabled, else value)
      3. Server's default peer_dns

    The dns_override_provided flag is necessary because dns_override="" is a
    real value (means "explicitly omit") that differs from None (means "use
    stored peer setting").
    """
    conn = get_db().conn
    row = conn.execute("SELECT * FROM peers WHERE id = ?", (peer_id,)).fetchone()
    if not row:
        raise HTTPException(404, "peer not found")

    # Bare-WG-imported peers have no privkey on the server side — the
    # operator's clients have the keys, and we can't reconstruct a valid
    # client .conf without them. Surface clearly so the UI can render a
    # tooltip explaining why the download button is disabled.
    has_priv = bool(row["has_private_key"]) if "has_private_key" in row.keys() else True
    if not has_priv or not row["private_key"]:
        raise HTTPException(
            422,
            "this peer was imported from a bare-WireGuard source; "
            "wgflow doesn't have the client's private key, so a downloadable "
            "config cannot be generated. The operator's existing client "
            ".conf files continue to work.",
        )

    entries = _load_peer_acls(peer_id)

    # AllowedIPs in the client config controls what the CLIENT routes
    # through the tunnel. Two cases:
    #   - Split-tunnel (allow-only ACL): use the allow-entry CIDRs so
    #     only whitelisted traffic goes through the VPN
    #   - Full-tunnel (any deny entry present): use 0.0.0.0/0 so ALL
    #     traffic goes through the tunnel; the server-side deny rules
    #     then block specific destinations. Without 0.0.0.0/0 on the
    #     client side, traffic to denied destinations would bypass the
    #     tunnel entirely and the deny rules would never fire.
    if acl_mod.has_any_deny(entries):
        allowed = ["0.0.0.0/0"]
    else:
        allowed = [e.cidr for e in entries if not e.is_deny] if entries else ["0.0.0.0/32"]

    # Pick the dns value to render.
    if dns_override_provided:
        effective_dns = dns_override
    else:
        effective_dns = row["dns"] if "dns" in row.keys() else None

    # Pull the global client MTU from network_settings (v3.6). When unset
    # (empty string), render_client_conf omits the MTU line entirely and
    # the client kernel picks its default. The validation of the stored
    # value happens at write time (set_tunnel_settings); we trust whatever
    # got persisted.
    mtu_row = conn.execute(
        "SELECT value FROM network_settings WHERE key = 'client_mtu'"
    ).fetchone()
    mtu_val = mtu_row["value"] if mtu_row else ""

    conf = wg.render_client_conf(
        peer_private_key=row["private_key"],
        peer_preshared_key=row["preshared_key"],
        peer_address=row["address"],
        allowed_ips=allowed,
        dns_override=effective_dns,
        mtu=mtu_val if mtu_val else None,
    )
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in row["name"])
    return f"{safe_name}.conf", conf


@app.get("/api/peers/{peer_id}/config")
def download_peer_config(peer_id: int, dns: Optional[str] = None):
    """Download a peer's .conf.

    Optional `?dns=` query param overrides the stored DNS:
      - omitted entirely → use peer's stored value
      - `?dns=`           → omit DNS line (split-tunnel friendly)
      - `?dns=1.1.1.1`    → use 1.1.1.1
    """
    provided = dns is not None
    filename, text = _peer_client_conf(peer_id, dns_override=dns,
                                        dns_override_provided=provided)
    return Response(
        content=text,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/peers/{peer_id}/qr")
def peer_qr(peer_id: int, dns: Optional[str] = None):
    """QR for a peer's config. Same `?dns=` override semantics as the
    plain config endpoint."""
    provided = dns is not None
    _, text = _peer_client_conf(peer_id, dns_override=dns,
                                 dns_override_provided=provided)
    png = wg.qr_png(text)
    return Response(content=png, media_type="image/png")


@app.get("/api/peers/{peer_id}/install-script")
def peer_install_script(
    peer_id: int,
    dns: Optional[str] = None,
    passphrase: Optional[str] = None,
):
    """Return a Windows installer for this peer as an AES-256 encrypted zip.

    The zip contains a single .ps1 with the WireGuard config embedded as
    base64 — recipient extracts and runs, no .conf needed alongside.

    Optional `?dns=` query param overrides the DNS in the bundled config
    (same semantics as /config endpoint).

    Optional `?passphrase=` (v3.7) lets the operator supply their own
    encryption passphrase instead of the auto-generated Diceware one.
    Server-side validation: minimum 12 characters. The UI is responsible
    for the strength meter; this endpoint just enforces the floor.
    Empty/missing → server generates a Diceware passphrase as before.

    The passphrase (whether generated or operator-supplied) is returned
    in the X-WGFlow-Passphrase response header so the UI can show it.
    Operator communicates the passphrase to the recipient via a separate
    channel (SMS, Signal, in person).

    Recipient extraction note: native Windows zip UI cannot extract AES-
    encrypted entries. Recipients need 7-Zip installed.
    """
    conn = get_db().conn
    row = conn.execute("SELECT name FROM peers WHERE id = ?", (peer_id,)).fetchone()
    if not row:
        raise HTTPException(404, "peer not found")

    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in row["name"])
    provided = dns is not None
    _, conf_text = _peer_client_conf(peer_id, dns_override=dns,
                                      dns_override_provided=provided)

    try:
        ps1_text = installer_script.render_install_script(safe_name, conf_text)
    except ValueError as e:
        raise HTTPException(500, f"could not render installer: {e}")

    # v3.7: passphrase override. If the operator supplied one, validate
    # it; otherwise generate a Diceware one as before. The 12-char floor
    # is a hard bound — anything weaker dramatically reduces the
    # security of the encrypted zip (which is potentially crossing
    # untrusted channels: SMS, email, etc).
    if passphrase is not None and passphrase.strip():
        candidate = passphrase.strip()
        if len(candidate) < 12:
            raise HTTPException(
                422, "passphrase must be at least 12 characters"
            )
        # Cap absurd lengths to prevent abuse — 256 chars is more than
        # any sane password and stops a megabyte-string DoS attempt.
        if len(candidate) > 256:
            raise HTTPException(422, "passphrase too long (max 256)")
        passphrase_value = candidate
    else:
        passphrase_value = installer_script.generate_passphrase()

    zip_bytes, _inner = installer_script.package_install_zip(
        safe_name, ps1_text, passphrase_value,
    )

    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_name}-install.zip"',
            # Surface passphrase to the UI so it can display it to the operator.
            # CORS-wise we're same-origin so exposing this header is fine; if
            # this app were ever served from a different origin from the UI,
            # we'd need Access-Control-Expose-Headers.
            "X-WGFlow-Passphrase": passphrase_value,
        },
    )


# ---------------------------------------------------------------------------
# Server config / defaults
# ---------------------------------------------------------------------------

from pydantic import BaseModel as _BaseModel


class _LoginIn(_BaseModel):
    password: str


@app.get("/api/auth/status")
def auth_status(
    session: Optional[str] = None,
):
    """Tell the UI whether auth is required and whether the caller is logged in.

    The cookie is read by the browser automatically; we don't need to look at
    it here because if the global require_auth dep let the request through,
    the caller is either authenticated OR auth is disabled.
    """
    return {
        "auth_required": auth.STATE.enabled,
        # If we got this far, the caller is authenticated or auth is off.
        "authenticated": True,
    }


@app.post("/api/auth/login")
def auth_login(body: _LoginIn, response: Response):
    """Verify the supplied password, mint a session, set a cookie."""
    if not auth.STATE.enabled:
        # Auth is disabled — no login needed. Tell the client clearly.
        return {"ok": True, "auth_required": False}

    if not auth.verify_password(body.password):
        # Same response shape as success but with ok=false. We deliberately
        # do NOT distinguish "wrong password" from "no password configured"
        # in the error message; that's a small bit of credential hygiene.
        raise HTTPException(401, "invalid password")

    token = auth.issue_token()
    response.set_cookie(
        key=auth.COOKIE_NAME,
        value=token,
        max_age=auth.SESSION_TTL_SECONDS,
        httponly=True,
        samesite="strict",
        # secure=True would be correct in production behind TLS, but the
        # default deployment is loopback-only HTTP, where secure=True would
        # make the cookie unusable. Operators putting a TLS proxy in front
        # should add their own Set-Cookie rewriting if they care.
        secure=False,
        path="/",
    )
    return {"ok": True, "auth_required": True}


from fastapi import Cookie as _Cookie


@app.post("/api/auth/logout")
def auth_logout(
    response: Response,
    session: Optional[str] = _Cookie(default=None, alias=auth.COOKIE_NAME),
):
    """Revoke the current session token and clear the cookie."""
    if session:
        auth.revoke_token(session)
    response.delete_cookie(auth.COOKIE_NAME, path="/")
    return {"ok": True}


def _container_uptime_seconds() -> int:
    """Return container uptime in seconds.

    Reads /proc/1/stat (PID 1's `starttime` in clock ticks since system boot)
    and /proc/uptime (system uptime in seconds), and computes the difference.
    The /proc/1/stat format is tricky because the `comm` field (between
    parens) can itself contain spaces or parens — so we anchor on the LAST
    closing paren and split everything after it.
    """
    try:
        with open("/proc/1/stat") as f:
            data = f.read()
        rparen = data.rfind(")")
        # After "(comm) " comes: state ppid pgrp session tty_nr tpgid flags ...
        # starttime is field 22 of the original line; after dropping the
        # first three (pid, comm, state) it's at index 19 of the post-comm split.
        # But we already split AFTER the paren so state is at index 0 →
        # starttime is at index 19.
        rest_fields = data[rparen + 2:].split()
        starttime_ticks = int(rest_fields[19])

        with open("/proc/uptime") as f:
            system_uptime = float(f.read().split()[0])

        clk_tck = os.sysconf("SC_CLK_TCK")
        return int(system_uptime - (starttime_ticks / clk_tck))
    except Exception:
        return 0


@app.get("/api/server")
def server_info():
    # Report the upstreams dnsmasq is *actually* using by reading the
    # rendered config rather than re-reading the env var. If the entrypoint
    # rejected an entry as malformed, the user will see the discrepancy here.
    dns_upstreams: List[str] = []
    try:
        with open("/etc/dnsmasq.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("server="):
                    dns_upstreams.append(line.split("=", 1)[1])
    except FileNotFoundError:
        pass

    return {
        "interface": SETTINGS.interface,
        "listen_port": SETTINGS.listen_port,
        "subnet": str(SETTINGS.subnet),
        "server_address": str(SETTINGS.server_address),
        "endpoint": SETTINGS.endpoint,
        "peer_dns": SETTINGS.peer_dns,
        "local_dns_enabled": SETTINGS.local_dns_enabled,
        "dns_upstreams": dns_upstreams,
        "default_acl": [str(e) for e in _default_acl()],
        "public_key": wg.server_public_key(),
        "uptime_seconds": _container_uptime_seconds(),
    }


@app.get("/api/db/export")
def db_export():
    """Download the live sqlite database as a binary file.

    We use sqlite's built-in backup API to get a consistent snapshot without
    locking writes or needing to pause the metrics collector. The backup
    stream is written to a temp file first, then served — FastAPI can't stream
    a sqlite backup directly since it needs a destination connection object.
    """
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        # sqlite backup API: consistent snapshot even with concurrent writes.
        src = get_db().conn
        dst = sqlite3.connect(tmp_path)
        try:
            src.backup(dst)
        finally:
            dst.close()

        data = Path(tmp_path).read_bytes()
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": "attachment; filename=\"wgflow.sqlite\""},
    )


@app.post("/api/db/import")
async def db_import(
    file: UploadFile = File(...),
    confirm: str = "",
):
    """Replace the running database with an uploaded sqlite file.

    Guarded by ?confirm=IMPORT so a stray browser request can't trigger it.
    The upload is validated before the swap so a corrupt file can't take down
    the running instance. After the swap, all kernel state (WireGuard peers +
    iptables chains) is rebuilt from the imported DB.

    The metrics collector is paused during the swap to release DB file
    handles. The ~2s metrics gap is acceptable; the collector resumes
    automatically after the swap.
    """
    if confirm != "IMPORT":
        raise HTTPException(400, "must pass ?confirm=IMPORT")

    # Read the upload into memory first. Typical DB is a few MB — even
    # a large one with lots of history is unlikely to exceed ~100 MB, which
    # is well within FastAPI's default body limit.
    data = await file.read()

    # Validate: is this actually a sqlite file?
    if len(data) < 16 or data[:16] != b"SQLite format 3\x00":
        raise HTTPException(422, "uploaded file is not a sqlite database")

    # Write to a temp file so we can open it and inspect the schema.
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name

    try:
        # Validate: does it have at minimum the `peers` and `peer_acls` tables?
        test_conn = sqlite3.connect(tmp_path)
        test_conn.row_factory = sqlite3.Row
        try:
            tables = {r[0] for r in test_conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()}
            required = {"peers", "peer_acls"}
            missing = required - tables
            if missing:
                raise HTTPException(
                    422,
                    f"database is missing required tables: {', '.join(sorted(missing))}. "
                    "This doesn't look like a wgflow database.",
                )
            # Quick sanity: peers table should have the core columns.
            peer_cols = {r[1] for r in test_conn.execute(
                "PRAGMA table_info(peers)"
            ).fetchall()}
            core_cols = {"id", "name", "public_key", "private_key", "preshared_key", "address"}
            missing_cols = core_cols - peer_cols
            if missing_cols:
                raise HTTPException(
                    422,
                    f"peers table is missing columns: {', '.join(sorted(missing_cols))}. "
                    "This may be a database from an incompatible version.",
                )
        finally:
            test_conn.close()

        # Pause the metrics collector — it holds a persistent read connection
        # to the DB and would conflict with overwriting the file.
        await metrics.stop()

        try:
            # Atomic swap: rename is atomic on Linux (same filesystem).
            db_path = str(SETTINGS.db_path)
            # Backup the current DB just in case. Silently skip if it fails
            # (disk full, permissions) — we still proceed.
            backup_path = db_path + ".pre-import.bak"
            try:
                shutil.copy2(db_path, backup_path)
            except OSError:
                pass

            shutil.move(tmp_path, db_path)
            tmp_path = None           # mark as consumed so finally doesn't delete it

            # Re-open the DB layer with the new file. This reinitialises the
            # global db instance and runs migrations so older-version imports
            # get the new columns they might be missing.
            global db
            db = DB(SETTINGS.db_path)

            # Rebuild kernel state from the imported DB. This is the same
            # logic that runs on container startup.
            _replay_state_to_kernel()

            # Restart the metrics collector against the new DB.
            metrics.start(db)

        except Exception:
            # If anything went wrong during the swap, try to restart metrics
            # with whatever DB state we're in so the app stays alive.
            try:
                metrics.start(db)
            except Exception:
                pass
            raise

    finally:
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    return {"ok": True, "message": "database replaced and kernel state rebuilt"}


# ---------------------------------------------------------------------------
# Migration importer (wg-easy / PiVPN / bare WireGuard)
# ---------------------------------------------------------------------------
# Three-step flow:
#   1. POST /api/import/upload  — multipart upload; parse + stash + return
#                                 a preview_id and a JSON summary
#   2. GET  /api/import/preview/{id} — re-fetch the preview (UI reload)
#   3. POST /api/import/commit  — apply the chosen peers to the DB
#
# Previews live in process memory with a 10-min TTL — see
# importers/preview_store.py. Restart loses pending previews; operators
# re-upload, which takes seconds.

# Cap on upload size. Real wg-easy/PiVPN dumps are kilobytes; the cap is
# defense against someone uploading a 4 GB tar to OOM the worker.
_IMPORT_MAX_BYTES = 8 * 1024 * 1024  # 8 MiB

# Magic confirmation string for /api/import/commit. The UI requires the
# operator to type this so the commit can't be triggered accidentally
# (e.g. by a browser refresh re-submitting the form). Mirrors the existing
# /api/db/import ?confirm=IMPORT pattern.
_IMPORT_CONFIRM_TOKEN = "IMPORT"


def _migration_enabled() -> bool:
    """Read the migration toggle from network_settings.

    The seed value comes from WGFLOW_MIGRATION_DEFAULT_ENABLED on first
    install (handled in db.py during _migrate). After that, runtime UI
    toggles are authoritative — this helper is the single source of
    truth, called by every import endpoint guard and by the UI's
    /api/server/migration GET.

    Defensive: if the row is missing for some reason (corrupted DB,
    manual deletion, migration didn't run), default to True. We'd rather
    fail-open here than have an operator wonder why the migrate tab
    disappeared, since the feature is admin-gated already.
    """
    row = get_db().conn.execute(
        "SELECT value FROM network_settings WHERE key = 'migration_enabled'"
    ).fetchone()
    if row is None:
        return True
    return row["value"] in ("1", "true", "yes", "on")


def _require_migration_enabled() -> None:
    """Guard called at the top of each import endpoint.

    Raises HTTPException(403) when migration is disabled, with a message
    that matches what the UI expects. Centralized so all three endpoints
    surface the same error shape.
    """
    if not _migration_enabled():
        raise HTTPException(
            403,
            "migration is disabled. enable it from server settings before importing.",
        )


@app.post("/api/import/upload")
async def import_upload(file: UploadFile = File(...)):
    """Accept a wg-easy/PiVPN/bare-WG file, parse it, stash a preview.

    Auto-detects the format. Returns a preview_id plus the parsed summary
    for the UI to render the per-peer list with status badges. The UI
    then calls /api/import/commit with the preview_id and the operator's
    accept/skip choices.
    """
    _require_migration_enabled()
    content = await file.read(_IMPORT_MAX_BYTES + 1)
    if len(content) > _IMPORT_MAX_BYTES:
        raise HTTPException(
            413,
            f"upload exceeds {_IMPORT_MAX_BYTES // (1024*1024)} MiB cap",
        )
    try:
        parsed = importer_detector.detect_and_parse(content)
    except ValueError as e:
        # Unrecognised format or parse failure. The detector messages are
        # specific enough to be operator-actionable; surface them as-is.
        raise HTTPException(422, str(e))

    # Annotate per-peer statuses against current wgflow state.
    server_addr = None
    try:
        server_addr = SETTINGS.server_address.ip
    except (AttributeError, ValueError):
        pass
    importer_commit.compute_statuses(
        parsed,
        get_db().conn,
        SETTINGS.subnet,
        server_address=server_addr,
    )

    preview_id = importer_store.store(parsed)
    return importer_serialize.serialize_preview(parsed, preview_id)


@app.get("/api/import/preview/{preview_id}")
def import_preview(preview_id: str):
    """Re-fetch a stashed preview. Useful if the operator reloads the
    page mid-review — the UI calls this on mount instead of having to
    re-upload.

    Refreshes statuses against current DB state so a peer that was
    'name-conflict' at upload time but had its conflicting peer deleted
    in the meantime now reads as 'ok'.
    """
    _require_migration_enabled()
    parsed = importer_store.get(preview_id)
    if parsed is None:
        raise HTTPException(404, "preview expired or not found")
    server_addr = None
    try:
        server_addr = SETTINGS.server_address.ip
    except (AttributeError, ValueError):
        pass
    importer_commit.compute_statuses(
        parsed,
        get_db().conn,
        SETTINGS.subnet,
        server_address=server_addr,
    )
    return importer_serialize.serialize_preview(parsed, preview_id)


@app.post("/api/import/commit")
def import_commit_endpoint(body: ImportCommit):
    """Apply the operator's choices from the preview to the wgflow DB.

    The body is small (preview_id + indices + flags); the actual peer
    data lives in the in-memory store and never re-touches the wire.

    Possible failure modes the UI handles:
      - migration disabled            → 403
      - confirm_token wrong          → 422
      - preview_id missing/expired   → 404 (operator re-uploads)
      - adopt_server_keypair=True
        but no source keypair        → 422
      - inserts that fail uniqueness → 500 (rolled back; operator
                                       re-checks the preview which now
                                       shows updated statuses)
    """
    _require_migration_enabled()
    if body.confirm_token != _IMPORT_CONFIRM_TOKEN:
        raise HTTPException(
            422,
            f"confirm_token must be exactly {_IMPORT_CONFIRM_TOKEN!r}",
        )

    parsed = importer_store.get(body.preview_id)
    if parsed is None:
        raise HTTPException(
            404, "preview expired or not found — please re-upload"
        )

    if body.adopt_server_keypair and parsed.server_keypair is None:
        raise HTTPException(
            422,
            "this source did not include a server keypair; cannot adopt",
        )

    try:
        result = importer_commit.apply(
            parsed=parsed,
            accepted_indices=list(body.accepted_indices),
            adopt_server_keypair=body.adopt_server_keypair,
            db=get_db(),
            server_private_key_path=SETTINGS.server_private_key_path,
            server_public_key_path=SETTINGS.server_public_key_path,
            default_acl=_default_acl(),
            create_peer_chain=ipt.create_peer_chain,
            apply_peer_acls=ipt.apply_peer_acls,
            sync_wg=_sync_wg,
            load_peer_acls=_load_peer_acls,
        )
    except sqlite3.IntegrityError as e:
        # Most likely a uniqueness violation we missed in the status
        # check — e.g. operator added a conflicting peer in another tab
        # between preview and commit. The transaction rolled back; the
        # preview's status will show the new conflict on next refresh.
        raise HTTPException(
            409,
            f"commit failed due to a conflict: {e}. Refresh the preview "
            "and check for new statuses.",
        )

    # Drop the preview only on success — failed commits can be retried
    # against the same preview after the operator fixes their selection.
    importer_store.drop(body.preview_id)

    return {
        "ok": True,
        "imported": result.imported,
        "skipped_conflict": result.skipped_conflict,
        "skipped_invalid": result.skipped_invalid,
        "server_keypair_adopted": result.server_keypair_adopted,
        "new_server_pubkey": result.new_server_pubkey,
    }


@app.get("/api/server/migration")
def get_migration_state():
    """Return the current migration toggle state.

    UI calls this on page load to decide whether to show the migrate
    tab, and on the server tab to render the toggle's current value.
    """
    return {"enabled": _migration_enabled()}


@app.put("/api/server/migration")
def set_migration_state(body: MigrationToggle):
    """Flip the migration toggle.

    Persists to network_settings so the choice survives container
    restarts. No confirm-token because (a) the action is reversible by
    flipping back, and (b) a misclick that disables the importer is
    annoying-but-recoverable, not data-destructive.

    Returns the new state so the UI can sync without a second round-trip.
    """
    new_value = "1" if body.enabled else "0"
    with get_db().write() as conn:
        # UPSERT pattern: INSERT … ON CONFLICT … UPDATE keeps a single
        # source of truth row whether or not it pre-existed (it should,
        # since db._migrate seeds it on first install — but defensive).
        conn.execute(
            """INSERT INTO network_settings (key, value) VALUES ('migration_enabled', ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
            (new_value,),
        )
    return {"enabled": body.enabled}


# Ten phosphor-CRT-inspired palettes shipped with wgflow. The UI's CSS has a
# matching `[data-instance-theme="<name>"]` block for each. Server-side
# we just gate writes against this allow-list so a malformed PUT can't
# poison the DB with an unknown theme name. Five originals (3.5) plus
# five additions (3.5 update): lime, pink, purple, gold, mint.
_VALID_THEMES = (
    "phosphor", "amber", "cyan", "magenta", "ice",
    "lime", "pink", "purple", "gold", "mint",
)

# Instance name length cap. Long enough for "home-server-prod-eu-west"
# style names; short enough to keep the header visually balanced.
_INSTANCE_NAME_MAX_LEN = 40


@app.get("/api/server/instance")
def get_instance_config():
    """Return the instance display config (name + color theme).

    Called by the UI on page load to render the header chrome and apply
    the theme attribute. Both fields always present in the response;
    missing rows in network_settings (shouldn't happen post-migration,
    but defensive) come back as ("", "phosphor").
    """
    conn = get_db().conn
    rows = {
        r["key"]: r["value"]
        for r in conn.execute(
            "SELECT key, value FROM network_settings "
            "WHERE key IN ('instance_name', 'instance_color_theme')"
        ).fetchall()
    }
    name = rows.get("instance_name", "")
    theme = rows.get("instance_color_theme", "phosphor")
    # If somehow a stale theme name is in the DB (downgrade from a future
    # version, manual sqlite edit), fall back to the default rather than
    # serving a value the UI can't render.
    if theme not in _VALID_THEMES:
        theme = "phosphor"
    return {"name": name, "color_theme": theme}


@app.put("/api/server/instance")
def set_instance_config(body: InstanceConfig):
    """Update the instance name and/or color theme.

    Both body fields are optional — sending only `name` leaves the theme
    alone, and vice versa. Empty string is a valid `name` (means "no
    name shown in the header chrome"). Theme must be one of the
    server-side allow-list; an unknown value rejects with 422.

    Persists to network_settings via UPSERT.
    """
    updates = []  # list of (key, value) tuples to upsert in one transaction

    if body.name is not None:
        # Trim and length-cap. We don't HTML-escape here — the UI is
        # responsible for escaping at render time (escapeHtml in the
        # frontend). Server-side restriction is just length + control-char.
        name = body.name.strip()
        if len(name) > _INSTANCE_NAME_MAX_LEN:
            raise HTTPException(
                422,
                f"name too long (max {_INSTANCE_NAME_MAX_LEN} chars)",
            )
        # Reject control characters that would make the header rendering
        # weird or could be used to inject ANSI escapes if the value
        # leaked into terminal logs. Tabs, newlines, NULs, etc.
        if any(ord(c) < 0x20 for c in name):
            raise HTTPException(422, "name contains control characters")
        updates.append(("instance_name", name))

    if body.color_theme is not None:
        if body.color_theme not in _VALID_THEMES:
            raise HTTPException(
                422,
                f"unknown theme '{body.color_theme}'; valid: {', '.join(_VALID_THEMES)}",
            )
        updates.append(("instance_color_theme", body.color_theme))

    if not updates:
        # Both fields omitted — return current state without writing.
        return get_instance_config()

    with get_db().write() as conn:
        for key, value in updates:
            conn.execute(
                """INSERT INTO network_settings (key, value) VALUES (?, ?)
                   ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
                (key, value),
            )

    # Echo the resulting full state for the UI's optimistic-update flow.
    return get_instance_config()


# ---------------------------------------------------------------------------
# Tunnel settings (v3.6) — client MTU + MSS clamping
# ---------------------------------------------------------------------------
# Both knobs are about working around path-MTU mismatches:
#   client_mtu  – sets the MTU on the peer's [Interface], baked into
#                 generated .conf files. No iptables effect.
#   mss_clamp   – installs an iptables mangle rule that rewrites TCP SYN
#                 MSS values, fixing TCP black-hole on broken-PMTUD paths.
#
# Persisted to network_settings; mss_clamp also applies to running iptables
# state immediately on save.

# Client MTU bounds. WireGuard's own minimum is 576 (smallest IP packet
# that doesn't fragment); 1500 is the Ethernet ceiling. Values outside
# this range are almost always misconfigurations.
_MTU_MIN = 576
_MTU_MAX = 1500


@app.get("/api/server/tunnel")
def get_tunnel_settings():
    """Read client_mtu + mss_clamp.

    Returns:
      {"client_mtu": "1412" | "", "mss_clamp": bool}
    """
    conn = get_db().conn
    rows = {
        r["key"]: r["value"]
        for r in conn.execute(
            "SELECT key, value FROM network_settings "
            "WHERE key IN ('client_mtu', 'mss_clamp')"
        ).fetchall()
    }
    return {
        "client_mtu": rows.get("client_mtu", ""),
        "mss_clamp": rows.get("mss_clamp", "0") == "1",
    }


@app.put("/api/server/tunnel")
def set_tunnel_settings(body: TunnelSettings):
    """Update client_mtu and/or mss_clamp.

    Both fields optional — sending only one leaves the other alone.
    MTU is validated against [_MTU_MIN, _MTU_MAX]; out-of-range is a 422.
    Empty string clears the override.

    On mss_clamp change, the iptables rule is installed/removed
    immediately so the operator gets feedback right away.
    """
    updates = []
    apply_mss = None  # None = no change; True = enable; False = disable

    if body.client_mtu is not None:
        v = body.client_mtu.strip()
        if v != "":
            try:
                n = int(v)
            except ValueError:
                raise HTTPException(422, f"MTU must be an integer or empty, got {v!r}")
            if not (_MTU_MIN <= n <= _MTU_MAX):
                raise HTTPException(
                    422,
                    f"MTU must be between {_MTU_MIN} and {_MTU_MAX}, got {n}",
                )
            v = str(n)  # canonicalize
        updates.append(("client_mtu", v))

    if body.mss_clamp is not None:
        updates.append(("mss_clamp", "1" if body.mss_clamp else "0"))
        apply_mss = body.mss_clamp

    if not updates:
        return get_tunnel_settings()

    with get_db().write() as conn:
        for key, value in updates:
            conn.execute(
                """INSERT INTO network_settings (key, value) VALUES (?, ?)
                   ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
                (key, value),
            )

    # Apply the MSS clamp toggle to live iptables state. We do this AFTER
    # the DB write so a failure to install the rule (rare; iptables is
    # very reliable) doesn't leave the persisted state and kernel state
    # diverged on retry — _replay_state_to_kernel will re-apply on restart.
    if apply_mss is True:
        ipt.enable_mss_clamp()
    elif apply_mss is False:
        ipt.disable_mss_clamp()

    return get_tunnel_settings()


# Helper: which DB key to use for layout, based on form factor.
# v3.8: separates desktop (default, backwards-compat) from mobile.
def _panel_order_key(form: Optional[str]) -> str:
    """Map a form-factor query param to the network_settings key.

    'desktop' (default, or any unrecognised value) → 'panel_order'
    'mobile'                                        → 'panel_order_mobile'

    The default-to-desktop choice is deliberate: a v3.7 client that
    doesn't pass the form param continues to work against v3.8, hitting
    the same row it always did. New v3.8 clients explicitly pass
    'desktop' or 'mobile' so each form factor reads/writes its own slot.
    """
    return "panel_order_mobile" if form == "mobile" else "panel_order"


def _panels_minimized_key(form: Optional[str]) -> str:
    return "panels_minimized_mobile" if form == "mobile" else "panels_minimized"


@app.get("/api/server/panel-order")
def get_panel_order(form: Optional[str] = None):
    """Read panel order. Empty list = default UI order.

    Returns: {"order": ["panel-id-1", "panel-id-2", ...]}

    Optional `?form=mobile` selects the mobile layout. Default
    (no param or `desktop`) returns the legacy `panel_order` key.
    """
    key = _panel_order_key(form)
    conn = get_db().conn
    row = conn.execute(
        "SELECT value FROM network_settings WHERE key = ?", (key,)
    ).fetchone()
    raw = row["value"] if row else ""
    if not raw:
        return {"order": [], "form": form or "desktop"}
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return {"order": [str(x) for x in parsed], "form": form or "desktop"}
    except (json.JSONDecodeError, TypeError, ValueError):
        pass
    return {"order": [], "form": form or "desktop"}


@app.put("/api/server/panel-order")
def set_panel_order(body: PanelOrder, form: Optional[str] = None):
    """Persist panel order (drag-to-reorder result).

    Optional `?form=mobile` writes to the mobile-specific slot.
    Default (no param or `desktop`) writes to the legacy slot.
    """
    if len(body.order) > 32:
        raise HTTPException(422, "too many panel ids (max 32)")
    for pid in body.order:
        if not isinstance(pid, str) or len(pid) > 64:
            raise HTTPException(422, "panel ids must be strings ≤ 64 chars")

    key = _panel_order_key(form)
    serialized = json.dumps(body.order)
    with get_db().write() as conn:
        conn.execute(
            """INSERT INTO network_settings (key, value) VALUES (?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
            (key, serialized),
        )
    return get_panel_order(form=form)


# ---------------------------------------------------------------------------
# Panels minimized state (v3.6 in-place patch)
# ---------------------------------------------------------------------------
# Maps panel-id → bool. true = collapsed to header, false/missing = expanded.
# Persists per-instance in network_settings.panels_minimized as JSON.
# Same forward-compat policy as panel_order: unknown ids are ignored at
# render time so old clients don't break when seeing new panel-ids.

@app.get("/api/server/panels-minimized")
def get_panels_minimized(form: Optional[str] = None):
    """Read minimized state. Optional `?form=mobile` for mobile slot."""
    key = _panels_minimized_key(form)
    conn = get_db().conn
    row = conn.execute(
        "SELECT value FROM network_settings WHERE key = ?", (key,)
    ).fetchone()
    raw = row["value"] if row else ""
    if not raw:
        return {"minimized": {}, "form": form or "desktop"}
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return {
                "minimized": {
                    str(k): bool(v) for k, v in parsed.items()
                    if isinstance(k, str)
                },
                "form": form or "desktop",
            }
    except (json.JSONDecodeError, TypeError, ValueError):
        pass
    return {"minimized": {}, "form": form or "desktop"}


@app.put("/api/server/panels-minimized")
def set_panels_minimized(body: dict, form: Optional[str] = None):
    """Persist minimized state. Optional `?form=mobile` for mobile slot."""
    minimized = body.get("minimized")
    if not isinstance(minimized, dict):
        raise HTTPException(422, "body must be {'minimized': {panel-id: bool}}")
    if len(minimized) > 32:
        raise HTTPException(422, "too many entries (max 32)")
    cleaned = {}
    for k, v in minimized.items():
        if not isinstance(k, str) or len(k) > 64:
            raise HTTPException(422, "panel ids must be strings ≤ 64 chars")
        cleaned[k] = bool(v)

    key = _panels_minimized_key(form)
    serialized = json.dumps(cleaned) if cleaned else ""
    with get_db().write() as conn:
        conn.execute(
            """INSERT INTO network_settings (key, value) VALUES (?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
            (key, serialized),
        )
    return get_panels_minimized(form=form)


# ---------------------------------------------------------------------------
# Polling interval config (v3.6 in-place patch)
# ---------------------------------------------------------------------------
# Single global value used by all the polling-based panels (ACL stats,
# DNS recent, iptables modal). Lower = more responsive but more network
# + iptables exec overhead. Higher = less load but slower to see new data.
# Range 1000..6000 ms enforced; 3000 default.

_POLL_MIN_MS = 1000
_POLL_MAX_MS = 6000


@app.get("/api/server/polling")
def get_polling_interval():
    """Read polling interval (ms). Always returns a valid integer in
    range; pre-3.6 DBs and corrupted values fall back to 3000."""
    conn = get_db().conn
    row = conn.execute(
        "SELECT value FROM network_settings WHERE key = 'polling_interval_ms'"
    ).fetchone()
    raw = (row["value"] if row else "") or "3000"
    try:
        val = int(raw)
    except (TypeError, ValueError):
        val = 3000
    if not (_POLL_MIN_MS <= val <= _POLL_MAX_MS):
        val = 3000
    return {"interval_ms": val}


@app.put("/api/server/polling")
def set_polling_interval(body: dict):
    """Update polling interval.

    Body: {"interval_ms": int}. Out-of-range → 422.
    """
    val = body.get("interval_ms")
    try:
        val = int(val)
    except (TypeError, ValueError):
        raise HTTPException(422, "interval_ms must be an integer")
    if not (_POLL_MIN_MS <= val <= _POLL_MAX_MS):
        raise HTTPException(
            422, f"interval_ms must be {_POLL_MIN_MS}..{_POLL_MAX_MS}, got {val}"
        )
    with get_db().write() as conn:
        conn.execute(
            """INSERT INTO network_settings (key, value) VALUES ('polling_interval_ms', ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
            (str(val),),
        )
    return {"interval_ms": val}


# ---------------------------------------------------------------------------
# Clipboard timeout (v3.7)
# ---------------------------------------------------------------------------
# How long the UI waits before overwriting the clipboard after a sensitive
# value is copied. 0 = disabled (just warn, don't overwrite). 1..300 sec
# range enforced. Best-effort on the UI side — browsers may reject
# clipboard writes outside of user gestures.

_CLIPBOARD_MIN_SEC = 0
_CLIPBOARD_MAX_SEC = 300


@app.get("/api/server/clipboard")
def get_clipboard_config():
    conn = get_db().conn
    row = conn.execute(
        "SELECT value FROM network_settings WHERE key = 'clipboard_timeout_sec'"
    ).fetchone()
    raw = (row["value"] if row else "") or "30"
    try:
        val = int(raw)
    except (TypeError, ValueError):
        val = 30
    if not (_CLIPBOARD_MIN_SEC <= val <= _CLIPBOARD_MAX_SEC):
        val = 30
    return {"timeout_sec": val}


@app.put("/api/server/clipboard")
def set_clipboard_config(body: dict):
    val = body.get("timeout_sec")
    try:
        val = int(val)
    except (TypeError, ValueError):
        raise HTTPException(422, "timeout_sec must be an integer")
    if not (_CLIPBOARD_MIN_SEC <= val <= _CLIPBOARD_MAX_SEC):
        raise HTTPException(
            422,
            f"timeout_sec must be {_CLIPBOARD_MIN_SEC}..{_CLIPBOARD_MAX_SEC}",
        )
    with get_db().write() as conn:
        conn.execute(
            """INSERT INTO network_settings (key, value)
               VALUES ('clipboard_timeout_sec', ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
            (str(val),),
        )
    return {"timeout_sec": val}


# ---------------------------------------------------------------------------
# Private key reveal (v3.7)
# ---------------------------------------------------------------------------
# Returns the raw private key for a peer. Separate endpoint from the full
# config so:
#   1. The UI can guard reveal behind a confirmation/warning specifically
#      about the key (rather than the broader config view).
#   2. Audit logging (future) can distinguish "viewed full config" from
#      "viewed bare private key" — different sensitivity.
#
# Auth: same session check as everything else. No extra confirmation
# step on the server side — the UI is responsible for the warning.
# Reasoning: confirmations on the server would require a multi-step
# flow (issue token, then redeem) that doesn't add real security
# against an authenticated session. The warning is for the operator's
# benefit, not adversarial.

@app.get("/api/peers/{peer_id}/private-key")
def peer_private_key(peer_id: int):
    """Return the bare private key for one peer.

    Response shape: {"private_key": "..."} or 404 / 410.
    Returns 410 (gone) if the peer was imported without a private key
    (has_private_key = 0) — cleaner than 404 so the UI can distinguish.
    """
    conn = get_db().conn
    row = conn.execute(
        "SELECT private_key, has_private_key FROM peers WHERE id = ?",
        (peer_id,),
    ).fetchone()
    if not row:
        raise HTTPException(404, "peer not found")
    has_pk = row["has_private_key"] if "has_private_key" in row.keys() else 1
    if not has_pk or not row["private_key"]:
        raise HTTPException(410, "private key not stored for this peer")
    return {"private_key": row["private_key"]}


# ---------------------------------------------------------------------------
# Live status
# ---------------------------------------------------------------------------

def _build_live_snapshot() -> List[PeerLive]:
    """Join the sqlite peer list with the latest metrics snapshot.

    We no longer shell out to `wg show` here; the collector does that once
    per second and caches the result, so this is a pure in-memory read.
    """
    conn = get_db().conn
    rows = conn.execute("SELECT id, name, address, public_key FROM peers").fetchall()
    snap = metrics.latest
    peers_dump = snap.peers if snap else {}
    now = int(time.time())
    out: List[PeerLive] = []
    for r in rows:
        pm = peers_dump.get(r["public_key"])
        handshake = pm.latest_handshake if pm else 0
        online = handshake > 0 and (now - handshake) < 180
        out.append(PeerLive(
            id=r["id"],
            name=r["name"],
            address=r["address"],
            public_key=r["public_key"],
            endpoint=pm.endpoint if pm else None,
            latest_handshake=handshake,
            rx_bytes=pm.rx_bytes if pm else 0,
            tx_bytes=pm.tx_bytes if pm else 0,
            online=online,
        ))
    return out


@app.get("/api/status", response_model=List[PeerLive])
def status():
    return _build_live_snapshot()


@app.get("/api/metrics/live")
def metrics_live():
    """Live (5-min) throughput ring + latest host vitals.

    Used by the UI to bootstrap the global chart before the first WS tick
    arrives. The WS stream delivers the same data as it evolves.
    """
    snap = metrics.latest
    return {
        "throughput": metrics.live_throughput(),
        "host": _host_dict(snap.host) if snap else None,
    }


@app.get("/api/metrics/history")
def metrics_history(window: str = "1h"):
    """Historical throughput from sqlite. Window: 1h, 6h, 24h."""
    seconds = {"1h": 3600, "6h": 6 * 3600, "24h": 24 * 3600}.get(window)
    if seconds is None:
        raise HTTPException(400, "window must be one of: 1h, 6h, 24h")
    return metrics.history(seconds)


@app.get("/api/metrics/peer/{peer_id}/sparkline")
def peer_sparkline(peer_id: int):
    """Last-60s rx/tx sparkline for a single peer."""
    conn = get_db().conn
    row = conn.execute(
        "SELECT public_key FROM peers WHERE id = ?", (peer_id,)
    ).fetchone()
    if not row:
        raise HTTPException(404, "peer not found")
    return metrics.peer_sparkline(row["public_key"])


@app.get("/api/metrics/cumulative")
def metrics_cumulative():
    """Persistent rx/tx totals that survive container restarts.

    Returns:
        {
          "rx_bytes": int,    # total since last clear (offset-adjusted)
          "tx_bytes": int,
          "since": int,       # last update unix ts (proxy for "currentness")
        }
    """
    return metrics.cumulative()


@app.post("/api/metrics/cumulative/reset")
def metrics_cumulative_reset(confirm: str = ""):
    """Zero the visible cumulative counters. Guarded by ?confirm=RESET so a
    misrouted request can't wipe accumulated stats by accident.

    Implementation note: the underlying total isn't deleted — we just set
    the offset equal to it, so the visible value reads zero. This keeps the
    delta-tracking machinery intact for future ticks.
    """
    if confirm != "RESET":
        raise HTTPException(400, "must pass ?confirm=RESET to zero counters")
    metrics.reset_cumulative()
    return {"ok": True}


def _host_dict(h) -> dict:
    return {
        "cpu_pct": h.cpu_pct,
        "mem_pct": h.mem_pct,
        "mem_used_bytes": h.mem_used_bytes,
        "mem_total_bytes": h.mem_total_bytes,
        "load1": h.load1, "load5": h.load5, "load15": h.load15,
        "if_rx_bytes": h.if_rx_bytes, "if_tx_bytes": h.if_tx_bytes,
        "if_rx_packets": h.if_rx_packets, "if_tx_packets": h.if_tx_packets,
        "if_rx_errors": h.if_rx_errors, "if_tx_errors": h.if_tx_errors,
        "if_rx_drops": h.if_rx_drops, "if_tx_drops": h.if_tx_drops,
    }


def _acl_hits_by_key(peer_id: int) -> dict:
    """Return a {(cidr, port, proto) -> (pkts, bytes)} map for one peer."""
    snap = metrics.latest
    if not snap:
        return {}
    hits = snap.acl_hits.get(peer_id, [])
    return {(h.cidr, h.port, h.proto): (h.pkts, h.bytes) for h in hits}


@app.get("/api/peers/{peer_id}/acl-hits")
def peer_acl_hits(peer_id: int):
    """Per-rule packet+byte counters for this peer's ACL chain."""
    conn = get_db().conn
    if not conn.execute("SELECT 1 FROM peers WHERE id = ?", (peer_id,)).fetchone():
        raise HTTPException(404, "peer not found")
    snap = metrics.latest
    hits = snap.acl_hits.get(peer_id, []) if snap else []
    return [
        {"cidr": h.cidr, "port": h.port, "proto": h.proto,
         "pkts": h.pkts, "bytes": h.bytes}
        for h in hits
    ]


# ---------------------------------------------------------------------------
# ACL aliases (v3.7) — named groups of CIDRs the operator can reference
# from peer ACLs as `@name`. CRUD endpoints + ref counting.
# ---------------------------------------------------------------------------

# Validate alias names: lowercase letters, digits, underscores; 1-32
# chars. Same rule as the parser regex; duplicated here for fast
# server-side rejection without parser invocation.
import re as _re
_ALIAS_NAME_RE = _re.compile(r"^[a-z0-9_]{1,32}$")


@app.get("/api/acl-aliases")
def list_acl_aliases():
    """Return all aliases with their bodies + reference counts.

    Response shape:
      [
        {
          "name": "home_lan",
          "description": "main home network",
          "body": [{"cidr": "192.168.0.0/16", "port": null, "proto": null}, ...],
          "ref_count": 3,         # how many peers reference this alias
          "ref_peer_ids": [3, 5, 12],
        },
        ...
      ]
    """
    conn = get_db().conn
    aliases = conn.execute(
        "SELECT name, body, description FROM acl_aliases ORDER BY name"
    ).fetchall()
    out = []
    for a in aliases:
        try:
            body_list = json.loads(a["body"])
        except (json.JSONDecodeError, TypeError):
            body_list = []
        ref_rows = conn.execute(
            "SELECT peer_id FROM acl_alias_refs WHERE alias_name = ? ORDER BY peer_id",
            (a["name"],),
        ).fetchall()
        ref_peer_ids = [r["peer_id"] for r in ref_rows]
        out.append({
            "name": a["name"],
            "description": a["description"] or "",
            "body": body_list,
            "ref_count": len(ref_peer_ids),
            "ref_peer_ids": ref_peer_ids,
        })
    return out


def _validate_alias_body(raw_body: str) -> List[acl_mod.ACLEntry]:
    """Parse + validate an alias body string. Returns list of ACLEntry.

    Body format is the same comma-separated ACL syntax as a peer's ACL,
    but with two extra constraints:
      - No deny entries (`!` prefix forbidden — aliases are allow-only;
        deny semantics live on the alias usage)
      - No nested aliases (`@other_name` forbidden — flat aliases only)

    Raises HTTPException(422) on any violation.
    """
    try:
        items = acl_mod.parse_list(raw_body)
    except acl_mod.ACLParseError as e:
        raise HTTPException(422, f"alias body parse error: {e}")
    if not items:
        raise HTTPException(422, "alias body must have at least one entry")

    out = []
    for item in items:
        if isinstance(item, acl_mod.ACLAliasRef):
            raise HTTPException(
                422,
                f"alias body cannot reference other aliases (@{item.name}); "
                f"flatten by including its CIDRs directly",
            )
        if item.action == "deny":
            raise HTTPException(
                422,
                f"alias body cannot contain deny rules (!{item.cidr}); "
                f"deny semantics apply to the alias usage, not to its body",
            )
        out.append(item)
    return out


@app.post("/api/acl-aliases")
def create_acl_alias(body: dict):
    """Create a new alias.

    Body: {"name": str, "description": str (optional), "body": str}
    where `body` is a comma-separated list like a peer's ACL.

    Conflicts (name already exists) → 409.
    """
    name = (body.get("name") or "").strip().lower()
    description = (body.get("description") or "").strip()
    raw_body = (body.get("body") or "").strip()

    if not _ALIAS_NAME_RE.match(name):
        raise HTTPException(
            422,
            "alias name must be 1-32 chars, lowercase letters/digits/underscore",
        )
    if len(description) > 200:
        raise HTTPException(422, "description too long (max 200 chars)")

    entries = _validate_alias_body(raw_body)

    conn = get_db().conn
    if conn.execute(
        "SELECT 1 FROM acl_aliases WHERE name = ?", (name,)
    ).fetchone():
        raise HTTPException(409, f"alias @{name} already exists")

    body_json = json.dumps([
        {"cidr": e.cidr, "port": e.port, "proto": e.proto}
        for e in entries
    ])
    with get_db().write() as c:
        c.execute(
            "INSERT INTO acl_aliases (name, body, description) VALUES (?, ?, ?)",
            (name, body_json, description or None),
        )
    return {"ok": True, "name": name}


@app.put("/api/acl-aliases/{name}")
def update_acl_alias(name: str, body: dict):
    """Update an existing alias's body and/or description.

    The name itself is immutable — to rename, delete and recreate (and
    update all referencing peers). Editing the body re-applies ACLs for
    every referencing peer so iptables stays in sync with the new
    expansion.
    """
    name = name.strip().lower()
    if not _ALIAS_NAME_RE.match(name):
        raise HTTPException(422, "invalid alias name in URL")

    conn = get_db().conn
    if not conn.execute(
        "SELECT 1 FROM acl_aliases WHERE name = ?", (name,)
    ).fetchone():
        raise HTTPException(404, f"alias @{name} not found")

    description = body.get("description")
    raw_body = body.get("body")

    updates = []
    params = []
    if description is not None:
        if len(description) > 200:
            raise HTTPException(422, "description too long (max 200 chars)")
        updates.append("description = ?")
        params.append(description.strip() or None)

    affected_peers: List[int] = []
    if raw_body is not None:
        entries = _validate_alias_body(raw_body)
        body_json = json.dumps([
            {"cidr": e.cidr, "port": e.port, "proto": e.proto}
            for e in entries
        ])
        updates.append("body = ?")
        params.append(body_json)
        # Find affected peers — they need iptables re-applied because
        # the alias's expansion has changed.
        affected_peers = [
            r["peer_id"]
            for r in conn.execute(
                "SELECT peer_id FROM acl_alias_refs WHERE alias_name = ?",
                (name,),
            ).fetchall()
        ]

    if not updates:
        return {"ok": True, "name": name}

    params.append(name)
    with get_db().write() as c:
        c.execute(
            f"UPDATE acl_aliases SET {', '.join(updates)} WHERE name = ?",
            params,
        )

    # Re-apply iptables for every peer that references this alias.
    # Cheap (per-peer chain flush + reapply); the alternative would be
    # to wait until they save their own ACL again, but that leaves
    # iptables stale meanwhile.
    for pid in affected_peers:
        peer_row = conn.execute(
            "SELECT address FROM peers WHERE id = ? AND enabled = 1",
            (pid,),
        ).fetchone()
        if peer_row:
            ipt.apply_peer_acls(pid, _load_peer_acls(pid),
                                peer_address=peer_row["address"])

    return {"ok": True, "name": name, "reapplied_peers": affected_peers}


@app.delete("/api/acl-aliases/{name}")
def delete_acl_alias(name: str):
    """Delete an alias. Refuses if any peer references it.

    The operator must remove the @name from each peer's ACL first.
    Force-delete is not provided — accidentally deleting an alias that
    a peer's full-tunnel ACL depends on would silently change that
    peer's iptables on next save (the alias would expand to nothing).
    Better to make the operator do it explicitly.
    """
    name = name.strip().lower()
    conn = get_db().conn
    row = conn.execute(
        "SELECT 1 FROM acl_aliases WHERE name = ?", (name,)
    ).fetchone()
    if not row:
        raise HTTPException(404, f"alias @{name} not found")

    refs = conn.execute(
        "SELECT peer_id FROM acl_alias_refs WHERE alias_name = ?", (name,)
    ).fetchall()
    if refs:
        peer_ids = [r["peer_id"] for r in refs]
        # Look up names for a friendlier error.
        names_rows = conn.execute(
            f"SELECT id, name FROM peers WHERE id IN ({','.join('?' * len(peer_ids))})",
            peer_ids,
        ).fetchall()
        peer_names = ", ".join(r["name"] for r in names_rows) or str(peer_ids)
        raise HTTPException(
            409,
            f"alias @{name} is referenced by {len(peer_ids)} peer(s): "
            f"{peer_names}. remove the reference from each peer first.",
        )

    with get_db().write() as c:
        c.execute("DELETE FROM acl_aliases WHERE name = ?", (name,))
    return {"ok": True, "deleted": name}


@app.get("/api/peers/acl-stats")
def acl_stats_snapshot():
    """Cross-peer ACL counter snapshot for the stats panel.

    This is the env-agnostic replacement for the failed iptables-LOG
    streaming path. Reads `iptables-save -c` once per call and parses
    the [pkts:bytes] counters per rule. The UI polls this every few
    seconds and computes deltas client-side, giving a "live feel"
    without requiring kernel-log delivery (which doesn't work reliably
    inside Docker containers due to nf_log_all_netns isolation).

    The response is shaped per-peer so the UI can group rules under
    each peer name. Disabled peers are excluded (their chains stay in
    place but no traffic hits them, so counters are useless to display).
    """
    return ipt.read_acl_stats()


@app.post("/api/peers/acl-stats/reset")
def acl_stats_reset():
    """Zero per-peer chain counters.

    Per-peer FORWARD chains are zeroed via `iptables -Z <chain>`. Rules
    are not removed; only counters reset. Does NOT zero INPUT-chain
    explicit-deny counters (touching INPUT could affect operator-managed
    rules). The UI banner explains this scoping.
    """
    ipt.reset_acl_stats()
    return {"ok": True, "snapshot_ts": time.time()}


@app.get("/api/iptables/dump")
def iptables_dump():
    """Full iptables dump (filter + nat tables) as plain text.

    Read-only. Used by the "view raw iptables" modal for inspection
    when the operator wants to verify rule shape directly. Auto-refreshed
    by the modal every few seconds while open.

    Returns plain text rather than JSON because the consumer is a
    fixed-width text display — parsing into structure would lose the
    layout iptables produces, and we'd just have to re-render it
    client-side. The text is short (a few KB) so the bandwidth cost
    is fine even at 3-second poll intervals.
    """
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(ipt.dump_all())


@app.get("/api/rdns/{ip}")
async def rdns(ip: str):
    """Reverse-DNS lookup for any IP. Cached server-side (24h hits, 5min misses)
    so repeated lookups of the same address are instant.

    Returns: {"ip": "1.2.3.4", "hostname": "host.example.com" | null}
    """
    # Light validation — don't pass arbitrary strings into gethostbyaddr.
    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, f"not a valid IP: {ip!r}")
    host = await inspector.reverse_dns(ip)
    return {"ip": ip, "hostname": host}


@app.get("/api/peers/{peer_id}/ping")
async def peer_ping(peer_id: int):
    """Ping the peer's tunnel IP from the server. Returns latency stats.

    Behavior depends on peer state:
      - Peer never connected: returns {"online": false, "ever_connected": false}
        immediately, no actual ping issued
      - Peer has handshake but it's stale (>180s): returns
        {"online": false, "last_handshake": <ts>}; no ping issued (would just
        time out and waste a second)
      - Peer is online: sends 3 ICMP probes (1s timeout each), reports avg/min/max,
        loss percentage, and a hint if 100% loss (likely split-tunneled or
        firewalled at the peer end)

    Why this design — pinging an offline peer is just a 3s wait for the
    timeout. We can tell from the metrics snapshot whether the peer is
    even reachable, so we short-circuit when not.
    """
    conn = get_db().conn
    row = conn.execute(
        "SELECT name, address, public_key, last_handshake_at FROM peers WHERE id = ?",
        (peer_id,),
    ).fetchone()
    if not row:
        raise HTTPException(404, "peer not found")

    peer_ip = row["address"].split("/", 1)[0]
    peer_name = row["name"]
    snap = metrics.latest
    pm = snap.peers.get(row["public_key"]) if snap else None
    handshake = pm.latest_handshake if pm else 0
    online = handshake > 0 and (int(time.time()) - handshake) < 180
    ever_connected = bool(row["last_handshake_at"]) or handshake > 0

    base = {
        "peer_id": peer_id,
        "peer_name": peer_name,
        "peer_ip": peer_ip,
        "online": online,
        "ever_connected": ever_connected,
        "last_handshake": handshake or (row["last_handshake_at"] or 0),
    }

    if not online:
        # Don't bother pinging — return state-only response.
        base["pinged"] = False
        base["reason"] = "peer offline" if ever_connected else "peer never connected"
        return base

    # 3 probes, 1s timeout each, total wall ≈ 3-4s worst case.
    # Use ping's own quiet stats parsing instead of regex acrobatics:
    # exit 0 means ≥1 reply received; we read the rtt summary line.
    proc = await asyncio.create_subprocess_exec(
        "ping", "-4", "-c", "3", "-W", "1", "-q", peer_ip,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return {**base, "pinged": True, "reachable": False,
                "reason": "ping timed out"}

    output = stdout.decode("utf-8", errors="replace")
    # Parse the ping summary lines. Format example:
    #   3 packets transmitted, 3 received, 0% packet loss, time 2003ms
    #   rtt min/avg/max/mdev = 12.345/13.456/14.567/0.789 ms
    import re as _re
    loss_m = _re.search(r"(\d+)%\s+packet loss", output)
    rtt_m = _re.search(
        r"(?:rtt|round-trip)\s+min/avg/max(?:/mdev)?\s*=\s*"
        r"([\d.]+)/([\d.]+)/([\d.]+)(?:/([\d.]+))?",
        output,
    )

    loss_pct = int(loss_m.group(1)) if loss_m else 100
    if rtt_m:
        result = {
            **base,
            "pinged": True,
            "reachable": loss_pct < 100,
            "loss_pct": loss_pct,
            "rtt_min_ms": float(rtt_m.group(1)),
            "rtt_avg_ms": float(rtt_m.group(2)),
            "rtt_max_ms": float(rtt_m.group(3)),
            "rtt_mdev_ms": float(rtt_m.group(4)) if rtt_m.group(4) else 0.0,
        }
    else:
        # Online (handshake fresh) but no ICMP got through. Most common
        # cause: peer's AllowedIPs is split-tunnel and doesn't include
        # 10.13.13.0/24 → reply leaves via the peer's regular internet,
        # never reaches us. Or the peer's OS firewall blocks ICMP.
        result = {
            **base,
            "pinged": True,
            "reachable": False,
            "loss_pct": 100,
            "reason": "online but no ICMP reply (peer may be split-tunneled or filtering ICMP)",
        }

    return result


@app.get("/api/peers/{peer_id}/inspect")
async def peer_inspect(peer_id: int):
    """Deep inspection of a single peer.

    Returns endpoint info (with reverse DNS), ACL hit counters, the raw
    `wg show` block, and the live conntrack flow list. Designed to populate
    the "inspect" modal in the UI; safe to poll every 2s while the modal
    is open (~15ms per call typical, dominated by the conntrack subprocess).
    """
    conn = get_db().conn
    row = conn.execute(
        "SELECT id, name, address, public_key FROM peers WHERE id = ?",
        (peer_id,),
    ).fetchone()
    if not row:
        raise HTTPException(404, "peer not found")

    snap = metrics.latest
    pm = snap.peers.get(row["public_key"]) if snap else None

    # Endpoint info + reverse DNS.
    endpoint_ip: Optional[str] = None
    endpoint_port: Optional[int] = None
    rdns: Optional[str] = None
    if pm and pm.endpoint:
        # Endpoint format is "ip:port". For IPv6 it's "[ip]:port".
        ep = pm.endpoint
        if ep.startswith("["):
            close = ep.find("]")
            endpoint_ip = ep[1:close]
            endpoint_port = int(ep[close + 2:])
        else:
            endpoint_ip, _, port_s = ep.rpartition(":")
            endpoint_port = int(port_s) if port_s.isdigit() else None
        if endpoint_ip:
            rdns = await inspector.reverse_dns(endpoint_ip)

    # ACL hits (latest snapshot, sorted by bytes descending — useful for
    # "what is this peer mostly talking to").
    hits = snap.acl_hits.get(peer_id, []) if snap else []
    hits_sorted = sorted(hits, key=lambda h: h.bytes, reverse=True)

    # conntrack — strip the /32 from the address.
    peer_src = row["address"].split("/", 1)[0]
    flows: List[dict] = []
    conntrack_ok = await asyncio.to_thread(inspector.conntrack_available)
    if conntrack_ok:
        raw_flows = await asyncio.to_thread(inspector.list_flows, peer_src)
        flows = [
            {
                "proto": f.proto,
                "src": f.src, "src_port": f.src_port,
                "dst": f.dst, "dst_port": f.dst_port,
                "state": f.state,
                "timeout_seconds": f.age_seconds,
                "packets": f.packets, "bytes": f.bytes,
            }
            for f in raw_flows
        ]

    # Raw wg show block.
    wg_block = await asyncio.to_thread(
        inspector.wg_peer_block, SETTINGS.interface, row["public_key"]
    )

    # DNS queries from this peer (ring buffer + recent sqlite history).
    peer_ip = row["address"].split("/", 1)[0]
    dns_recent_for_peer = dns_log.recent_for_peer_ip(peer_ip, limit=50)

    return {
        "peer": {
            "id": row["id"],
            "name": row["name"],
            "address": row["address"],
            "public_key": row["public_key"],
        },
        "endpoint": {
            "raw": pm.endpoint if pm else None,
            "ip": endpoint_ip,
            "port": endpoint_port,
            "reverse_dns": rdns,
        },
        "transfer": {
            "rx_bytes": pm.rx_bytes if pm else 0,
            "tx_bytes": pm.tx_bytes if pm else 0,
            "rx_rate": pm.rx_rate if pm else 0.0,
            "tx_rate": pm.tx_rate if pm else 0.0,
            "latest_handshake": pm.latest_handshake if pm else 0,
        },
        "acl_top": [
            {"cidr": h.cidr, "port": h.port, "proto": h.proto,
             "pkts": h.pkts, "bytes": h.bytes, "action": h.action}
            for h in hits_sorted
        ],
        "flows": flows,
        "conntrack_available": conntrack_ok,
        "wg_dump": wg_block,
        "dns": dns_recent_for_peer,
        "sparkline": metrics.peer_sparkline(row["public_key"]),
    }


@app.get("/api/dns/recent")
def dns_recent(limit: int = 100):
    """Recent DNS queries across all peers, newest first.
    Returns an empty list when local DNS is disabled (no queries to log)."""
    if not SETTINGS.local_dns_enabled:
        return []
    return dns_log.recent_global(limit=min(limit, 1000))


@app.get("/api/peers/{peer_id}/dns")
def peer_dns(peer_id: int, limit: int = 50, history: bool = False):
    """DNS queries for one peer.

    By default returns the in-memory ring (very recent, up to 200 entries).
    Pass ?history=true to query sqlite for older deduplicated history.
    Returns empty list when local DNS is disabled.
    """
    if not SETTINGS.local_dns_enabled:
        return []
    conn = get_db().conn
    row = conn.execute(
        "SELECT address FROM peers WHERE id = ?", (peer_id,)
    ).fetchone()
    if not row:
        raise HTTPException(404, "peer not found")

    if history:
        return dns_log.history_for_peer_id(peer_id, limit=min(limit, 1000))

    peer_ip = row["address"].split("/", 1)[0]
    return dns_log.recent_for_peer_ip(peer_ip, limit=min(limit, 200))


# ---------------------------------------------------------------------------
# DNS overrides — manual hostname → internal-IP rewrites.
# ---------------------------------------------------------------------------

class _DnsOverrideIn(_BaseModel):
    pattern: str
    target_ip: str
    note: Optional[str] = None


@app.get("/api/dns/overrides")
def list_dns_overrides():
    """List every override currently in effect."""
    return dns_overrides.list_all(get_db().conn)


@app.post("/api/dns/overrides", status_code=201)
def add_dns_override(body: _DnsOverrideIn):
    """Create an override. Validates the pattern and IP, refuses public
    targets, then re-renders the dnsmasq drop-in file and HUPs dnsmasq.

    On success returns the persisted row including its assigned id.
    """
    try:
        pattern = dns_overrides.validate_pattern(body.pattern)
        target = dns_overrides.validate_target(body.target_ip)
    except dns_overrides.OverrideError as e:
        raise HTTPException(422, str(e))

    note = (body.note or "").strip() or None

    conn = get_db().conn
    # Surface uniqueness violations cleanly instead of letting sqlite raise.
    if conn.execute(
        "SELECT 1 FROM dns_overrides WHERE pattern = ?", (pattern,)
    ).fetchone():
        raise HTTPException(409, f"override for {pattern!r} already exists")

    with get_db().write() as c:
        cur = c.execute(
            "INSERT INTO dns_overrides (pattern, target_ip, note) VALUES (?, ?, ?)",
            (pattern, target, note),
        )
        new_id = cur.lastrowid

    # Re-render and reload dnsmasq.
    try:
        dns_overrides.write_and_reload(dns_overrides.list_all(get_db().conn))
    except Exception as e:
        # The DB row already exists; surface the apply error so the operator
        # knows the override is staged but not active yet.
        raise HTTPException(500, f"override saved but dnsmasq reload failed: {e}")

    row = get_db().conn.execute(
        "SELECT id, pattern, target_ip, note, created_at FROM dns_overrides WHERE id = ?",
        (new_id,),
    ).fetchone()
    return dict(row)


@app.delete("/api/dns/overrides/{override_id}", status_code=204)
def delete_dns_override(override_id: int):
    conn = get_db().conn
    if not conn.execute(
        "SELECT 1 FROM dns_overrides WHERE id = ?", (override_id,)
    ).fetchone():
        raise HTTPException(404, "override not found")

    with get_db().write() as c:
        c.execute("DELETE FROM dns_overrides WHERE id = ?", (override_id,))

    try:
        dns_overrides.write_and_reload(dns_overrides.list_all(get_db().conn))
    except Exception as e:
        raise HTTPException(500, f"override deleted but dnsmasq reload failed: {e}")
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Log streams — on-demand WebSocket per source.
# ---------------------------------------------------------------------------

@app.get("/api/logs/availability")
def logs_availability():
    """Tell the UI which streams are usable right now and why each isn't."""
    return log_streams.availability()


@app.websocket("/ws/logs/{source}")
async def ws_logs(websocket: WebSocket, source: str):
    """On-demand log stream. Source must be one of: dnsmasq, wireguard,
    iptables, access. Auth: same cookie check as the status WS — anyone
    able to read these can also see admin data, so they need a session."""
    if not auth.is_authenticated_ws(websocket):
        await websocket.close(code=4401)
        return
    handler = log_streams.DISPATCH.get(source)
    if handler is None:
        await websocket.close(code=4404)
        return
    await websocket.accept()
    # Track this connection for the live-icon tooltip. Source label
    # includes the log type so the operator can see what's open
    # ("/ws/logs/dnsmasq" vs "/ws/logs/wireguard"). Decremented in
    # finally so abnormal teardown still gets accounted.
    counter_label = f"/ws/logs/{source}"
    ws_counter.increment(counter_label)
    try:
        await handler(websocket)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        # Surface unexpected errors to the client before closing.
        try:
            await websocket.send_json({"error": f"stream failed: {e!r}"})
        except Exception:
            pass
    finally:
        ws_counter.decrement(counter_label)


# ---------------------------------------------------------------------------
# Network diagnostics — public IP, speedtest, on-demand tools
# ---------------------------------------------------------------------------

class _DiagToolIn(_BaseModel):
    target: str
    record_type: Optional[str] = None        # only used by `dig`
    count: Optional[int] = None              # only used by `ping`


@app.get("/api/network/status")
async def network_status():
    """Lightweight status for the top bar: public IP + last speedtest summary."""
    ip = await network_diag.public_ip()
    conn = get_db().conn
    row = conn.execute(
        "SELECT ts, ping_ms, jitter_ms, down_mbps, up_mbps, error, endpoint "
        "FROM speedtest_history ORDER BY ts DESC LIMIT 1"
    ).fetchone()
    last = dict(row) if row else None
    sched_row = conn.execute(
        "SELECT value FROM network_settings WHERE key = 'auto_interval_min'"
    ).fetchone()
    auto_min = int(sched_row["value"]) if sched_row else 0
    auto_ep_row = conn.execute(
        "SELECT value FROM network_settings WHERE key = 'auto_endpoint'"
    ).fetchone()
    auto_endpoint = auto_ep_row["value"] if auto_ep_row else "cloudflare"
    return {
        "public_ip": ip,
        "last_speedtest": last,
        "auto_interval_min": auto_min,
        "auto_endpoint": auto_endpoint,
    }


@app.get("/api/network/speedtest/endpoints")
def network_speedtest_endpoints():
    """List every speedtest endpoint the server can run a test against.

    UI populates a dropdown from this. Includes a `default` flag for the
    initial selection and `supports_upload` so the UI can label download-
    only endpoints clearly.
    """
    return network_diag.list_endpoints()


@app.post("/api/network/speedtest")
async def network_speedtest_run(endpoint: str = "cloudflare"):
    """Run a speedtest synchronously and persist the result.

    Speedtests take 15-30 seconds; clients should set a generous timeout.
    Concurrent calls are serialized via the module-level lock so two
    operators clicking at once don't compete for upload bandwidth.

    The test consumes real upload AND download bandwidth on the server
    while running — VPN peers will see degraded throughput for the duration.

    Query param `endpoint` selects which provider to test against; defaults
    to `cloudflare`. See GET /api/network/speedtest/endpoints for the list.
    """
    if endpoint not in network_diag.ENDPOINTS:
        raise HTTPException(422, f"unknown endpoint: {endpoint}")
    result = await network_diag.run_speedtest(endpoint)
    _persist_speedtest(result)
    return result


@app.get("/api/network/speedtest/history")
def network_speedtest_history(limit: int = 200):
    """Return up to `limit` most recent speedtest rows, oldest first
    (so the chart can render left-to-right naturally)."""
    conn = get_db().conn
    rows = conn.execute(
        """SELECT ts, ping_ms, jitter_ms, down_mbps, up_mbps, duration_s, error, endpoint
           FROM speedtest_history ORDER BY ts DESC LIMIT ?""",
        (max(1, min(limit, 1000)),),
    ).fetchall()
    return [dict(r) for r in reversed(rows)]


@app.delete("/api/network/speedtest/history", status_code=204)
def network_speedtest_history_clear(confirm: str = ""):
    """Wipe all speedtest history. Destructive — guarded by ?confirm=DELETE
    so it can't be triggered by accident (e.g. a stale browser tab making
    a misrouted request). The chart will be empty until new tests run.

    The auto-test schedule is NOT touched — only the historical samples.
    """
    if confirm != "DELETE":
        raise HTTPException(400, "must pass ?confirm=DELETE to wipe history")
    with get_db().write() as c:
        c.execute("DELETE FROM speedtest_history")
    return None


class _SpeedtestSchedule(_BaseModel):
    interval_min: int                   # 0 = disabled, else minutes (min effective 5)
    endpoint: Optional[str] = None      # if set, persists which endpoint auto-tests use


@app.put("/api/network/speedtest/schedule")
def network_speedtest_set_schedule(body: _SpeedtestSchedule):
    """Set the auto-speedtest schedule. 0 disables. Min effective interval 5 min.

    The endpoint is optional — when omitted, the previously-saved auto endpoint
    stays in effect (default: 'cloudflare' for fresh installs).
    """
    interval = body.interval_min
    if interval < 0:
        raise HTTPException(422, "interval cannot be negative")
    if 0 < interval < 5:
        interval = 5

    if body.endpoint is not None and body.endpoint not in network_diag.ENDPOINTS:
        raise HTTPException(422, f"unknown endpoint: {body.endpoint}")

    with get_db().write() as c:
        c.execute(
            """INSERT INTO network_settings (key, value) VALUES (?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
            ("auto_interval_min", str(interval)),
        )
        if body.endpoint is not None:
            c.execute(
                """INSERT INTO network_settings (key, value) VALUES (?, ?)
                   ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
                ("auto_endpoint", body.endpoint),
            )
    return {"interval_min": interval, "endpoint": body.endpoint}


@app.post("/api/network/diag/{tool}")
async def network_diag_run(tool: str, body: _DiagToolIn):
    """Run a diagnostic tool. Output is captured raw and returned as a
    string for the UI to display in a <pre> block."""
    handler = network_diag.DIAG_TOOLS.get(tool)
    if handler is None:
        raise HTTPException(404, f"unknown tool: {tool}")
    try:
        if tool == "dig":
            result = await handler(body.target, body.record_type or "A")
        elif tool == "ping":
            # Ping accepts an optional count; default 3 lives in the tool itself.
            if body.count is not None:
                result = await handler(body.target, body.count)
            else:
                result = await handler(body.target)
        else:
            result = await handler(body.target)
    except ValueError as e:
        raise HTTPException(422, str(e))
    return result


@app.websocket("/ws/status")
async def ws_status(websocket: WebSocket):
    """Stream combined peer + host + throughput snapshot every 1 second.

    WebSocket auth: FastAPI middleware doesn't intercept WS handshakes
    (different ASGI scope), so we check the session cookie ourselves
    before accepting. Browsers include cookies on WS connects to the same
    origin so this works transparently from the UI.

    Disconnect handling:
      The loop runs as a `send_loop` task. A second `recv_drain` task
      reads from the client; when the client closes the socket, that
      task raises WebSocketDisconnect (or ConnectionClosed) and we
      cancel the send loop. Without this, send_text() can keep silently
      succeeding for up to ~2 hours after a dirty close (browser tab
      killed, network dropped) because TCP retransmit timeouts are
      that long; the kernel still buffers writes that never reach the
      client. The recv-side detection is much faster: the OS surfaces
      a closed socket on read attempts almost immediately.

      Both tasks share an `asyncio.wait(..., FIRST_COMPLETED)` so
      whichever side notices first wins and tears the other down.
    """
    if not auth.is_authenticated_ws(websocket):
        await websocket.close(code=4401)    # custom close code = unauthorized
        return
    await websocket.accept()
    # Track this connection in the global counter so the UI can show
    # how many WSes are open. Counter is decremented in the finally
    # block below so abnormal teardown still gets accounted for.
    ws_counter.increment("/ws/status")

    async def send_loop():
        """Push a status snapshot every 1s. Raises if the socket is dead."""
        while True:
            # All of this reads metrics.* state, which is updated by the
            # collector task. No shell-outs here — pure in-memory reads
            # plus a sqlite query.
            conn = get_db().conn
            rows = conn.execute(
                "SELECT id, name, address, public_key, last_handshake_at FROM peers"
            ).fetchall()
            snap = metrics.latest
            peers_dump = snap.peers if snap else {}
            acl_snapshots = snap.acl_hits if snap else {}
            now = int(time.time())

            peer_list = []
            for r in rows:
                pm = peers_dump.get(r["public_key"])
                handshake = pm.latest_handshake if pm else 0
                online = handshake > 0 and (now - handshake) < 180
                # ever_connected: True if we've persisted a handshake at any
                # point in the past. Survives container restarts (kernel
                # state resets but the db row is preserved).
                ever_connected = bool(r["last_handshake_at"]) or handshake > 0
                # The "best" handshake to display — the live one if present,
                # otherwise the persisted one. So a peer that connected
                # yesterday and is now offline still shows "1d ago" instead
                # of "never".
                effective_handshake = handshake or (r["last_handshake_at"] or 0)
                hits = acl_snapshots.get(r["id"], [])
                peer_list.append({
                    "id": r["id"],
                    "name": r["name"],
                    "address": r["address"],
                    "public_key": r["public_key"],
                    "endpoint": pm.endpoint if pm else None,
                    "latest_handshake": effective_handshake,
                    "rx_bytes": pm.rx_bytes if pm else 0,
                    "tx_bytes": pm.tx_bytes if pm else 0,
                    "rx_rate": pm.rx_rate if pm else 0.0,
                    "tx_rate": pm.tx_rate if pm else 0.0,
                    "online": online,
                    "ever_connected": ever_connected,
                    "acl_hits": [
                        {"cidr": h.cidr, "port": h.port, "proto": h.proto,
                         "pkts": h.pkts, "bytes": h.bytes}
                        for h in hits
                    ],
                    "sparkline": [
                        {"ts": p["ts"], "rx": p["rx"], "tx": p["tx"]}
                        for p in metrics.peer_sparkline(r["public_key"])
                    ],
                })

            # Latest throughput point: the most recent entry of the ring.
            tp = metrics.throughput_ring[-1] if metrics.throughput_ring else None
            payload = {
                "peers": peer_list,
                "host": _host_dict(snap.host) if snap else None,
                "throughput_point": {
                    "ts": tp.ts, "rx": tp.rx_rate, "tx": tp.tx_rate,
                    "online": tp.peers_online, "total": tp.peers_total,
                } if tp else None,
                "session_count": sum(1 for p in peer_list if p["online"]),
                # WS counter snapshot (v3.6). Cheap to compute (sum of a
                # small dict). UI uses this to render the live-icon
                # tooltip showing how many WSes are open + breakdown.
                "ws_count": ws_counter.snapshot(),
            }
            await websocket.send_text(json.dumps(payload))
            await asyncio.sleep(1.0)

    async def recv_drain():
        """Sit on receive_text() to detect client disconnect promptly.

        We don't expect the client to send us anything — the protocol is
        server→client only. But a pending recv_text() call is what makes
        the OS surface a closed socket via WebSocketDisconnect, instead
        of us waiting for the next send to discover the same fact ~minutes
        or hours later. If the client DOES send something, we just discard
        it and keep waiting; the panel UI never sends to /ws/status so
        this branch is unreachable in practice.
        """
        while True:
            await websocket.receive_text()

    send_task = asyncio.create_task(send_loop(), name="ws_status_send")
    recv_task = asyncio.create_task(recv_drain(), name="ws_status_recv")
    try:
        # FIRST_COMPLETED: whichever task finishes (or raises) wins.
        # Disconnect raises in recv_task; a serialization or socket-write
        # error raises in send_task. Either way we want to tear down both.
        done, pending = await asyncio.wait(
            {send_task, recv_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        # Surface the exception from whichever task completed, if it was
        # exceptional. This makes leaks during development louder — a
        # silent crash in send_loop would otherwise just look like a
        # disconnect. WebSocketDisconnect is the expected case and is
        # caught below.
        for t in done:
            exc = t.exception()
            if exc and not isinstance(exc, (WebSocketDisconnect, asyncio.CancelledError)):
                # Log but don't re-raise: we want the cleanup path to run
                # regardless. A real bug would also produce stderr noise.
                import traceback
                traceback.print_exception(type(exc), exc, exc.__traceback__)
    except WebSocketDisconnect:
        # Normal close path — client tab closed, network dropped, etc.
        pass
    finally:
        # Cancel whichever task is still running. await-ing them after
        # cancel() guarantees their finally blocks run before we proceed.
        for t in (send_task, recv_task):
            if not t.done():
                t.cancel()
        # Drain the cancellations. Use return_exceptions=True so a
        # CancelledError in one task doesn't stop us awaiting the other.
        await asyncio.gather(send_task, recv_task, return_exceptions=True)
        # Best-effort close. Already-closed sockets raise here, which we
        # swallow — the goal is just to ensure the close handshake is
        # initiated if we got here via send-side error rather than
        # client-initiated disconnect.
        try:
            await websocket.close()
        except Exception:
            pass
        # Always decrement the WS counter, even on abnormal teardown.
        ws_counter.decrement("/ws/status")


# ---------------------------------------------------------------------------
# v4.2-rebuild: multisite API (registration-then-bundle, no callback)
# ---------------------------------------------------------------------------
# Symmetric peering on wg0. Two-step copy-paste pairing — no callback,
# no chicken-and-egg.
#
# Flow:
#   1. importer (wgB):
#        POST /api/multisite/registration
#        → wgflow generates keypair locally, allocates overlay addr,
#          stashes privkey on a pending-bundle row, returns
#          registration text. Operator copies.
#   2. creator (wgA):
#        POST /api/multisite/links {registration: "..."}
#        → parse registration, allocate own overlay, generate PSK,
#          INSERT wgB AS A wg0 PEER IMMEDIATELY (peer_type=multisite),
#          persist established row, return bundle text. Operator copies
#          back. wgA is now ready to handshake with wgB the moment
#          wgB has wgA's pubkey.
#   3. importer (wgB):
#        POST /api/multisite/links/{id}/import-complete {bundle: "..."}
#        → parse bundle, INSERT wgA AS A wg0 PEER using stashed
#          privkey, transition status to 'established'. Tunnel
#          handshakes within ~5s; overlay reachable.
#
# No background reconciliation needed — every step's prerequisites are
# satisfied before the step runs.
#
# Endpoints:
#   GET    /api/multisite/status                  → counts + local overlay
#   GET    /api/multisite/links                   → list rows
#   POST   /api/multisite/registration            → step 1 (importer)
#   POST   /api/multisite/links                   → step 2 (creator, takes registration)
#   POST   /api/multisite/links/{id}/import-complete → step 3 (importer, takes bundle)
#   PUT    /api/multisite/links/{id}              → toggle / rename
#   DELETE /api/multisite/links/{id}              → remove


def _multisite_link_to_out(conn, row) -> dict:
    """Shape a federation_links row + paired peer for the API."""
    peer = None
    if row["peer_id"]:
        peer = conn.execute(
            "SELECT name, public_key, address, enabled, last_handshake_at "
            "FROM peers WHERE id=?", (row["peer_id"],),
        ).fetchone()

    return {
        "id": row["id"],
        "name": row["name"],
        "role": row["role"],
        "status": row["status"],
        "local_overlay_addr": row["local_overlay_addr"],
        "remote_overlay_addr": row["remote_overlay_addr"],
        "local_advertised": row["local_advertised"] or "",
        "remote_advertised": row["remote_advertised"] or "",
        "remote_endpoint": row["remote_endpoint"] or "",
        "remote_instance_id": row["remote_instance_id"],
        "remote_instance_name": row["remote_instance_name"],
        "last_handshake_ts": row["last_handshake_ts"],
        "last_error": row["last_error"],
        "enabled": bool(row["enabled"]),
        "created_at": row["created_at"],
        # Importer-side rows in pending-bundle have a privkey stashed;
        # surface only the boolean to the panel (privkey itself never
        # leaves the server). Helps the UI show "waiting for bundle"
        # state distinctly from "established but no handshake yet."
        "has_pending_privkey": bool(row["importer_privkey"]),
        # Paired peer info (None until peer_id is set).
        "peer_id": row["peer_id"],
        "peer_name": peer["name"] if peer else None,
        "peer_public_key": peer["public_key"] if peer else None,
        "peer_address": peer["address"] if peer else None,
        "peer_last_handshake": peer["last_handshake_at"] if peer else None,
    }


@app.get("/api/multisite/status")
def multisite_status():
    """Lightweight summary for the panel header."""
    if not SETTINGS.multisite_enabled:
        return {"enabled": False, "reason": "WG_MULTISITE=0"}

    try:
        conn = get_db().conn
        rows = conn.execute(
            "SELECT role, status, enabled, local_overlay_addr "
            "FROM federation_links"
        ).fetchall()
        creator_links = sum(1 for r in rows if r["role"] == "creator")
        importer_links = sum(1 for r in rows if r["role"] == "importer")
        established = sum(
            1 for r in rows
            if r["enabled"] and r["status"] == "established"
        )
        pending_bundle = sum(
            1 for r in rows
            if r["enabled"] and r["status"] == "pending-bundle"
        )
        # Local overlay address — first row's local_overlay_addr if
        # any links exist. All rows on a given wgflow share the same
        # local_overlay_addr (it's our identity on the overlay).
        local_addr = None
        if rows:
            la = rows[0]["local_overlay_addr"]
            if la:
                local_addr = la.split("/", 1)[0]

        return {
            "enabled": True,
            "creator_links": creator_links,
            "importer_links": importer_links,
            "established": established,
            "pending_bundle": pending_bundle,
            "total": len(rows),
            "local_addr": local_addr,
            "default_endpoint": SETTINGS.federation_wg_endpoint,
        }
    except Exception as e:
        print(f"[multisite] status read failed: {type(e).__name__}: {e}",
              flush=True)
        return {
            "enabled": False,
            "reason": f"status read error: {type(e).__name__}",
            "error_detail": str(e)[:300],
        }


@app.get("/api/multisite/links")
def multisite_list_links():
    conn = get_db().conn
    rows = conn.execute(
        "SELECT * FROM federation_links ORDER BY id"
    ).fetchall()
    return [_multisite_link_to_out(conn, r) for r in rows]


def _validate_advertised(advertised: list, label: str) -> List[str]:
    """Shared advertised-CIDR validator used by both registration and
    create-link endpoints. Refuses 0.0.0.0/0 and ::/0 as a hard rule
    (lockout prevention — full-tunnel through a multisite link would
    rehome all the remote's traffic through us)."""
    out: List[str] = []
    for cidr in (advertised or []):
        cidr = cidr.strip()
        if not cidr:
            continue
        if cidr in ("0.0.0.0/0", "::/0"):
            raise HTTPException(
                400,
                f"0.0.0.0/0 in {label} would full-tunnel the remote "
                "wgflow through this one — refused. List specific "
                "CIDRs only.",
            )
        try:
            import ipaddress as _ip
            _ip.ip_network(cidr, strict=False)
        except ValueError:
            raise HTTPException(400, f"{label} CIDR malformed: {cidr}")
        if cidr not in out:
            out.append(cidr)
    return out


def _allocate_two_overlay_addrs(conn, prefer_local: str):
    """Pick two non-conflicting overlay addresses in 10.99.0.0/24.

    Returns (local, remote) where local takes prefer_local if free,
    and remote is the next free that is not local. Used by both the
    registration endpoint (prefer_local=DEFAULT_IMPORTER_OVERLAY_ADDR)
    and the create-from-registration endpoint (prefer_local=
    DEFAULT_CREATOR_OVERLAY_ADDR), but the latter passes the parsed
    importer overlay as the *remote* (already known) and we only
    allocate local in that case.
    """
    local = multisite_mod.allocate_overlay_addr(conn, prefer=prefer_local)
    used = {local}
    existing = conn.execute(
        "SELECT local_overlay_addr, remote_overlay_addr "
        "FROM federation_links"
    ).fetchall()
    for r in existing:
        for col in ("local_overlay_addr", "remote_overlay_addr"):
            v = (r[col] or "").split("/", 1)[0].strip()
            if v:
                used.add(v)
    for octet in range(1, 255):
        cand = f"10.99.0.{octet}"
        if cand not in used:
            return local, cand
    raise HTTPException(500, "overlay address pool exhausted")


@app.post("/api/multisite/registration", status_code=201)
def multisite_registration(body: MultisiteRegistrationRequest):
    """STEP 1 (importer): generate keypair, allocate overlay, return
    registration text for the operator to paste into the OTHER
    wgflow's '+ create from registration' form.

    Persists a federation_links row with role='importer',
    status='pending-bundle', importer_privkey set. The privkey stays
    on this row until the bundle import completes (step 3), at which
    point it moves to peers.private_key and is cleared from this row.

    Triggers replay so wg0 picks up the new overlay address. No peer
    entry yet on this side — that arrives in step 3 with the bundle.
    """
    if not SETTINGS.multisite_enabled:
        raise HTTPException(403, "multisite is disabled (WG_MULTISITE=0)")

    name = (body.name or "").strip()
    if not name:
        raise HTTPException(400, "name is required")

    advertised = _validate_advertised(body.advertised_networks,
                                      "advertised_networks")

    endpoint = (body.endpoint or "").strip() or SETTINGS.federation_wg_endpoint
    if ":" not in endpoint:
        raise HTTPException(
            400, "endpoint must be host:port (e.g. vpn.example.com:51820)"
        )

    privkey, pubkey = (None, _live_wg0_pubkey())

    with get_db().write() as conn:
        if conn.execute(
            "SELECT 1 FROM federation_links WHERE name=?", (name,)
        ).fetchone():
            raise HTTPException(409, f"link '{name}' already exists")

        # Allocate our overlay (.2 by default for importer side).
        # remote_overlay is unknown until the bundle arrives — leave
        # placeholder.
        local_overlay = multisite_mod.allocate_overlay_addr(
            conn, prefer=multisite_mod.DEFAULT_IMPORTER_OVERLAY_ADDR,
        )

        conn.execute(
            """INSERT INTO federation_links (
                name, role, peer_id,
                importer_privkey, psk,
                local_overlay_addr, remote_overlay_addr,
                local_advertised, remote_advertised,
                remote_endpoint,
                status, enabled
            ) VALUES (?, 'importer', NULL,
                      ?, '',
                      ?, '',
                      ?, '',
                      '',
                      'pending-bundle', 1)""",
            (name, privkey,
             f"{local_overlay}/32",
             ",".join(advertised)),
        )
        link_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    # Replay so wg0 picks up our overlay /32 as a secondary address.
    # No mgmt peer yet (that's step 3) — but we still need the
    # overlay address bound so step 3's replay doesn't have to do
    # double work, and so the operator can ping their own .2 as a
    # smoke test.
    _replay_state_to_kernel()

    registration_text = multisite_mod.build_registration(
        suggested_link_name=name,
        importer_pubkey=pubkey,
        importer_endpoint=endpoint,
        importer_overlay_addr=local_overlay,
        importer_advertised=advertised,
        importer_instance_name=_local_instance_name(),
    )

    return {
        "id": link_id,
        "name": name,
        "local_overlay_addr": local_overlay,
        "registration": registration_text,
    }


@app.post("/api/multisite/links", status_code=201)
def multisite_create_from_registration(body: MultisiteCreateLinkRequest):
    """STEP 2 (creator): parse a registration from the OTHER wgflow,
    install wgB as a wg0 peer NOW, return the bundle for the operator
    to paste back.

    This is the step that breaks the chicken-and-egg in the v4.2-pre
    callback design — we have wgB's pubkey from the registration, so
    we can put wgB's peer entry in place immediately. The moment wgB
    has our pubkey too (after pasting the bundle in step 3), the
    tunnel handshakes.

    name override: if body.name is set, it overrides the suggested
    name from the registration. Operators frequently want to label
    links by what THEY think of the remote, not what the remote
    suggested.
    """
    if not SETTINGS.multisite_enabled:
        raise HTTPException(403, "multisite is disabled (WG_MULTISITE=0)")

    try:
        parsed = multisite_mod.parse_registration(body.registration)
    except multisite_mod.MultisiteError as e:
        raise HTTPException(400, str(e))

    name = (body.name or "").strip() or parsed.suggested_link_name
    advertised = _validate_advertised(body.advertised_networks,
                                      "advertised_networks")

    endpoint = (body.endpoint or "").strip() or SETTINGS.federation_wg_endpoint
    if ":" not in endpoint:
        raise HTTPException(400, "endpoint must be host:port")

    server_pubkey = _live_wg0_pubkey()

    psk = multisite_mod.generate_psk()
    importer_overlay = parsed.importer_overlay_addr

    with get_db().write() as conn:
        if conn.execute(
            "SELECT 1 FROM federation_links WHERE name=?", (name,)
        ).fetchone():
            raise HTTPException(409, f"link '{name}' already exists")

        # Multi-wgflow safety: the registration's importer_overlay
        # must not collide with an address already used on this side
        # for a DIFFERENT remote. If it does, the operator on the
        # OTHER side accidentally chose an address we already have
        # routed to a different paired wgflow — accepting this would
        # produce two routes to the same overlay /32 via different
        # tunnels.
        existing_collision = conn.execute(
            "SELECT id, name FROM federation_links "
            "WHERE remote_overlay_addr LIKE ?",
            (f"{importer_overlay}/%",),
        ).fetchone()
        if existing_collision:
            raise HTTPException(409,
                f"the registration claims overlay address "
                f"{importer_overlay}, but that's already used by link "
                f"'{existing_collision['name']}' on this wgflow. ask "
                f"the operator on the OTHER side to re-run + import "
                f"with a different overlay address.")

        # Allocate our local overlay using the stable-identity rule:
        # if any prior link exists on this wgflow, reuse its
        # local_overlay_addr (our identity must be stable across
        # links). For the very first link, prefer .1 (creator
        # convention).
        try:
            local_overlay = multisite_mod.allocate_overlay_addr(
                conn,
                prefer=multisite_mod.DEFAULT_CREATOR_OVERLAY_ADDR,
            )
        except multisite_mod.MultisiteError as e:
            raise HTTPException(500, str(e))
        # Defense: the importer's overlay (carried in the registration)
        # must not collide with ours. If it does, the operator picked
        # the same address we already use for ourselves, which is
        # impossible to honor.
        if importer_overlay == local_overlay:
            raise HTTPException(
                409,
                f"overlay address collision: this wgflow uses "
                f"{local_overlay} as its own identity, but the "
                f"registration claims that address for the remote. "
                f"the operator on the OTHER side should re-run "
                f"+ import with a different address.",
            )

        # AllowedIPs for the wgB-as-peer entry on our side: wgB's
        # overlay /32 + each network wgB advertised.
        importer_aips = [f"{importer_overlay}/32"]
        for cidr in parsed.importer_advertised:
            if cidr and cidr not in importer_aips:
                importer_aips.append(cidr)

        # The peer-row's name should reflect the OTHER wgflow's
        # installation name (e.g. 'multisite:Falcon') — not the local
        # link name, which can be operator-supplied and may not match
        # what the remote calls itself. Fall back to link name only
        # when the registration was from an older wgflow that didn't
        # carry an instance name.
        remote_inst = parsed.importer_instance_name or name
        peer_display_name = f"multisite:{remote_inst}"

        # INSERT wgB as a wg0 peer NOW. peer_type='multisite' so it
        # doesn't appear in the live-peers panel. The peers.address
        # column holds the overlay /32 — _load_all_peers_for_sync
        # joins federation_links to compute the extended AllowedIPs.
        cur = conn.execute(
            """INSERT INTO peers (
                name, public_key, private_key, preshared_key,
                address, enabled, has_private_key, peer_type
            ) VALUES (?, ?, '', ?, ?, 1, 0, 'multisite')""",
            (
                peer_display_name,
                parsed.importer_pubkey,
                psk,
                f"{importer_overlay}/32",
            ),
        )
        peer_id = cur.lastrowid

        conn.execute(
            """INSERT INTO federation_links (
                name, role, peer_id,
                importer_privkey, psk,
                local_overlay_addr, remote_overlay_addr,
                local_advertised, remote_advertised,
                remote_endpoint,
                remote_instance_name,
                status, enabled
            ) VALUES (?, 'creator', ?,
                      NULL, ?,
                      ?, ?,
                      ?, ?,
                      ?,
                      ?,
                      'established', 1)""",
            (name, peer_id, psk,
             f"{local_overlay}/32", f"{importer_overlay}/32",
             ",".join(advertised),
             ",".join(parsed.importer_advertised),
             parsed.importer_endpoint,
             remote_inst),
        )
        link_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    # Replay so wg0 gets the secondary overlay address bound + the
    # new mgmt peer in syncconf.
    _replay_state_to_kernel()

    bundle_text = multisite_mod.build_bundle(
        link_name=name,
        creator_pubkey=server_pubkey,
        creator_endpoint=endpoint,
        creator_overlay_addr=local_overlay,
        importer_overlay_addr=importer_overlay,
        psk=psk,
        creator_advertised=advertised,
        creator_instance_name=_local_instance_name(),
    )

    return {
        "id": link_id,
        "name": name,
        "local_overlay_addr": local_overlay,
        "remote_overlay_addr": importer_overlay,
        "bundle": bundle_text,
    }


@app.post("/api/multisite/links/{link_id}/import-complete")
def multisite_import_complete(link_id: int, body: MultisiteImportCompleteRequest):
    """STEP 3 (importer): parse the bundle, install wgA as a wg0 peer
    using the privkey we stashed in step 1, transition to established.

    Look up the row by link_id (the panel knows which link the operator
    is completing — it came back from step 1). Validate the row is
    in pending-bundle state. Parse bundle. Sanity-check the bundle's
    importer_overlay_addr matches our row's local_overlay_addr — if
    they don't match, the operator pasted the wrong bundle (or some
    other wgflow generated this bundle for a different importer).

    On success: insert peer row for wgA, update federation_links to
    move privkey out of the row, transition status=established, replay.
    """
    if not SETTINGS.multisite_enabled:
        raise HTTPException(403, "multisite is disabled (WG_MULTISITE=0)")

    try:
        parsed = multisite_mod.parse_bundle(body.bundle)
    except multisite_mod.MultisiteError as e:
        raise HTTPException(400, str(e))

    with get_db().write() as conn:
        row = conn.execute(
            "SELECT * FROM federation_links WHERE id=?", (link_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(404, "link not found")
        if row["role"] != "importer":
            raise HTTPException(409,
                "this link is on the creator side; bundle import is for "
                "importer-side links")
        if row["status"] != "pending-bundle":
            current_status = row["status"]
            raise HTTPException(409,
                f"link is in status '{current_status}', expected "
                f"'pending-bundle'. is the bundle already imported?")

        # Sanity check: the bundle's importer_overlay_addr must match
        # what we allocated in step 1. If not, the bundle came from a
        # different pairing or someone hand-edited it.
        our_overlay = (row["local_overlay_addr"] or "").split("/", 1)[0]
        if parsed.importer_overlay_addr != our_overlay:
            raise HTTPException(400,
                f"bundle is for overlay {parsed.importer_overlay_addr}, "
                f"this link expects {our_overlay}. wrong bundle pasted?")

        # Multi-wgflow safety: refuse the bundle if the creator's
        # overlay address collides with an address we already have
        # in use for a DIFFERENT remote. This catches the case where
        # wgB is paired with wgA (remote=10.99.0.1) and now tries to
        # pair with wgC who independently picked the creator-default
        # 10.99.0.1 — we'd otherwise end up with two routes to .1
        # via different tunnels and the kernel would silently pick
        # one, leaving the other peer unreachable.
        creator_overlay = parsed.creator_overlay_addr
        existing_collision = conn.execute(
            "SELECT id, name, remote_overlay_addr FROM federation_links "
            "WHERE id != ? AND remote_overlay_addr LIKE ?",
            (link_id, f"{creator_overlay}/%"),
        ).fetchone()
        if existing_collision:
            raise HTTPException(409,
                f"overlay address {creator_overlay} is already used by "
                f"link '{existing_collision['name']}' on this wgflow. "
                f"the operator on the OTHER side ({parsed.creator_instance_name or 'unknown'}) "
                f"should re-run + create from registration with a "
                f"different local overlay address. recommended: pick "
                f"a value not in use by any of YOUR other links.")
        # Same check vs our own local — defensive, the registration-
        # vs-creator dialog should have prevented this, but a hand-
        # edited bundle could slip past.
        if creator_overlay == our_overlay:
            raise HTTPException(409,
                f"the bundle's creator overlay {creator_overlay} matches "
                f"this wgflow's own overlay address. someone needs to "
                f"pick a different address.")

        # AllowedIPs for wgA-as-peer: wgA's overlay /32 + each
        # network wgA advertised.
        creator_aips = [f"{parsed.creator_overlay_addr}/32"]
        for cidr in parsed.creator_advertised:
            if cidr and cidr not in creator_aips:
                creator_aips.append(cidr)

        # Insert peer row using the privkey we stashed in step 1.
        # has_private_key=1 because we DO hold the keypair this time
        # (we generated it locally during registration).
        # Insert the peer row for the creator side. private_key='' and
        # has_private_key=0 because we don't hold a per-link privkey —
        # both wgflows peer with each other using their respective wg0
        # server keypairs (whatever entrypoint.sh generated). Only
        # public_key + preshared_key matter for kernel handshake;
        # private_key on this row would only be relevant if someone
        # asked us to render a downloadable conf for this peer (which
        # we never do — multisite peers don't have downloadable confs).
        # Same instance-name fallback logic as the creator side: the
        # peer row reflects what the OTHER wgflow calls itself.
        remote_inst = parsed.creator_instance_name or row["name"]
        peer_display_name = f"multisite:{remote_inst}"

        cur = conn.execute(
            """INSERT INTO peers (
                name, public_key, private_key, preshared_key,
                address, enabled, has_private_key, peer_type
            ) VALUES (?, ?, '', ?, ?, 1, 0, 'multisite')""",
            (
                peer_display_name,
                parsed.creator_pubkey,
                parsed.psk,
                f"{parsed.creator_overlay_addr}/32",
            ),
        )
        peer_id = cur.lastrowid

        conn.execute(
            """UPDATE federation_links SET
                peer_id=?,
                importer_privkey=NULL,
                psk=?,
                remote_overlay_addr=?,
                remote_advertised=?,
                remote_endpoint=?,
                remote_instance_name=?,
                status='established',
                last_error=NULL
               WHERE id=?""",
            (peer_id, parsed.psk,
             f"{parsed.creator_overlay_addr}/32",
             ",".join(parsed.creator_advertised),
             parsed.creator_endpoint,
             remote_inst,
             link_id),
        )

    _replay_state_to_kernel()

    fresh = get_db().conn.execute(
        "SELECT * FROM federation_links WHERE id=?", (link_id,)
    ).fetchone()
    return _multisite_link_to_out(get_db().conn, fresh)


@app.put("/api/multisite/links/{link_id}")
def multisite_update_link(link_id: int, body: MultisiteUpdateRequest):
    """Toggle enabled and/or rename. Other fields are not editable —
    keypair/endpoint/advertised changes are delete + re-pair."""
    with get_db().write() as conn:
        row = conn.execute(
            "SELECT * FROM federation_links WHERE id=?", (link_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(404, "link not found")

        sets = []
        params = []
        if body.name is not None:
            new_name = body.name.strip()
            if not new_name:
                raise HTTPException(400, "name cannot be empty")
            dup = conn.execute(
                "SELECT 1 FROM federation_links WHERE name=? AND id != ?",
                (new_name, link_id),
            ).fetchone()
            if dup:
                raise HTTPException(409, f"link '{new_name}' already exists")
            sets.append("name=?")
            params.append(new_name)
            # NOTE: we DO NOT update peers.name here. The peer-row
            # display name reflects what the REMOTE wgflow calls
            # itself (its instance name), not the local link label.
            # Renaming the link locally is a relabel of "what do I
            # call this connection in my panel" — it does not change
            # the identity of the peer at the other end.
        if body.enabled is not None:
            sets.append("enabled=?")
            params.append(1 if body.enabled else 0)
            if row["peer_id"]:
                conn.execute(
                    "UPDATE peers SET enabled=? WHERE id=?",
                    (1 if body.enabled else 0, row["peer_id"]),
                )
        if sets:
            params.append(link_id)
            conn.execute(
                f"UPDATE federation_links SET {', '.join(sets)} WHERE id=?",
                params,
            )

    _replay_state_to_kernel()

    fresh = get_db().conn.execute(
        "SELECT * FROM federation_links WHERE id=?", (link_id,)
    ).fetchone()
    return _multisite_link_to_out(get_db().conn, fresh)


@app.delete("/api/multisite/links/{link_id}", status_code=204)
def multisite_delete_link(link_id: int):
    """Delete a link and its paired peer.

    Local-only — the remote wgflow doesn't know we're forgetting them.
    They'll keep dialing us / accepting our connect until the operator
    deletes the link on their side too.
    """
    with get_db().write() as conn:
        row = conn.execute(
            "SELECT peer_id FROM federation_links WHERE id=?", (link_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(404, "link not found")
        peer_id = row["peer_id"]
        conn.execute("DELETE FROM federation_links WHERE id=?", (link_id,))
        if peer_id:
            conn.execute("DELETE FROM peers WHERE id=?", (peer_id,))

    _replay_state_to_kernel()
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# v4.1: blocklist sources
# ---------------------------------------------------------------------------
# Endpoints:
#   GET    /api/blocklist/status                → counts + last-merged ts
#   GET    /api/blocklist/sources               → list rows
#   POST   /api/blocklist/sources               → add custom URL
#   PUT    /api/blocklist/sources/{id}          → toggle enabled
#   DELETE /api/blocklist/sources/{id}          → remove
#   POST   /api/blocklist/refresh               → fetch all enabled, merge,
#                                                  write file, SIGHUP dnsmasq
#
# All endpoints are panel-auth gated like the rest of the panel API.
# Refresh is operator-triggered only — no scheduling in v4.1; that's
# the v4.2+ backlog. The refresh path is async because fetching
# multiple sources sequentially can take 5-30 seconds and we don't
# want to block the event loop.

def _blocklist_row_to_out(row) -> BlocklistSourceOut:
    return BlocklistSourceOut(
        id=row["id"],
        name=row["name"],
        url=row["url"],
        enabled=bool(row["enabled"]),
        is_preset=bool(row["is_preset"]),
        last_fetched_ts=row["last_fetched_ts"],
        last_entry_count=row["last_entry_count"],
        last_overlap_count=row["last_overlap_count"],
        last_error=row["last_error"],
        created_at=row["created_at"],
    )


@app.get("/api/blocklist/status")
def blocklist_status():
    """Lightweight summary: last merge timestamp + total unique entries.

    Used by the panel header to render "last merged X ago, N entries".
    Does NOT report per-source detail; that's the /sources endpoint.
    """
    conn = get_db().conn
    last_ts = conn.execute(
        "SELECT value FROM network_settings WHERE key='blocklist_last_merged_ts'"
    ).fetchone()
    last_count = conn.execute(
        "SELECT value FROM network_settings WHERE key='blocklist_last_merged_count'"
    ).fetchone()
    enabled_count = conn.execute(
        "SELECT COUNT(*) FROM blocklist_sources WHERE enabled=1"
    ).fetchone()[0]
    total_count = conn.execute(
        "SELECT COUNT(*) FROM blocklist_sources"
    ).fetchone()[0]

    def _to_int_or_none(row):
        if row is None:
            return None
        v = row["value"]
        if not v:
            return None
        try:
            return int(v)
        except ValueError:
            return None

    return {
        "last_merged_ts": _to_int_or_none(last_ts),
        "last_merged_count": _to_int_or_none(last_count),
        "enabled_sources": enabled_count,
        "total_sources": total_count,
    }


@app.get("/api/blocklist/sources", response_model=List[BlocklistSourceOut])
def blocklist_list_sources():
    rows = get_db().conn.execute(
        "SELECT * FROM blocklist_sources ORDER BY id"
    ).fetchall()
    return [_blocklist_row_to_out(r) for r in rows]


@app.post("/api/blocklist/sources", response_model=BlocklistSourceOut,
          status_code=201)
def blocklist_add_source(body: BlocklistSourceCreate):
    """Add an operator-supplied custom blocklist source.

    Validates the URL has http(s) scheme but does NOT fetch it now —
    that happens on the next refresh. This means the operator can add
    several sources without each click triggering a network fetch.
    """
    url = body.url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        raise HTTPException(400, "url must be http:// or https://")

    with get_db().write() as conn:
        # Name uniqueness — surface a clean conflict response.
        if conn.execute(
            "SELECT 1 FROM blocklist_sources WHERE name=?", (body.name,)
        ).fetchone():
            raise HTTPException(409, f"source '{body.name}' already exists")
        cur = conn.execute(
            "INSERT INTO blocklist_sources (name, url, enabled, is_preset) "
            "VALUES (?, ?, 1, 0)",
            (body.name, url),
        )
        new_id = cur.lastrowid
        row = conn.execute(
            "SELECT * FROM blocklist_sources WHERE id=?", (new_id,)
        ).fetchone()
    return _blocklist_row_to_out(row)


@app.put("/api/blocklist/sources/{source_id}",
         response_model=BlocklistSourceOut)
def blocklist_toggle_source(source_id: int, body: BlocklistSourceUpdate):
    with get_db().write() as conn:
        row = conn.execute(
            "SELECT * FROM blocklist_sources WHERE id=?", (source_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(404, "source not found")
        conn.execute(
            "UPDATE blocklist_sources SET enabled=? WHERE id=?",
            (1 if body.enabled else 0, source_id),
        )
        fresh = conn.execute(
            "SELECT * FROM blocklist_sources WHERE id=?", (source_id,)
        ).fetchone()
    return _blocklist_row_to_out(fresh)


@app.delete("/api/blocklist/sources/{source_id}", status_code=204)
def blocklist_delete_source(source_id: int):
    """Remove a source. Allowed for both presets and custom rows —
    presets are pre-populated, not protected."""
    with get_db().write() as conn:
        if conn.execute(
            "SELECT 1 FROM blocklist_sources WHERE id=?", (source_id,)
        ).fetchone() is None:
            raise HTTPException(404, "source not found")
        conn.execute("DELETE FROM blocklist_sources WHERE id=?", (source_id,))
    return Response(status_code=204)


@app.post("/api/blocklist/refresh")
async def blocklist_refresh():
    """Fetch all enabled sources, merge, write file, SIGHUP dnsmasq.

    Synchronous from the operator's perspective — we wait for every
    source to finish before responding. The response carries per-source
    status so the UI can show "stevenblack-ads: 142,891 entries; oisd:
    error HTTP 502; urlhaus: unchanged". Errors on individual sources
    don't fail the whole refresh — we merge whatever fetched
    successfully and the operator sees the partial result.
    """
    import httpx
    async with httpx.AsyncClient(follow_redirects=True) as client:
        # Run the merge inside a write transaction so per-source row
        # updates and the network_settings stamp are atomic.
        # blocklist.refresh_all writes the kernel-side file (the
        # dnsmasq blocklist) outside any transaction — that's
        # intentional, sqlite's transaction has nothing to do with
        # filesystem writes.
        with get_db().write() as conn:
            summary = await blocklist_mod.refresh_all(conn, client)

    return {
        "total_sources_attempted": summary.total_sources_attempted,
        "sources_fetched":         summary.sources_fetched,
        "sources_unchanged":       summary.sources_unchanged,
        "sources_error":           summary.sources_error,
        "merged_unique_count":     summary.merged_unique_count,
        "per_source":              summary.per_source,
    }


# ---------------------------------------------------------------------------
# v4.1.1: upstream WireGuard client connections
# ---------------------------------------------------------------------------
# Endpoints:
#   GET    /api/upstream/connections             → list rows
#   POST   /api/upstream/preview                  → parse + filter, no DB write
#   POST   /api/upstream/connections              → create (after preview confirm)
#   PUT    /api/upstream/connections/{id}         → rename / toggle / override AIPs
#   DELETE /api/upstream/connections/{id}         → tear down + remove
#
# The two-step preview→create flow is deliberate: the operator sees the
# AllowedIPs filter result BEFORE any kernel state changes. Confirms
# trust in the safety filter and lets the operator override the
# applied set if they actually want full-tunnel.

def _upstream_row_to_out(row) -> UpstreamConnectionOut:
    return UpstreamConnectionOut(
        id=row["id"],
        name=row["name"],
        interface_name=row["interface_name"],
        enabled=bool(row["enabled"]),
        local_address=row["local_address"],
        upstream_dns=row["upstream_dns"],
        mtu=row["mtu"],
        remote_endpoint=row["remote_endpoint"],
        remote_allowed_ips_declared=row["remote_allowed_ips_declared"],
        remote_allowed_ips_applied=row["remote_allowed_ips_applied"],
        persistent_keepalive=row["persistent_keepalive"],
        last_handshake_ts=row["last_handshake_ts"],
        last_error=row["last_error"],
        created_at=row["created_at"],
    )


@app.get("/api/upstream/connections",
         response_model=List[UpstreamConnectionOut])
def upstream_list():
    rows = get_db().conn.execute(
        "SELECT * FROM upstream_connections ORDER BY id"
    ).fetchall()
    return [_upstream_row_to_out(r) for r in rows]


@app.post("/api/upstream/preview", response_model=UpstreamPreviewOut)
def upstream_preview(body: UpstreamPreviewRequest):
    """Parse the operator-supplied conf and run the safety filter.

    Returns what WOULD be created if the operator confirms. No DB
    write, no kernel state change. The operator's frontend then
    shows the filter diff (full-tunnel replaced, overlaps stripped)
    before they hit "create."
    """
    try:
        parsed = upstream_mod.parse_wg_conf(body.conf_text)
    except upstream_mod.ConfParseError as e:
        raise HTTPException(400, f"conf parse failed: {e}")

    report = upstream_mod._filter_allowed_ips(parsed.allowed_ips)

    return UpstreamPreviewOut(
        local_address=parsed.address,
        upstream_dns=parsed.dns,
        mtu=parsed.mtu,
        remote_endpoint=parsed.endpoint,
        remote_allowed_ips_declared=parsed.allowed_ips,
        remote_allowed_ips_applied=report.final_applied,
        full_tunnel_replaced=report.full_tunnel_replaced,
        stripped_overlaps=report.stripped_overlaps,
        persistent_keepalive=parsed.persistent_keepalive,
        has_psk=bool(parsed.preshared_key),
    )


@app.post("/api/upstream/connections",
          response_model=UpstreamConnectionOut, status_code=201)
def upstream_create(body: UpstreamCreateRequest):
    """Create an upstream connection from an operator-confirmed preview.

    Re-parses the conf server-side (we don't trust client-side parsing
    even within a session). Applies the AllowedIPs filter unless the
    operator explicitly overrode the applied set in the preview UI.
    Inserts the row, then triggers a replay so the kernel interface
    comes up immediately.

    Failures during kernel bring-up are surfaced as the response's
    `last_error` field and the row is still persisted with enabled=1
    — operator can fix the underlying issue (DNS resolution of the
    endpoint, key format, etc.) and trigger a re-replay via toggle.
    """
    try:
        parsed = upstream_mod.parse_wg_conf(body.conf_text)
    except upstream_mod.ConfParseError as e:
        raise HTTPException(400, f"conf parse failed: {e}")

    if body.allowed_ips_override is not None:
        # Operator explicitly chose the applied set in the preview UI.
        # Trust their choice — they saw the filter recommendation and
        # decided to override. We do still validate that each is a
        # parseable CIDR.
        applied = []
        for cidr in body.allowed_ips_override:
            cidr = cidr.strip()
            if not cidr:
                continue
            # Reject 0.0.0.0/0 even when explicitly overridden — this
            # is a hard safety, not a soft one. Operator who really
            # wants full-tunnel needs to use the routing policy
            # feature when we add it (v4.2+ backlog), not just shove
            # a default route in.
            if cidr in ("0.0.0.0/0", "::/0"):
                raise HTTPException(
                    400,
                    "0.0.0.0/0 is a hard refusal — would route the "
                    "panel through the upstream and lock you out. "
                    "Specify the actual CIDRs you want to route, "
                    "or omit override to use the safe filtered default."
                )
            applied.append(cidr)
        if not applied:
            raise HTTPException(400, "allowed_ips_override is empty")
    else:
        report = upstream_mod._filter_allowed_ips(parsed.allowed_ips)
        applied = report.final_applied

    if not applied:
        raise HTTPException(
            400,
            "after filtering, no AllowedIPs remained — every declared "
            "CIDR overlapped with our protected networks. Override the "
            "applied set if you've audited this."
        )

    declared_str = ",".join(parsed.allowed_ips)
    applied_str  = ",".join(applied)
    dns_str = ",".join(parsed.dns) if parsed.dns else None

    with get_db().write() as conn:
        # Name uniqueness pre-flight.
        if conn.execute(
            "SELECT 1 FROM upstream_connections WHERE name=?", (body.name,)
        ).fetchone():
            raise HTTPException(409, f"upstream '{body.name}' already exists")

        iface = upstream_mod.allocate_interface_name(conn)

        cur = conn.execute(
            """INSERT INTO upstream_connections (
                name, interface_name,
                local_privkey, local_address, upstream_dns, mtu,
                remote_pubkey, remote_psk, remote_endpoint,
                remote_allowed_ips_declared, remote_allowed_ips_applied,
                persistent_keepalive, enabled
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
            (body.name, iface,
             parsed.private_key, parsed.address, dns_str, parsed.mtu,
             parsed.public_key, parsed.preshared_key, parsed.endpoint,
             declared_str, applied_str, parsed.persistent_keepalive),
        )
        new_id = cur.lastrowid

    # Trigger replay so the kernel interface comes up. Errors on this
    # particular upstream get caught inside replay_to_kernel and
    # stamped into last_error, so the response correctly reflects them.
    _replay_state_to_kernel()

    row = get_db().conn.execute(
        "SELECT * FROM upstream_connections WHERE id=?", (new_id,)
    ).fetchone()
    return _upstream_row_to_out(row)


@app.put("/api/upstream/connections/{conn_id}",
         response_model=UpstreamConnectionOut)
def upstream_update(conn_id: int, body: UpstreamUpdateRequest):
    """Rename, toggle enabled, or override applied AllowedIPs.

    Changing the upstream's keys / endpoint / declared AllowedIPs
    requires re-importing — those come from the conf and we don't
    re-parse here.
    """
    with get_db().write() as conn:
        row = conn.execute(
            "SELECT * FROM upstream_connections WHERE id=?", (conn_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(404, "upstream not found")

        sets = []
        params = []

        if body.name is not None:
            # Uniqueness check ignoring this row's own current name.
            dup = conn.execute(
                "SELECT 1 FROM upstream_connections "
                "WHERE name=? AND id != ?",
                (body.name, conn_id),
            ).fetchone()
            if dup:
                raise HTTPException(409, f"upstream '{body.name}' already exists")
            sets.append("name=?")
            params.append(body.name)

        if body.enabled is not None:
            sets.append("enabled=?")
            params.append(1 if body.enabled else 0)

        if body.allowed_ips_override is not None:
            applied = []
            for cidr in body.allowed_ips_override:
                cidr = cidr.strip()
                if not cidr:
                    continue
                if cidr in ("0.0.0.0/0", "::/0"):
                    raise HTTPException(
                        400, "0.0.0.0/0 is a hard refusal — see create endpoint"
                    )
                applied.append(cidr)
            if not applied:
                raise HTTPException(400, "allowed_ips_override is empty")
            sets.append("remote_allowed_ips_applied=?")
            params.append(",".join(applied))

        if sets:
            params.append(conn_id)
            conn.execute(
                f"UPDATE upstream_connections SET {', '.join(sets)} WHERE id=?",
                params,
            )

    # Replay so the kernel reflects the change (including a route
    # update if AllowedIPs changed, or an interface tear-down if
    # disabled).
    _replay_state_to_kernel()

    fresh = get_db().conn.execute(
        "SELECT * FROM upstream_connections WHERE id=?", (conn_id,)
    ).fetchone()
    return _upstream_row_to_out(fresh)


@app.delete("/api/upstream/connections/{conn_id}", status_code=204)
def upstream_delete(conn_id: int):
    """Tear down + remove. Forgetting a row is local-only — the upstream
    has no way to know we're gone (we're a client of theirs)."""
    with get_db().write() as conn:
        row = conn.execute(
            "SELECT interface_name FROM upstream_connections WHERE id=?",
            (conn_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "upstream not found")
        # Tear down the kernel interface explicitly before deleting
        # the row, so even if replay_to_kernel doesn't run for any
        # reason the wgN interface goes away.
        try:
            upstream_mod.tear_down(row["interface_name"])
        except Exception as e:
            print(f"[upstream] tear_down on delete failed: {e}", flush=True)
        conn.execute("DELETE FROM upstream_connections WHERE id=?", (conn_id,))
    _replay_state_to_kernel()
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def index():
    path = Path(__file__).parent / "static" / "index.html"
    return HTMLResponse(path.read_text())


# v4.0.1: small dispatch table for static assets we serve at the root.
# The original `/favicon.svg` handler was per-file; with the addition of
# apple-touch-icon, manifest.json, and the PNG home-screen icons we'd
# rather table-drive than write 5 near-identical handlers. Each entry
# maps a request path to (filename in app/static/, MIME type, cache age).
# If a future file needs different headers, fork the handler — but
# nothing today does.
_STATIC_ROOT_ASSETS = {
    "/favicon.svg":          ("favicon.svg",          "image/svg+xml", 86400),
    "/apple-touch-icon.png": ("apple-touch-icon.png", "image/png",     86400),
    "/icon-192.png":         ("icon-192.png",         "image/png",     86400),
    "/icon-512.png":         ("icon-512.png",         "image/png",     86400),
    "/manifest.json":        ("manifest.json",        "application/manifest+json", 86400),
}


def _serve_static_root(name: str, media_type: str, max_age: int) -> Response:
    """Read a file from app/static/ and return it with cache headers."""
    path = Path(__file__).parent / "static" / name
    return Response(
        content=path.read_bytes(),
        media_type=media_type,
        headers={"Cache-Control": f"public, max-age={max_age}"},
    )


@app.get("/favicon.svg")
def favicon_svg():
    """Bracket-[w] mark, the panel brand distilled to a single character.
    Phosphor on dark by default; the runtime favicon swap in
    static/index.html (refreshFavicon) replaces this with a theme-tracked
    data-URL after JS loads. This static file remains as the pre-JS
    fallback for bookmarks, PWA install snapshots, and browsers that
    fetch the favicon before parsing the document."""
    f, mt, age = _STATIC_ROOT_ASSETS["/favicon.svg"]
    return _serve_static_root(f, mt, age)


@app.get("/apple-touch-icon.png")
def apple_touch_icon():
    """180x180 home-screen icon for iOS. Apple ignores SVG favicons
    and won't render them on the home screen — must be a PNG.
    Generated at build time by scripts/render-favicon-png.py. Theme-
    fixed (phosphor on dark) intentionally: home-screen icons should
    be brand-stable, not tracking the user's panel preferences."""
    f, mt, age = _STATIC_ROOT_ASSETS["/apple-touch-icon.png"]
    return _serve_static_root(f, mt, age)


@app.get("/icon-192.png")
def icon_192():
    """192x192 PNG referenced by manifest.json for Android PWA icon."""
    f, mt, age = _STATIC_ROOT_ASSETS["/icon-192.png"]
    return _serve_static_root(f, mt, age)


@app.get("/icon-512.png")
def icon_512():
    """512x512 PNG referenced by manifest.json. Used for Android PWA
    icon and as the maskable variant (same image; we don't separately
    pad for maskable safe area in v4.0 since the [w] mark already sits
    well within the inner 80% of the canvas)."""
    f, mt, age = _STATIC_ROOT_ASSETS["/icon-512.png"]
    return _serve_static_root(f, mt, age)


@app.get("/manifest.json")
def manifest_json():
    """Web app manifest. Lets Android Chrome surface a richer
    'Add to Home Screen' flow with a proper icon, theme color, and
    standalone display mode. Doesn't enable a one-tap install button
    — that requires a service worker too, which is on the v4.1+
    backlog. iOS Safari ignores most manifest fields; the apple-touch-
    icon and apple-mobile-web-app-* meta tags carry that platform."""
    f, mt, age = _STATIC_ROOT_ASSETS["/manifest.json"]
    return _serve_static_root(f, mt, age)


@app.get("/healthz")
def healthz():
    return JSONResponse({"ok": True})
