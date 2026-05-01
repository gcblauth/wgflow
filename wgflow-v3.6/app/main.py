"""FastAPI application for wgflow."""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sqlite3
import tempfile
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Optional

from fastapi import (
    FastAPI,
    File,
    HTTPException,
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
        "SELECT cidr, port, proto, action, comment FROM peer_acls WHERE peer_id = ? ORDER BY id",
        (row["id"],),
    ).fetchall()
    entries = [
        acl_mod.ACLEntry(
            cidr=r["cidr"],
            port=r["port"],
            proto=r["proto"],
            action=r["action"] if (r["action"] in ("allow", "deny")) else "allow",
            # Comment may be NULL on rows from pre-3.6 DBs that haven't
            # been touched since the column was added. Coerce to "" so
            # downstream code (renderers, str()) doesn't have to handle
            # None separately.
            comment=r["comment"] or "",
        )
        for r in acl_rows
    ]
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
    )


def _load_all_peers_for_sync() -> List[wg.PeerConfig]:
    conn = get_db().conn
    rows = conn.execute(
        "SELECT name, public_key, preshared_key, address FROM peers WHERE enabled = 1"
    ).fetchall()
    return [
        wg.PeerConfig(
            name=r["name"],
            public_key=r["public_key"],
            preshared_key=r["preshared_key"],
            address=r["address"],
        )
        for r in rows
    ]


def _load_peer_acls(peer_id: int) -> List[acl_mod.ACLEntry]:
    rows = get_db().conn.execute(
        "SELECT cidr, port, proto, action, comment FROM peer_acls WHERE peer_id = ? ORDER BY id",
        (peer_id,),
    ).fetchall()
    return [
        acl_mod.ACLEntry(
            cidr=r["cidr"],
            port=r["port"],
            proto=r["proto"],
            # action can be NULL in pre-migration rows (SQLite ALTER TABLE
            # ADD COLUMN only sets DEFAULT for new inserts, not existing rows).
            # Treat NULL as "allow" to preserve the row's original intent.
            action=r["action"] if (r["action"] in ("allow", "deny")) else "allow",
            comment=r["comment"] or "",
        )
        for r in rows
    ]


def _replay_state_to_kernel() -> None:
    """On startup, push the DB state to wg + iptables.

    WireGuard state is volatile across container restarts; iptables chains we
    create are also volatile. We must rebuild both from sqlite.
    """
    ipt.ensure_base_chain()

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
    if path in auth.PUBLIC_PATHS or path == "/" or path.startswith("/static/"):
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
            conn.execute(
                "INSERT INTO peer_acls (peer_id, cidr, port, proto, action, comment) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (peer_id, e.cidr, e.port, e.proto, e.action, e.comment or None),
            )
    return peer_id


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
    conn = get_db().conn
    rows = conn.execute("SELECT * FROM peers ORDER BY id").fetchall()
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
    row = conn.execute("SELECT address FROM peers WHERE id = ?", (peer_id,)).fetchone()
    if not row:
        raise HTTPException(404, "peer not found")

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
    if not conn.execute("SELECT 1 FROM peers WHERE id = ?", (peer_id,)).fetchone():
        raise HTTPException(404, "peer not found")

    try:
        entries = [acl_mod.parse_entry(e.raw) for e in body.acl]
    except acl_mod.ACLParseError as e:
        raise HTTPException(422, str(e))

    with get_db().write() as c:
        c.execute("DELETE FROM peer_acls WHERE peer_id = ?", (peer_id,))
        for e in entries:
            c.execute(
                "INSERT INTO peer_acls (peer_id, cidr, port, proto, action, comment) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (peer_id, e.cidr, e.port, e.proto, e.action, e.comment or None),
            )

    peer_row = conn.execute("SELECT address FROM peers WHERE id = ?", (peer_id,)).fetchone()
    ipt.apply_peer_acls(peer_id, entries,
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
def peer_install_script(peer_id: int, dns: Optional[str] = None):
    """Return a Windows installer for this peer as an AES-256 encrypted zip.

    The zip contains a single .ps1 with the WireGuard config embedded as
    base64 — recipient extracts and runs, no .conf needed alongside.

    Optional `?dns=` query param overrides the DNS in the bundled config
    (same semantics as /config endpoint).

    The passphrase is generated fresh on every download (8 Diceware words,
    ~60 bits entropy) and returned in the X-WGFlow-Passphrase response
    header so the UI can show it to the operator. Operator communicates
    the passphrase to the recipient via a separate channel (SMS, Signal,
    in person).

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

    passphrase = installer_script.generate_passphrase()
    zip_bytes, _inner = installer_script.package_install_zip(
        safe_name, ps1_text, passphrase,
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
            "X-WGFlow-Passphrase": passphrase,
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


@app.get("/api/server/panel-order")
def get_panel_order():
    """Read panel order. Empty list = default UI order.

    Returns: {"order": ["panel-id-1", "panel-id-2", ...]}
    """
    conn = get_db().conn
    row = conn.execute(
        "SELECT value FROM network_settings WHERE key = 'panel_order'"
    ).fetchone()
    raw = row["value"] if row else ""
    if not raw:
        return {"order": []}
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return {"order": [str(x) for x in parsed]}
    except (json.JSONDecodeError, TypeError, ValueError):
        pass
    return {"order": []}


@app.put("/api/server/panel-order")
def set_panel_order(body: PanelOrder):
    """Persist panel order (drag-to-reorder result).

    The body's `order` is a list of panel-id strings (matching the
    `data-panel-id` attribute on each reorderable panel in the DOM).
    Unknown ids are stored as-is; the UI ignores them on render. This
    keeps the schema forward-compatible with future panel additions —
    an old client that doesn't know about a new panel-id won't break
    when it sees one.

    Empty list = reset to default. Stored as JSON in network_settings.
    """
    # Light validation: accept up to 32 ids, each ≤ 64 chars. Defensive
    # against an attacker-controlled payload bloating the DB row.
    if len(body.order) > 32:
        raise HTTPException(422, "too many panel ids (max 32)")
    for pid in body.order:
        if not isinstance(pid, str) or len(pid) > 64:
            raise HTTPException(422, "panel ids must be strings ≤ 64 chars")

    serialized = json.dumps(body.order)
    with get_db().write() as conn:
        conn.execute(
            """INSERT INTO network_settings (key, value) VALUES ('panel_order', ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
            (serialized,),
        )
    return get_panel_order()


# ---------------------------------------------------------------------------
# Panels minimized state (v3.6 in-place patch)
# ---------------------------------------------------------------------------
# Maps panel-id → bool. true = collapsed to header, false/missing = expanded.
# Persists per-instance in network_settings.panels_minimized as JSON.
# Same forward-compat policy as panel_order: unknown ids are ignored at
# render time so old clients don't break when seeing new panel-ids.

@app.get("/api/server/panels-minimized")
def get_panels_minimized():
    """Read minimized state.

    Returns: {"minimized": {"panel-id": true, ...}}
    """
    conn = get_db().conn
    row = conn.execute(
        "SELECT value FROM network_settings WHERE key = 'panels_minimized'"
    ).fetchone()
    raw = row["value"] if row else ""
    if not raw:
        return {"minimized": {}}
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            # Filter to bool values only — defensive against malformed
            # payloads (e.g. someone hand-edits the DB and writes strings).
            return {"minimized": {
                str(k): bool(v) for k, v in parsed.items()
                if isinstance(k, str)
            }}
    except (json.JSONDecodeError, TypeError, ValueError):
        pass
    return {"minimized": {}}


@app.put("/api/server/panels-minimized")
def set_panels_minimized(body: dict):
    """Persist minimized state.

    Accepts {"minimized": {...}}. We deliberately use a plain dict for
    the body (not a Pydantic model) because the keys are arbitrary
    panel-ids that aren't fixed at API design time — Pydantic would
    require a model with explicit fields.

    Light validation: max 32 entries, keys ≤ 64 chars (matches the
    panel_order limit so an attacker can't bloat the DB row via either
    endpoint).
    """
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

    serialized = json.dumps(cleaned) if cleaned else ""
    with get_db().write() as conn:
        conn.execute(
            """INSERT INTO network_settings (key, value) VALUES ('panels_minimized', ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
            (serialized,),
        )
    return get_panels_minimized()


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
# UI
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def index():
    path = Path(__file__).parent / "static" / "index.html"
    return HTMLResponse(path.read_text())


@app.get("/healthz")
def healthz():
    return JSONResponse({"ok": True})
