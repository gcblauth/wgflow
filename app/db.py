"""SQLite persistence layer.

Schema:
    peers          one row per wireguard peer
    peer_acls      many rows per peer, one per allowed destination entry

We use a thread-local connection because sqlite3 connections are not safe to
share across threads. FastAPI's threadpool dispatches sync endpoints to
worker threads, so we cannot pass a single connection around.
"""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS peers (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL UNIQUE,
    public_key      TEXT NOT NULL UNIQUE,
    private_key     TEXT NOT NULL,          -- stored so we can re-render the client config
    preshared_key   TEXT NOT NULL,
    address         TEXT NOT NULL UNIQUE,   -- e.g. "10.13.13.5/32"
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    enabled         INTEGER NOT NULL DEFAULT 1,
    last_handshake_at INTEGER,              -- unix ts of most recent observed handshake; NULL = never seen
    -- Per-peer DNS preference for generated configs.
    --   NULL  → use the server's default peer_dns (WG_PEER_DNS / auto-derived)
    --   ''    → empty string sentinel: omit DNS line entirely (split-tunnel friendly)
    --   else  → use this string as the DNS value (one or more comma-separated IPs)
    -- Three states deliberately: "unset" vs "explicitly disabled" vs "explicit value".
    dns             TEXT
);

-- Migrate older databases that pre-date the last_handshake_at column.
-- ALTER TABLE ADD COLUMN is idempotent here only via the OR-ignore pattern;
-- we wrap it in PRAGMA introspection because IF NOT EXISTS is not supported.
-- Note: this runs at startup via DB.__init__ → executescript. If the column
-- already exists, the ALTER raises; we swallow it in db.py's init.

CREATE TABLE IF NOT EXISTS peer_acls (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_id     INTEGER NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    cidr        TEXT NOT NULL,         -- always normalised to CIDR form
    port        INTEGER,               -- NULL = any
    proto       TEXT,                  -- NULL = any, else 'tcp' or 'udp'
    action      TEXT NOT NULL DEFAULT 'allow',   -- 'allow' or 'deny'
    UNIQUE(peer_id, cidr, port, proto, action)
);

CREATE INDEX IF NOT EXISTS idx_peer_acls_peer ON peer_acls(peer_id);

-- Aggregated metrics sample, written every 10s. We intentionally store
-- aggregate numbers only (not per-peer rows) to keep storage bounded. With
-- a 10s cadence and 24h retention we have 8640 rows — trivial.
CREATE TABLE IF NOT EXISTS metrics_samples (
    ts              INTEGER PRIMARY KEY,     -- unix timestamp, whole seconds
    rx_bytes_per_s  REAL NOT NULL,           -- sum over all peers
    tx_bytes_per_s  REAL NOT NULL,
    peers_online    INTEGER NOT NULL,
    peers_total     INTEGER NOT NULL,
    cpu_pct         REAL,                    -- host cpu %
    mem_pct         REAL,                    -- host mem %
    load1           REAL                     -- host loadavg(1m)
);

CREATE INDEX IF NOT EXISTS idx_metrics_ts ON metrics_samples(ts);

-- Cumulative traffic counters that survive container restarts. Single-row
-- singleton (id=1). The metrics collector updates this on every tick by:
--   1. Reading the current sum-of-peer counters from `wg show`
--   2. Computing delta = max(0, current_raw - last_raw_total)
--      (negative deltas mean a wg interface reset; treat as fresh start)
--   3. Adding delta to {rx,tx}_total
--   4. Storing current_raw as the new last_raw_total
--
-- The visible "Σ" tile = {rx,tx}_total - {rx,tx}_offset. Operator-triggered
-- "clear counter" sets offset = total → tile reads zero without losing the
-- underlying total (which we still need to detect future deltas).
CREATE TABLE IF NOT EXISTS cumulative_traffic (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    rx_total        INTEGER NOT NULL DEFAULT 0,
    tx_total        INTEGER NOT NULL DEFAULT 0,
    rx_offset       INTEGER NOT NULL DEFAULT 0,
    tx_offset       INTEGER NOT NULL DEFAULT 0,
    last_raw_rx     INTEGER NOT NULL DEFAULT 0,
    last_raw_tx     INTEGER NOT NULL DEFAULT 0,
    updated_at      INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO cumulative_traffic (id) VALUES (1);


-- DNS query log. We deduplicate aggressively to keep this table small:
-- one row per (peer_id, query_name, query_type) per minute. The `count`
-- column tracks how many times that query repeated in that minute, so a
-- chatty client doesn't generate one row per lookup.
CREATE TABLE IF NOT EXISTS dns_queries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,         -- minute-aligned unix timestamp
    peer_id     INTEGER REFERENCES peers(id) ON DELETE SET NULL,
    peer_ip     TEXT NOT NULL,            -- always recorded, even if peer is gone
    query_name  TEXT NOT NULL,
    query_type  TEXT NOT NULL,            -- A, AAAA, PTR, etc.
    answer      TEXT,                     -- joined with ; — NULL if no reply yet
    source      TEXT NOT NULL,            -- 'upstream' | 'cached' | 'blocked' | 'local'
    count       INTEGER NOT NULL DEFAULT 1,
    UNIQUE(ts, peer_ip, query_name, query_type)
);

CREATE INDEX IF NOT EXISTS idx_dns_ts ON dns_queries(ts);
CREATE INDEX IF NOT EXISTS idx_dns_peer ON dns_queries(peer_id, ts);

-- DNS overrides. Each row is one rewrite rule:
--   pattern: a domain like "example.com" or "*.example.com"
--   target:  the IP address dnsmasq returns for matching queries
-- These are loaded into a dnsmasq drop-in conf at /etc/dnsmasq.d/wgflow-overrides.conf
-- and applied on creation/deletion via SIGHUP. They survive restart because the
-- replay logic re-renders the file at startup.
CREATE TABLE IF NOT EXISTS dns_overrides (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern     TEXT NOT NULL UNIQUE,
    target_ip   TEXT NOT NULL,
    note        TEXT,                          -- optional human label, free-form
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Speedtest history. One row per completed test, persisted for graphing.
-- Pruned by age (90 days) on the same schedule as DNS query pruning.
CREATE TABLE IF NOT EXISTS speedtest_history (
    ts          INTEGER PRIMARY KEY,
    ping_ms     REAL NOT NULL,
    jitter_ms   REAL NOT NULL,
    down_mbps   REAL NOT NULL,
    up_mbps     REAL NOT NULL,
    duration_s  REAL NOT NULL,
    error       TEXT,
    endpoint    TEXT                           -- which endpoint this test ran against; NULL for legacy rows
);
CREATE INDEX IF NOT EXISTS idx_speedtest_ts ON speedtest_history(ts);

-- Persisted scheduler interval (minutes) for automatic speedtests.
-- 0 means disabled. Stored as a key/value singleton.
CREATE TABLE IF NOT EXISTS network_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class DB:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._write_lock = threading.Lock()
        # Initialise schema on main thread so it is guaranteed present.
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            self._migrate(conn)
            conn.commit()

    def _migrate(self, conn) -> None:
        """Run schema migrations for databases created by older versions.

        sqlite has no `ALTER TABLE ADD COLUMN IF NOT EXISTS`, so we introspect
        with PRAGMA table_info and add columns conditionally.
        """
        cols = {r[1] for r in conn.execute("PRAGMA table_info(peers)").fetchall()}
        if "last_handshake_at" not in cols:
            conn.execute("ALTER TABLE peers ADD COLUMN last_handshake_at INTEGER")
        if "dns" not in cols:
            # NULL on existing peers → they keep using the server default
            # (preserves legacy behavior). New peers can opt in to a custom
            # DNS or disable it via the empty-string sentinel.
            conn.execute("ALTER TABLE peers ADD COLUMN dns TEXT")

        # peer_acls.action added when deny-rule support landed.
        # Existing rows get DEFAULT 'allow' — fully backward compatible.
        acl_cols = {r[1] for r in conn.execute("PRAGMA table_info(peer_acls)").fetchall()}
        if acl_cols and "action" not in acl_cols:
            conn.execute(
                "ALTER TABLE peer_acls ADD COLUMN action TEXT NOT NULL DEFAULT 'allow'"
            )
        # Backfill any NULL action values that snuck in before the column
        # existed or from the ALTER TABLE add (SQLite doesn't retroactively
        # fill existing rows with the DEFAULT, only new inserts get it).
        conn.execute(
            "UPDATE peer_acls SET action = 'allow' WHERE action IS NULL"
        )

        # speedtest_history.endpoint added when multi-endpoint support landed.
        # Existing rows get NULL → the UI treats them as "unknown endpoint",
        # color-coded as gray, which is honest.
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(speedtest_history)").fetchall()}
            if cols and "endpoint" not in cols:
                conn.execute("ALTER TABLE speedtest_history ADD COLUMN endpoint TEXT")
        except Exception:
            # Table may not exist yet on a brand-new DB — that's fine, the
            # CREATE TABLE statement above already includes the column.
            pass

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    @property
    def conn(self) -> sqlite3.Connection:
        """Per-thread connection."""
        if not hasattr(self._local, "conn"):
            self._local.conn = self._connect()
        return self._local.conn

    @contextmanager
    def write(self) -> Iterator[sqlite3.Connection]:
        """Serialise writes across threads to avoid SQLITE_BUSY under load."""
        with self._write_lock:
            try:
                yield self.conn
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise
