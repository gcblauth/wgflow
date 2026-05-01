"""SQLite persistence layer.

Schema:
    peers          one row per wireguard peer
    peer_acls      many rows per peer, one per allowed destination entry

We use a thread-local connection because sqlite3 connections are not safe to
share across threads. FastAPI's threadpool dispatches sync endpoints to
worker threads, so we cannot pass a single connection around.
"""
from __future__ import annotations

import re
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS peers (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL UNIQUE,
    public_key      TEXT NOT NULL UNIQUE,
    private_key     TEXT NOT NULL,          -- stored so we can re-render the client config; "" for bare-WG imports
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
    dns             TEXT,
    -- True (1) for normal wgflow-managed peers — wgflow holds their privkey
    -- and can render a downloadable client config. False (0) for peers
    -- imported from bare-WG sources where only the public key is known
    -- (operator's clients have the privkeys; wgflow can't re-issue configs).
    -- The UI gates the "download config" button on this flag.
    has_private_key INTEGER NOT NULL DEFAULT 1
);

-- Migrate older databases that pre-date the last_handshake_at column.
-- ALTER TABLE ADD COLUMN is idempotent here only via the OR-ignore pattern;
-- we wrap it in PRAGMA introspection because IF NOT EXISTS is not supported.
-- Note: this runs at startup via DB.__init__ → executescript. If the column
-- already exists, the ALTER raises; we swallow it in db.py's init.

CREATE TABLE IF NOT EXISTS peer_acls (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_id     INTEGER NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    cidr        TEXT,                  -- NULL when this is an alias reference
    port        INTEGER,               -- NULL = any
    proto       TEXT,                  -- NULL = any, else 'tcp' or 'udp'
    action      TEXT NOT NULL DEFAULT 'allow',   -- 'allow' or 'deny'
    comment     TEXT,                  -- v3.6: optional human label, ≤ 80 chars
    alias_ref   TEXT,                  -- v3.7: alias name when this row is a ref;
                                       --        cidr/port/proto are NULL in that case
    -- Source-order preservation: the operator's textbox order matters
    -- because deny rules emit BEFORE the catchall ACCEPT in iptables.
    -- Use insertion order (id ASC) on read; no separate column needed.
    UNIQUE(peer_id, cidr, port, proto, action, alias_ref)
);

CREATE INDEX IF NOT EXISTS idx_peer_acls_peer ON peer_acls(peer_id);

-- ACL aliases (v3.7).
--
-- Named groups of ACL entries. Operator defines `@home_lan = 192.168.0.0/16,
-- 192.168.1.0/24` once; peers reference it as `@home_lan` (or `!@home_lan`
-- to deny) in their normal ACL list. At apply time, the alias name is
-- expanded into its constituent entries and emitted as individual iptables
-- rules.
--
-- Constraints:
--   - Aliases are allow-only (no `!` prefix inside the alias body). The
--     deny prefix applies to alias *usage*, not to entries within. This
--     keeps iptables rule generation simple and avoids chain-target
--     collision corner cases.
--   - Aliases do not nest. Cannot reference @other_alias inside a body.
--   - Names: lowercase letters, digits, underscores, 1-32 chars. The
--     leading @ is implicit (not stored in the name column).
--   - Body stored as a JSON array of {cidr, port, proto} objects. We
--     don't store comments inside aliases (they're a peer-rule concept
--     only).
--
-- Deletion is blocked while any peer references the alias. The
-- alias_peer_refs view (below) makes the reference count cheap to
-- query.
CREATE TABLE IF NOT EXISTS acl_aliases (
    name        TEXT PRIMARY KEY,        -- without leading @
    body        TEXT NOT NULL,           -- JSON array of {cidr, port, proto}
    description TEXT,                    -- optional human label
    created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Reference index: which peers' ACL bodies mention which alias.
-- Refreshed atomically when a peer's ACL is saved. Lets us quickly
-- answer "is this alias referenced anywhere" before allowing delete,
-- without scanning every peer's ACL text.
CREATE TABLE IF NOT EXISTS acl_alias_refs (
    alias_name  TEXT NOT NULL REFERENCES acl_aliases(name) ON DELETE CASCADE,
    peer_id     INTEGER NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    PRIMARY KEY (alias_name, peer_id)
);

CREATE INDEX IF NOT EXISTS idx_acl_alias_refs_alias ON acl_alias_refs(alias_name);
CREATE INDEX IF NOT EXISTS idx_acl_alias_refs_peer  ON acl_alias_refs(peer_id);


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
        if "has_private_key" not in cols:
            # Added in 3.3 alongside the import feature. Existing peers
            # all had wgflow-generated keypairs, so backfill to 1 (true).
            # Imports from bare-WG insert with 0 to skip config-download.
            conn.execute(
                "ALTER TABLE peers ADD COLUMN has_private_key INTEGER NOT NULL DEFAULT 1"
            )

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

        # peer_acls.comment added in v3.6 — optional human label per ACL
        # entry. NULL on existing rows; the UI treats NULL == "" for
        # display purposes.
        if acl_cols and "comment" not in acl_cols:
            conn.execute("ALTER TABLE peer_acls ADD COLUMN comment TEXT")

        # v3.7: alias_ref column on peer_acls. NULL on existing rows
        # (which are all literal CIDR rules); populated when the peer's
        # ACL contains an `@alias_name` reference.
        if acl_cols and "alias_ref" not in acl_cols:
            conn.execute("ALTER TABLE peer_acls ADD COLUMN alias_ref TEXT")

        # v3.7: drop the NOT NULL constraint on cidr.
        #
        # Original v3.5 schema declared `cidr TEXT NOT NULL`. For alias
        # references we want cidr to be NULL (the alias_ref column tells
        # the loader to look up the body elsewhere). SQLite has no
        # ALTER COLUMN, so we have to rebuild the table.
        #
        # Detection: look at the table's CREATE statement and check
        # whether `cidr TEXT NOT NULL` appears. Fresh installs already
        # have the new schema (CREATE TABLE IF NOT EXISTS at the top of
        # this module declares cidr TEXT, no NOT NULL), so the rebuild
        # is a no-op for them.
        sql_row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='peer_acls'"
        ).fetchone()
        sql_text = (sql_row[0] if sql_row else "") or ""
        # Use a tolerant match — different SQLite versions render
        # whitespace slightly differently. Look for "cidr" near "NOT NULL"
        # before any other column declaration.
        needs_rebuild = bool(
            sql_text and
            re.search(r"\bcidr\s+TEXT\s+NOT\s+NULL", sql_text, re.IGNORECASE)
        )
        # Also rebuild if the UNIQUE constraint doesn't include alias_ref —
        # without it, multiple alias-ref rows collide on (peer, NULL, NULL,
        # NULL, action). Note SQLite treats NULL as distinct in UNIQUE,
        # so duplicate alias_ref values would be allowed accidentally if
        # we left the old constraint. The new schema's UNIQUE includes
        # alias_ref so this is a one-time fix.
        if not needs_rebuild and sql_text and "alias_ref" not in sql_text.split("UNIQUE", 1)[-1]:
            needs_rebuild = True

        if needs_rebuild:
            # Rebuild dance: create new table, copy rows, drop old,
            # rename. Wrap in a savepoint so a failure mid-way leaves
            # the DB in a consistent state.
            conn.execute("SAVEPOINT peer_acls_rebuild")
            try:
                conn.execute("""
                    CREATE TABLE peer_acls__new (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        peer_id     INTEGER NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
                        cidr        TEXT,
                        port        INTEGER,
                        proto       TEXT,
                        action      TEXT NOT NULL DEFAULT 'allow',
                        comment     TEXT,
                        alias_ref   TEXT,
                        UNIQUE(peer_id, cidr, port, proto, action, alias_ref)
                    )
                """)
                # Copy preserving id (and therefore source order, since
                # callers SELECT ORDER BY id). The old table may not have
                # had alias_ref/comment columns; defensive defaults.
                old_cols = {r[1] for r in conn.execute(
                    "PRAGMA table_info(peer_acls)"
                ).fetchall()}
                select_alias_ref = "alias_ref" if "alias_ref" in old_cols else "NULL"
                select_comment   = "comment"   if "comment"   in old_cols else "NULL"
                conn.execute(f"""
                    INSERT INTO peer_acls__new
                        (id, peer_id, cidr, port, proto, action, comment, alias_ref)
                    SELECT id, peer_id, cidr, port, proto, action,
                           {select_comment}, {select_alias_ref}
                    FROM peer_acls
                """)
                conn.execute("DROP TABLE peer_acls")
                conn.execute("ALTER TABLE peer_acls__new RENAME TO peer_acls")
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_peer_acls_peer "
                    "ON peer_acls(peer_id)"
                )
                conn.execute("RELEASE SAVEPOINT peer_acls_rebuild")
            except Exception:
                conn.execute("ROLLBACK TO SAVEPOINT peer_acls_rebuild")
                conn.execute("RELEASE SAVEPOINT peer_acls_rebuild")
                raise

        # The acl_aliases and acl_alias_refs tables are created via the
        # same schema-execution at startup that creates peer_acls. We
        # don't need explicit migration because both are CREATE TABLE
        # IF NOT EXISTS — fresh and existing DBs converge to the same
        # final schema.

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

        # Persist a unique instance_id for telemetry tracking.
        row = conn.execute("SELECT value FROM network_settings WHERE key = 'instance_id'").fetchone()
        if not row:
            conn.execute(
                "INSERT INTO network_settings (key, value) VALUES ('instance_id', ?)",
                (str(uuid.uuid4()),)
            )

        # Seed migration_enabled on first install. The env var
        # WGFLOW_MIGRATION_DEFAULT_ENABLED only acts as the seed value —
        # once this row exists, runtime UI/API toggles are authoritative
        # and the env var is ignored on subsequent restarts. This matches
        # how `auto_interval_min` works: env var seeds defaults, DB wins
        # at runtime, so an operator who toggles the UI doesn't have it
        # silently overwritten by their .env on the next `docker compose up`.
        row = conn.execute(
            "SELECT value FROM network_settings WHERE key = 'migration_enabled'"
        ).fetchone()
        if not row:
            from .config import SETTINGS  # local import to avoid cycles
            initial = "1" if SETTINGS.migration_default_enabled else "0"
            conn.execute(
                "INSERT INTO network_settings (key, value) VALUES ('migration_enabled', ?)",
                (initial,)
            )

        # Instance identity (added 3.5). `instance_name` is a free-form
        # display string shown in the header next to the wgflow logo —
        # default empty so existing installs upgrade silently with no
        # name shown. `instance_color_theme` selects one of five
        # phosphor-CRT-inspired palettes; default 'phosphor' matches
        # the historical accent green so the upgrade is visually identical.
        for key, default in (("instance_name", ""),
                             ("instance_color_theme", "phosphor")):
            row = conn.execute(
                "SELECT value FROM network_settings WHERE key = ?", (key,)
            ).fetchone()
            if not row:
                conn.execute(
                    "INSERT INTO network_settings (key, value) VALUES (?, ?)",
                    (key, default),
                )

        # v3.6 additions:
        # - client_mtu: when set, generated peer .conf files include
        #   `MTU = <value>` under [Interface]. Empty string = let the
        #   client kernel pick the default (typically 1420). Values are
        #   stored as strings (we validate in the API endpoint, not DB).
        # - mss_clamp: when "1", install a TCPMSS --clamp-mss-to-pmtu rule
        #   in iptables mangle/FORWARD. Helps TCP black-hole problems on
        #   paths with broken PMTUD. "0" or empty = no rule.
        # - panel_order: JSON array of panel-id strings setting the
        #   vertical order of dashboard panels. Empty string = default
        #   order (defined in the frontend). When non-empty, applied at
        #   page load to override DOM source order.
        # - panels_minimized: JSON object mapping panel-id → bool. true
        #   means the panel is currently collapsed to its header. Empty
        #   string = nothing minimized. Added in v3.6 in-place patch.
        # - polling_interval_ms: integer in milliseconds, applied to
        #   ACL stats, DNS recent, iptables modal, and similar polling
        #   loops. Default "3000" (3 seconds). Range 1000..6000 enforced
        #   in the API. Added in v3.6 in-place patch.
        # - clipboard_timeout_sec: integer seconds, how long after a
        #   sensitive value (private key, peer config) is written to
        #   the clipboard before we attempt to overwrite it with a
        #   space. 0 = disabled. 1..300 enforced. Default "30". Added
        #   in v3.7. Best-effort: browsers may reject the overwrite if
        #   it doesn't have a user gesture.
        for key, default in (("client_mtu", ""),
                             ("mss_clamp",  "0"),
                             ("panel_order", ""),
                             ("panels_minimized", ""),
                             ("polling_interval_ms", "3000"),
                             ("clipboard_timeout_sec", "30"),
                             # v3.8: per-form-factor saved layouts. The
                             # existing panel_order/panels_minimized are
                             # used as the desktop layout (unchanged for
                             # backwards compat); these new keys hold the
                             # mobile-specific layout. Frontend chooses
                             # which to load/save based on viewport
                             # width + an optional manual toggle.
                             ("panel_order_mobile", ""),
                             ("panels_minimized_mobile", "")):
            row = conn.execute(
                "SELECT value FROM network_settings WHERE key = ?", (key,)
            ).fetchone()
            if not row:
                conn.execute(
                    "INSERT INTO network_settings (key, value) VALUES (?, ?)",
                    (key, default),
                )

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
