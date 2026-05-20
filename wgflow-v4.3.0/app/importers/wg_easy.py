"""wg-easy importer.

Handles both supported file formats:

  v1-v14: a single `wg0.json` file with `server` and `clients` keys.
          The `server.privateKey/publicKey/address` fields hold the
          server's keypair; the `clients` dict is keyed by UUID with
          per-peer privateKey, publicKey, preSharedKey, address, name,
          enabled.

  v15+:   a SQLite DB at `/etc/wireguard/wg-easy.db`. Their schema split
          server settings into one table and clients into another. The
          v15 setup wizard accepts a v14 wg0.json for migration, so most
          v15 operators have actually re-emitted that JSON; we still
          accept the .db file directly because it's what's on disk.

Both paths produce the same `ParsedImport`, with `source` set to the
appropriate constant. The dispatcher in `detector.py` decides which
function to call based on file magic.
"""
from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path
from typing import Tuple

from . import parsed as P


def parse_v14_json(content: bytes) -> P.ParsedImport:
    """Parse a wg-easy v1-v14 wg0.json blob.

    The schema we care about (others fields ignored — wg-easy stores
    PostUp/PostDown there too but those are wgflow's job to manage):

        {
          "server": {
            "privateKey": "...",
            "publicKey":  "...",
            "address":    "10.8.0.1"
          },
          "clients": {
            "<uuid>": {
              "name":         "alice-laptop",
              "address":      "10.8.0.2",
              "privateKey":   "...",
              "publicKey":    "...",
              "preSharedKey": "...",
              "enabled":      true
            },
            ...
          }
        }
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise ValueError(f"wg0.json is not valid JSON: {e}") from None

    if not isinstance(data, dict):
        raise ValueError("wg0.json root must be an object")

    server_kp = _extract_server_keypair_v14(data)
    out = P.ParsedImport(source=P.SOURCE_WG_EASY_V14, server_keypair=server_kp)

    clients = data.get("clients")
    if not isinstance(clients, dict):
        out.warnings.append("no 'clients' object found in wg0.json")
        return out

    for client_id, client in clients.items():
        if not isinstance(client, dict):
            out.warnings.append(f"client {client_id!r} is not an object — skipped")
            continue
        peer = _parse_v14_client(client_id, client)
        if peer is not None:
            out.peers.append(peer)

    return out


def parse_v15_sqlite(content: bytes) -> P.ParsedImport:
    """Parse a wg-easy v15 wg-easy.db SQLite blob.

    We don't import sqlite3 against the bytes directly — sqlite3 needs a
    file path. Write to a temp file, open read-only, query the tables
    we care about, then delete the temp.

    The v15 schema isn't yet fully stable in upstream (they've been
    iterating), so the parser is defensive: list available tables, look
    for a clients-shaped one and a server-shaped one, fail with a clear
    message if neither is present.
    """
    out = P.ParsedImport(source=P.SOURCE_WG_EASY_V15, server_keypair=None)

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        tf.write(content)
        tf.flush()
        tmp_path = Path(tf.name)

    try:
        # Read-only URI: never modify the operator's source DB even by
        # accident (e.g. a bad query holding a lock that triggers WAL
        # checkpoint on close).
        uri = f"file:{tmp_path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        try:
            tables = {
                r["name"]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }

            # Server keypair extraction. v15 has used a few names across
            # iterations; try them in order. If none match, leave
            # server_keypair=None and let the UI hide the "adopt key"
            # toggle.
            server_kp = _extract_server_keypair_v15(conn, tables)
            if server_kp is not None:
                out.server_keypair = server_kp
            else:
                out.warnings.append(
                    "couldn't locate the server keypair in this v15 DB — "
                    "the 'adopt server keypair' option will be unavailable"
                )

            # Clients table. Same defensive lookup.
            client_table = _find_client_table(conn, tables)
            if client_table is None:
                out.warnings.append(
                    "couldn't locate a clients table in this v15 DB; no peers imported"
                )
                return out

            for row in conn.execute(f"SELECT * FROM {client_table}"):
                peer = _parse_v15_client(dict(row))
                if peer is not None:
                    out.peers.append(peer)
        finally:
            conn.close()
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            # Already gone or permission issue — not worth crashing the
            # import for. The OS will clean up /tmp eventually.
            pass

    return out


# --- v14 helpers ----------------------------------------------------------


def _extract_server_keypair_v14(data: dict) -> P.ParsedKeyPair | None:
    server = data.get("server")
    if not isinstance(server, dict):
        return None
    priv = server.get("privateKey")
    pub = server.get("publicKey")
    if not isinstance(priv, str) or not isinstance(pub, str):
        return None
    try:
        priv = P.validate_wg_key(priv, label="server.privateKey")
        pub = P.validate_wg_key(pub, label="server.publicKey")
    except ValueError:
        # Don't let a malformed server keypair abort the whole import —
        # the operator may still want to migrate the peers and rotate
        # keys themselves later.
        return None
    return P.ParsedKeyPair(private_key=priv, public_key=pub)


def _parse_v14_client(client_id: str, client: dict) -> P.ParsedPeer | None:
    """Parse a single wg-easy v14 client entry into a ParsedPeer.

    Returns None for fundamentally unusable rows (no name AND no address
    — nothing to import). Returns a ParsedPeer with status=invalid for
    rows that have a name but bad fields, so the operator can see what
    was rejected.
    """
    raw_name = client.get("name") or client_id
    if not isinstance(raw_name, str):
        return None

    peer = P.ParsedPeer(
        name="", public_key="", private_key="", preshared_key="",
        address="", has_private_key=True,
        notes=f"imported from wg-easy v14 (id={client_id})",
    )
    try:
        peer.name = P.validate_peer_name(raw_name)
        peer.public_key = P.validate_wg_key(
            str(client.get("publicKey", "")), label=f"{raw_name}.publicKey"
        )
        peer.private_key = P.validate_wg_key(
            str(client.get("privateKey", "")), label=f"{raw_name}.privateKey"
        )
        # PSK is optional in WireGuard. wg-easy generates one for every
        # client by default, but defensive: missing PSK -> generate one
        # at commit time. Empty-string sentinel for "needs generation".
        psk_raw = client.get("preSharedKey")
        if isinstance(psk_raw, str) and psk_raw.strip():
            peer.preshared_key = P.validate_wg_key(
                psk_raw, label=f"{raw_name}.preSharedKey"
            )
        else:
            peer.preshared_key = ""
        peer.address = P.validate_address(str(client.get("address", "")))
        peer.enabled = bool(client.get("enabled", True))
    except ValueError as e:
        peer.status = P.STATUS_INVALID
        peer.invalid_reason = str(e)
    return peer


# --- v15 helpers ----------------------------------------------------------
# v15's schema has shifted across point releases. We try a few known
# table/column names rather than hard-coding one. If upstream introduces
# a layout we don't recognize, the parser surfaces "couldn't locate" and
# the operator can fall back to the v14 export-to-json path.


# Table names we've seen in the wild for the clients-list table.
# Listed most-recent-first; first match wins.
_V15_CLIENT_TABLES = ("clients", "client", "wireguard_clients", "peers")

# Server-settings tables we've seen.
_V15_SERVER_TABLES = ("settings", "server", "config", "wireguard_settings")


def _find_client_table(conn: sqlite3.Connection, tables: set) -> str | None:
    for candidate in _V15_CLIENT_TABLES:
        if candidate in tables:
            # Sanity check: must have at least the keys we need.
            cols = {r["name"] for r in conn.execute(f"PRAGMA table_info({candidate})")}
            if {"name", "publicKey", "privateKey", "address"}.issubset(cols) or \
               {"name", "public_key", "private_key", "address"}.issubset(cols):
                return candidate
    return None


def _extract_server_keypair_v15(
    conn: sqlite3.Connection, tables: set
) -> P.ParsedKeyPair | None:
    """Best-effort server keypair extraction from a v15 DB.

    We try a few approaches in order:
      1. A row in a settings table with privateKey/publicKey columns
      2. A key/value-shaped table where keys 'privateKey' and 'publicKey'
         hold the server's keys

    Returns None if we can't find them. The operator gets a warning in
    the UI and the "adopt server keypair" toggle is hidden.
    """
    for candidate in _V15_SERVER_TABLES:
        if candidate not in tables:
            continue
        cols = {r["name"] for r in conn.execute(f"PRAGMA table_info({candidate})")}
        # Path 1: row-shaped settings table.
        if {"privateKey", "publicKey"}.issubset(cols):
            row = conn.execute(
                f"SELECT privateKey, publicKey FROM {candidate} LIMIT 1"
            ).fetchone()
            if row and row["privateKey"] and row["publicKey"]:
                try:
                    return P.ParsedKeyPair(
                        private_key=P.validate_wg_key(
                            row["privateKey"], label="server.privateKey"
                        ),
                        public_key=P.validate_wg_key(
                            row["publicKey"], label="server.publicKey"
                        ),
                    )
                except ValueError:
                    return None
        # Path 2: key/value table with 'key' and 'value' columns.
        if {"key", "value"}.issubset(cols):
            kv = {
                r["key"]: r["value"]
                for r in conn.execute(f"SELECT key, value FROM {candidate}")
            }
            priv = kv.get("privateKey") or kv.get("private_key")
            pub = kv.get("publicKey") or kv.get("public_key")
            if priv and pub:
                try:
                    return P.ParsedKeyPair(
                        private_key=P.validate_wg_key(priv, label="server.privateKey"),
                        public_key=P.validate_wg_key(pub, label="server.publicKey"),
                    )
                except ValueError:
                    return None
    return None


def _parse_v15_client(row: dict) -> P.ParsedPeer | None:
    """One v15 client row → one ParsedPeer.

    v15 has used both camelCase and snake_case column names depending on
    point release; tolerate both.
    """
    def col(*names):
        for n in names:
            if n in row and row[n] is not None:
                return row[n]
        return None

    name = col("name")
    if not isinstance(name, str) or not name.strip():
        return None

    peer = P.ParsedPeer(
        name="", public_key="", private_key="", preshared_key="",
        address="", has_private_key=True,
        notes="imported from wg-easy v15",
    )
    try:
        peer.name = P.validate_peer_name(name)
        peer.public_key = P.validate_wg_key(
            str(col("publicKey", "public_key") or ""),
            label=f"{name}.publicKey",
        )
        peer.private_key = P.validate_wg_key(
            str(col("privateKey", "private_key") or ""),
            label=f"{name}.privateKey",
        )
        psk_raw = col("preSharedKey", "preshared_key", "pre_shared_key")
        if isinstance(psk_raw, str) and psk_raw.strip():
            peer.preshared_key = P.validate_wg_key(
                psk_raw, label=f"{name}.preSharedKey"
            )
        else:
            peer.preshared_key = ""
        peer.address = P.validate_address(str(col("address", "ipv4Address") or ""))
        peer.enabled = bool(col("enabled") if col("enabled") is not None else True)
    except ValueError as e:
        peer.status = P.STATUS_INVALID
        peer.invalid_reason = str(e)
    return peer
