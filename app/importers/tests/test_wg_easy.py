"""Exercise the wg-easy parser against synthesized fixtures.

We generate two DBs/JSONs in memory:
  - a clean one (3 peers, all valid)
  - a messy one (one peer with bad pubkey, one with bad address,
    one with newline in name)
and check the parser produces the right ParsedImport for each.
"""
import json
import sys
import sqlite3
import secrets
import base64

sys.path.insert(0, "/home/claude/wgflow-v3.2-fixed")
from app.importers import wg_easy, parsed as P


def fake_wg_key():
    """A 32-random-bytes base64 string. Looks like a wg key but isn't on
    Curve25519. The parser only checks shape, not curve membership."""
    return base64.b64encode(secrets.token_bytes(32)).decode()


# --- Clean v14 fixture ----------------------------------------------------

clean_v14 = {
    "server": {
        "privateKey": fake_wg_key(),
        "publicKey":  fake_wg_key(),
        "address":    "10.8.0.1",
    },
    "clients": {
        "uuid-alice": {
            "name": "alice-laptop",
            "address": "10.8.0.2",
            "privateKey": fake_wg_key(),
            "publicKey":  fake_wg_key(),
            "preSharedKey": fake_wg_key(),
            "enabled": True,
        },
        "uuid-bob": {
            "name": "bob-phone",
            "address": "10.8.0.3",
            "privateKey": fake_wg_key(),
            "publicKey":  fake_wg_key(),
            "preSharedKey": fake_wg_key(),
            "enabled": True,
        },
        "uuid-carol": {
            "name": "carol-server",
            "address": "10.8.0.4",
            "privateKey": fake_wg_key(),
            "publicKey":  fake_wg_key(),
            "preSharedKey": fake_wg_key(),
            "enabled": False,
        },
    },
}

result = wg_easy.parse_v14_json(json.dumps(clean_v14).encode())
assert result.source == P.SOURCE_WG_EASY_V14, result.source
assert result.server_keypair is not None
assert len(result.peers) == 3, len(result.peers)
assert all(p.status == P.STATUS_OK for p in result.peers), [
    (p.name, p.status, p.invalid_reason) for p in result.peers
]
assert any(not p.enabled for p in result.peers), "carol should be disabled"
assert all(p.has_private_key for p in result.peers)
assert result.warnings == []
print(f"[clean v14] OK — {len(result.peers)} peers, server keypair present")


# --- Messy v14 fixture: one bad pubkey, one bad address, one bad name -----

messy_v14 = {
    "server": clean_v14["server"],
    "clients": {
        "uuid-good": {
            "name": "good-peer",
            "address": "10.8.0.10",
            "privateKey": fake_wg_key(),
            "publicKey":  fake_wg_key(),
            "preSharedKey": fake_wg_key(),
            "enabled": True,
        },
        "uuid-badkey": {
            "name": "bad-key",
            "address": "10.8.0.11",
            "privateKey": "not-base64!!",
            "publicKey":  fake_wg_key(),
            "preSharedKey": fake_wg_key(),
        },
        "uuid-badaddr": {
            "name": "bad-addr",
            "address": "not-an-ip",
            "privateKey": fake_wg_key(),
            "publicKey":  fake_wg_key(),
            "preSharedKey": fake_wg_key(),
        },
        "uuid-badname": {
            "name": "evil\nname=injection",
            "address": "10.8.0.13",
            "privateKey": fake_wg_key(),
            "publicKey":  fake_wg_key(),
            "preSharedKey": fake_wg_key(),
        },
    },
}

result = wg_easy.parse_v14_json(json.dumps(messy_v14).encode())
ok_peers = [p for p in result.peers if p.status == P.STATUS_OK]
bad_peers = [p for p in result.peers if p.status == P.STATUS_INVALID]
assert len(ok_peers) == 1, f"expected 1 ok, got {len(ok_peers)}: {[p.name for p in ok_peers]}"
assert len(bad_peers) == 3, f"expected 3 invalid, got {len(bad_peers)}"
print(f"[messy v14] OK — {len(ok_peers)} valid + {len(bad_peers)} invalid:")
for p in bad_peers:
    print(f"           - {p.name!r:30s} → {p.invalid_reason}")


# --- Edge cases -----------------------------------------------------------

# Garbage input.
try:
    wg_easy.parse_v14_json(b"not json at all")
    raise AssertionError("should have raised")
except ValueError as e:
    print(f"[garbage] OK — raised ValueError: {e}")

# Empty clients dict.
result = wg_easy.parse_v14_json(b'{"server": {}, "clients": {}}')
assert result.peers == []
assert result.server_keypair is None  # malformed server entry
print(f"[empty]   OK — 0 peers, server keypair correctly absent")


# --- v15 SQLite fixture ---------------------------------------------------

# Synthesize a v15-shaped DB on disk.
import tempfile
db_path = tempfile.NamedTemporaryFile(suffix=".db", delete=False).name
conn = sqlite3.connect(db_path)
conn.executescript("""
    CREATE TABLE clients (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        publicKey TEXT NOT NULL,
        privateKey TEXT NOT NULL,
        preSharedKey TEXT,
        address TEXT NOT NULL,
        enabled INTEGER DEFAULT 1
    );
    CREATE TABLE settings (
        privateKey TEXT,
        publicKey TEXT,
        address TEXT
    );
""")
conn.execute("INSERT INTO settings VALUES (?, ?, ?)",
             (fake_wg_key(), fake_wg_key(), "10.9.0.1"))
for i, name in enumerate(["dave", "eve", "frank"], start=2):
    conn.execute("INSERT INTO clients (name, publicKey, privateKey, preSharedKey, address, enabled) "
                 "VALUES (?, ?, ?, ?, ?, ?)",
                 (name, fake_wg_key(), fake_wg_key(), fake_wg_key(),
                  f"10.9.0.{i}", 1))
conn.commit()
conn.close()

with open(db_path, "rb") as f:
    db_bytes = f.read()

result = wg_easy.parse_v15_sqlite(db_bytes)
assert result.source == P.SOURCE_WG_EASY_V15
assert result.server_keypair is not None, f"v15 server keypair missing: {result.warnings}"
assert len(result.peers) == 3, f"expected 3, got {len(result.peers)}"
assert all(p.status == P.STATUS_OK for p in result.peers)
print(f"[v15 db] OK — {len(result.peers)} peers, server keypair present")

import os
os.unlink(db_path)
print()
print("ALL WG-EASY PARSER TESTS PASSED")
