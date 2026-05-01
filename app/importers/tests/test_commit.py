"""Phase-2 integration tests: status computation + commit dry-run.

We don't actually exercise the wg/iptables side of `apply()` here
(those need a real wgflow runtime). Instead we test the pieces that
matter: status computation against a fake DB, and the preview store
TTL behavior.
"""
import base64
import ipaddress
import secrets
import sqlite3
import sys
import time

sys.path.insert(0, "/home/claude/wgflow-v3.2-fixed")

from app.importers import parsed as P, preview_store, serialize
from app.importers.commit import compute_statuses, _pick_free_address


def k():
    return base64.b64encode(secrets.token_bytes(32)).decode()


def make_db():
    """Fake wgflow DB with three existing peers."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE peers (
            id INTEGER PRIMARY KEY,
            name TEXT, public_key TEXT, address TEXT
        );
    """)
    conn.execute("INSERT INTO peers (name, public_key, address) VALUES (?, ?, ?)",
                 ("existing-alice", "EXISTING_PUBKEY_AAA=", "10.13.13.2/32"))
    conn.execute("INSERT INTO peers (name, public_key, address) VALUES (?, ?, ?)",
                 ("existing-bob",   "EXISTING_PUBKEY_BBB=", "10.13.13.3/32"))
    conn.execute("INSERT INTO peers (name, public_key, address) VALUES (?, ?, ?)",
                 ("existing-carol", "EXISTING_PUBKEY_CCC=", "10.13.13.4/32"))
    conn.commit()
    return conn


# --- Test 1: clean import, no conflicts -----------------------------------

print("--- test 1: clean import ---")
db = make_db()
subnet = ipaddress.IPv4Network("10.13.13.0/24")

parsed = P.ParsedImport(source=P.SOURCE_WG_EASY_V14, server_keypair=None)
parsed.peers = [
    P.ParsedPeer(name="dave", public_key=k(), private_key=k(), preshared_key=k(),
                 address="10.13.13.10/32", has_private_key=True),
    P.ParsedPeer(name="eve",  public_key=k(), private_key=k(), preshared_key=k(),
                 address="10.13.13.11/32", has_private_key=True),
]
compute_statuses(parsed, db, subnet)
for p in parsed.peers:
    print(f"  {p.name}: {p.status}")
    assert p.status == P.STATUS_OK, p.status
print("  PASS")


# --- Test 2: name conflict ------------------------------------------------

print("--- test 2: name conflict ---")
parsed = P.ParsedImport(source=P.SOURCE_WG_EASY_V14, server_keypair=None)
parsed.peers = [
    P.ParsedPeer(name="existing-alice",  # conflicts!
                 public_key=k(), private_key=k(), preshared_key=k(),
                 address="10.13.13.20/32", has_private_key=True),
]
compute_statuses(parsed, db, subnet)
assert parsed.peers[0].status == P.STATUS_NAME_CONFLICT, parsed.peers[0].status
print(f"  alice conflict status: {parsed.peers[0].status}")
print("  PASS")


# --- Test 3: pubkey conflict (re-import detection) ------------------------

print("--- test 3: pubkey conflict (re-import) ---")
parsed = P.ParsedImport(source=P.SOURCE_WG_EASY_V14, server_keypair=None)
parsed.peers = [
    P.ParsedPeer(name="brand-new-name",
                 public_key="EXISTING_PUBKEY_BBB=",  # bob's existing pubkey
                 private_key=k(), preshared_key=k(),
                 address="10.13.13.50/32", has_private_key=True),
]
compute_statuses(parsed, db, subnet)
assert parsed.peers[0].status == P.STATUS_PUBKEY_CONFLICT, parsed.peers[0].status
print(f"  status: {parsed.peers[0].status}")
print("  PASS — re-import correctly detected via pubkey not name")


# --- Test 4: address out of range, gets reassigned ------------------------

print("--- test 4: address out of range → reassigned ---")
parsed = P.ParsedImport(source=P.SOURCE_PIVPN, server_keypair=None)
parsed.peers = [
    P.ParsedPeer(name="frank", public_key=k(), private_key=k(), preshared_key=k(),
                 address="10.6.0.5/32",  # different subnet (PiVPN's)
                 has_private_key=True),
    P.ParsedPeer(name="gloria", public_key=k(), private_key=k(), preshared_key=k(),
                 address="10.6.0.6/32",
                 has_private_key=True),
]
# Pretend wgflow's server lives at 10.13.13.1
server_addr = ipaddress.IPv4Address("10.13.13.1")
compute_statuses(parsed, db, subnet, server_address=server_addr)
for p in parsed.peers:
    print(f"  {p.name}: {p.status} → assigned {p.assigned_address}")
    assert p.status == P.STATUS_ADDRESS_OUT_OF_RANGE
    assert p.assigned_address is not None
    assert p.assigned_address.startswith("10.13.13.")
    # Must NOT be the server's own /32, must NOT be any existing peer's
    assert p.assigned_address != "10.13.13.1/32", "must skip server address"
    assert p.assigned_address not in {"10.13.13.2/32", "10.13.13.3/32", "10.13.13.4/32"}
# The two reassigned addresses must differ.
assert parsed.peers[0].assigned_address != parsed.peers[1].assigned_address, \
    "reassignment must avoid intra-import collisions"
print("  PASS — server address excluded, both got distinct fresh /32s")


# --- Test 5: address collision with existing peer -------------------------

print("--- test 5: address collision ---")
parsed = P.ParsedImport(source=P.SOURCE_WG_EASY_V14, server_keypair=None)
parsed.peers = [
    P.ParsedPeer(name="brand-new", public_key=k(), private_key=k(), preshared_key=k(),
                 address="10.13.13.3/32",  # bob's existing /32
                 has_private_key=True),
]
compute_statuses(parsed, db, subnet)
assert parsed.peers[0].status == P.STATUS_ADDRESS_CONFLICT, parsed.peers[0].status
print(f"  status: {parsed.peers[0].status}")
print("  PASS")


# --- Test 6: invalid stays invalid ----------------------------------------

print("--- test 6: parser-flagged invalid not changed by status compute ---")
parsed = P.ParsedImport(source=P.SOURCE_WG_EASY_V14, server_keypair=None)
bad = P.ParsedPeer(name="badly-formed", public_key="", private_key="",
                   preshared_key="", address="", has_private_key=True)
bad.status = P.STATUS_INVALID
bad.invalid_reason = "parser said no"
parsed.peers = [bad]
compute_statuses(parsed, db, subnet)
assert parsed.peers[0].status == P.STATUS_INVALID
print(f"  unchanged: {parsed.peers[0].status} ({parsed.peers[0].invalid_reason})")
print("  PASS")


# --- Test 7: address pool exhaustion --------------------------------------

print("--- test 7: address pool exhaustion ---")
tiny_subnet = ipaddress.IPv4Network("192.168.99.0/30")  # 2 hosts: .1 and .2
tiny_db = sqlite3.connect(":memory:")
tiny_db.row_factory = sqlite3.Row
tiny_db.executescript("""
    CREATE TABLE peers (id INTEGER PRIMARY KEY, name TEXT, public_key TEXT, address TEXT);
""")
# Both hosts taken
tiny_db.execute("INSERT INTO peers (name, public_key, address) VALUES (?, ?, ?)",
                ("server", "S=", "192.168.99.1/32"))
tiny_db.execute("INSERT INTO peers (name, public_key, address) VALUES (?, ?, ?)",
                ("only-peer", "P=", "192.168.99.2/32"))
tiny_db.commit()

parsed = P.ParsedImport(source=P.SOURCE_PIVPN, server_keypair=None)
parsed.peers = [
    P.ParsedPeer(name="hopeful", public_key=k(), private_key=k(), preshared_key=k(),
                 address="10.0.0.42/32",  # out of tiny subnet
                 has_private_key=True),
]
compute_statuses(parsed, tiny_db, tiny_subnet)
assert parsed.peers[0].status == P.STATUS_INVALID, parsed.peers[0].status
assert "exhausted" in parsed.peers[0].invalid_reason, parsed.peers[0].invalid_reason
print(f"  exhaustion correctly flagged: {parsed.peers[0].invalid_reason}")
print("  PASS")


# --- Test 8: preview store roundtrip --------------------------------------

print("--- test 8: preview store store/get/drop ---")
p = P.ParsedImport(source=P.SOURCE_BARE_WG, server_keypair=None)
pid = preview_store.store(p)
assert isinstance(pid, str) and len(pid) == 32  # 16 hex bytes
assert preview_store.get(pid) is p
preview_store.drop(pid)
assert preview_store.get(pid) is None
print("  PASS")


# --- Test 9: preview store TTL --------------------------------------------

print("--- test 9: preview store TTL eviction ---")
preview_store.PREVIEW_TTL = 0.05  # ms-scale
p = P.ParsedImport(source=P.SOURCE_BARE_WG, server_keypair=None)
pid = preview_store.store(p)
assert preview_store.get(pid) is p
time.sleep(0.1)
assert preview_store.get(pid) is None, "should have expired"
print("  PASS")


# --- Test 10: serialize_preview shape -------------------------------------

print("--- test 10: serialize_preview JSON shape ---")
p = P.ParsedImport(
    source=P.SOURCE_WG_EASY_V14,
    server_keypair=P.ParsedKeyPair(private_key=k(), public_key=k()),
)
p.peers = [
    P.ParsedPeer(name="alice", public_key=k(), private_key=k(), preshared_key=k(),
                 address="10.13.13.10/32", has_private_key=True),
]
p.peers[0].status = P.STATUS_OK
p.warnings = ["one warning"]

js = serialize.serialize_preview(p, "preview-id-xyz")
assert js["preview_id"] == "preview-id-xyz"
assert js["source"] == P.SOURCE_WG_EASY_V14
assert js["server_keypair"]["has_private_key"] is True
assert "private_key" not in js["server_keypair"], "must NOT leak server privkey"
assert len(js["peers"]) == 1
assert js["peers"][0]["status"] == P.STATUS_OK
assert "private_key" not in js["peers"][0], "must NOT leak peer privkey"
assert "preshared_key" not in js["peers"][0], "must NOT leak PSK"
assert js["summary"]["total"] == 1
assert js["summary"]["ok"] == 1
print("  shape OK, no secrets leak through preview")
print("  PASS")

print()
print("ALL PHASE-2 TESTS PASSED")
