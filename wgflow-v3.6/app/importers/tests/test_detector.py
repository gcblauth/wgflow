"""Test the dispatcher across all five branches + error paths."""
import sys, json, io, tarfile, secrets, base64, sqlite3, tempfile, os
sys.path.insert(0, "/home/claude/wgflow-v3.2-fixed")
from app.importers import detector, parsed as P

def k(): return base64.b64encode(secrets.token_bytes(32)).decode()

# --- v14 JSON ---
v14 = json.dumps({
    "server": {"privateKey": k(), "publicKey": k(), "address": "10.0.0.1"},
    "clients": {"x": {"name": "alice", "address": "10.0.0.2",
                      "privateKey": k(), "publicKey": k(),
                      "preSharedKey": k(), "enabled": True}}
}).encode()
r = detector.detect_and_parse(v14)
assert r.source == P.SOURCE_WG_EASY_V14, r.source
print(f"detected v14 JSON         → {r.source}")

# --- v15 SQLite ---
db_path = tempfile.NamedTemporaryFile(suffix='.db', delete=False).name
conn = sqlite3.connect(db_path)
conn.executescript("""
    CREATE TABLE clients (id INTEGER PRIMARY KEY, name TEXT, publicKey TEXT,
                          privateKey TEXT, preSharedKey TEXT, address TEXT,
                          enabled INTEGER DEFAULT 1);
    CREATE TABLE settings (privateKey TEXT, publicKey TEXT);
""")
conn.execute("INSERT INTO settings VALUES (?, ?)", (k(), k()))
conn.execute("INSERT INTO clients (name, publicKey, privateKey, preSharedKey, address) "
             "VALUES (?, ?, ?, ?, ?)", ("eve", k(), k(), k(), "10.1.0.5"))
conn.commit(); conn.close()
with open(db_path, "rb") as f: db_bytes = f.read()
os.unlink(db_path)
r = detector.detect_and_parse(db_bytes)
assert r.source == P.SOURCE_WG_EASY_V15
print(f"detected v15 SQLite       → {r.source}")

# --- PiVPN tar.gz ---
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w:gz") as tar:
    server_priv = k()
    client_pub = k(); client_psk = k(); client_priv = k()
    server_conf = f"[Interface]\nPrivateKey = {server_priv}\nAddress = 10.6.0.1/24\n\n[Peer]\nPublicKey = {client_pub}\nPresharedKey = {client_psk}\nAllowedIPs = 10.6.0.2/32\n"
    client_conf = f"[Interface]\nPrivateKey = {client_priv}\nAddress = 10.6.0.2/24\n\n[Peer]\nPublicKey = {k()}\nPresharedKey = {client_psk}\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0\n"
    for path, content in [("etc/wireguard/wg0.conf", server_conf),
                           ("etc/wireguard/configs/zoe.conf", client_conf)]:
        info = tarfile.TarInfo(name=path)
        info.size = len(content.encode())
        tar.addfile(info, io.BytesIO(content.encode()))
r = detector.detect_and_parse(buf.getvalue())
assert r.source == P.SOURCE_PIVPN
print(f"detected PiVPN tar.gz     → {r.source}")

# --- bare WG ---
text = f"""[Interface]
Address = 10.5.0.1/24
PrivateKey = {k()}

### my-laptop
[Peer]
PublicKey = {k()}
AllowedIPs = 10.5.0.2/32
""".encode()
r = detector.detect_and_parse(text)
assert r.source == P.SOURCE_BARE_WG
print(f"detected bare WG          → {r.source}")

# --- error: unknown format ---
try:
    detector.detect_and_parse(b"this is not a config file at all")
    raise AssertionError("should have raised")
except ValueError as e:
    print(f"unknown bytes correctly raised → {e}")

# --- error: empty ---
try:
    detector.detect_and_parse(b"")
    raise AssertionError("should have raised")
except ValueError as e:
    print(f"empty bytes correctly raised   → {e}")

# --- error: JSON without 'clients' key ---
try:
    detector.detect_and_parse(b'{"foo": "bar"}')
    raise AssertionError("should have raised")
except ValueError as e:
    print(f"non-wgeasy JSON correctly raised → {e}")

print()
print("ALL DETECTOR TESTS PASSED")
