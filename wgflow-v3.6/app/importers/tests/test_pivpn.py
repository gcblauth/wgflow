"""Build a fake PiVPN backup tarball and parse it."""
import io
import sys
import tarfile
import secrets
import base64

sys.path.insert(0, "/home/claude/wgflow-v3.2-fixed")
from app.importers import pivpn, parsed as P


def fake_wg_key():
    return base64.b64encode(secrets.token_bytes(32)).decode()


# Synthesize 3 client keypairs + a server keypair.
server_priv = fake_wg_key()
server_pub = fake_wg_key()  # in real PiVPN this is derived; we don't care here
clients = [
    ("alice",  fake_wg_key(), fake_wg_key(), fake_wg_key(), "10.6.0.2"),
    ("bob",    fake_wg_key(), fake_wg_key(), fake_wg_key(), "10.6.0.3"),
    ("carol",  fake_wg_key(), fake_wg_key(), fake_wg_key(), "10.6.0.4"),
]

# Build the server wg0.conf
server_lines = [
    "[Interface]",
    f"PrivateKey = {server_priv}",
    "Address = 10.6.0.1/24",
    "ListenPort = 51820",
    "",
]
for name, c_priv, c_pub, c_psk, c_addr in clients:
    server_lines += [
        f"### Client {name}",
        "[Peer]",
        f"PublicKey = {c_pub}",
        f"PresharedKey = {c_psk}",
        f"AllowedIPs = {c_addr}/32",
        "",
    ]
server_conf = "\n".join(server_lines)

# Build per-client confs
client_confs = {}
for name, c_priv, c_pub, c_psk, c_addr in clients:
    client_confs[name] = f"""[Interface]
PrivateKey = {c_priv}
Address = {c_addr}/24
DNS = 9.9.9.9, 149.112.112.112

[Peer]
PublicKey = {server_pub}
PresharedKey = {c_psk}
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::0/0
"""

# Pack into a tar.gz
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w:gz") as tar:
    def add(path, content):
        data = content.encode()
        info = tarfile.TarInfo(name=path)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    add("etc/wireguard/wg0.conf", server_conf)
    for name, conf in client_confs.items():
        add(f"etc/wireguard/configs/{name}.conf", conf)

archive = buf.getvalue()
print(f"archive size: {len(archive)} bytes")

# Parse
result = pivpn.parse(archive)
print(f"source: {result.source}")
print(f"server keypair present: {result.server_keypair is not None}")
print(f"peers: {len(result.peers)}")
print(f"warnings: {result.warnings}")
for peer in result.peers:
    status = "OK" if peer.status == P.STATUS_OK else f"INVALID: {peer.invalid_reason}"
    print(f"  - {peer.name:10s} addr={peer.address:18s}  has_psk={bool(peer.preshared_key)}  {status}")

# Assertions
assert result.source == P.SOURCE_PIVPN
assert result.server_keypair is not None, "PiVPN server keypair missing"
assert result.server_keypair.private_key == server_priv
assert len(result.peers) == 3
assert all(p.status == P.STATUS_OK for p in result.peers)
# Verify pubkey matching: client alice's pubkey in the parsed result should
# match the server's [Peer] entry pubkey for 10.6.0.2.
expected_alice_pubkey = clients[0][2]
parsed_alice = next(p for p in result.peers if p.name == "alice")
assert parsed_alice.public_key == expected_alice_pubkey, \
    f"alice pubkey mismatch: {parsed_alice.public_key} vs {expected_alice_pubkey}"

# Address normalisation: input was 10.6.0.2 but should be 10.6.0.2/32 in IR
assert parsed_alice.address == "10.6.0.2/32"
print()
print("PIVPN PARSER TEST PASSED")


# --- Test orphan peer warning ---------------------------------------------
print()
print("--- orphan-peer scenario ---")
# Drop alice's client conf but keep server's [Peer] block. Server has
# 3 [Peer]s, archive has 2 client confs → 1 warning expected.
buf2 = io.BytesIO()
with tarfile.open(fileobj=buf2, mode="w:gz") as tar:
    def add(path, content):
        data = content.encode()
        info = tarfile.TarInfo(name=path)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    add("etc/wireguard/wg0.conf", server_conf)
    # only bob and carol
    for name in ("bob", "carol"):
        add(f"etc/wireguard/configs/{name}.conf", client_confs[name])

result2 = pivpn.parse(buf2.getvalue())
assert len(result2.peers) == 2
assert any("no matching client" in w for w in result2.warnings), result2.warnings
print(f"orphan warning surfaced: {[w for w in result2.warnings if 'no matching' in w][0][:80]}")
print("ORPHAN PEER WARNING TEST PASSED")
