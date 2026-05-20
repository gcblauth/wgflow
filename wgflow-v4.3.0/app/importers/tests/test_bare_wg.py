import sys, secrets, base64
sys.path.insert(0, "/home/claude/wgflow-v3.2-fixed")
from app.importers import bare_wg, parsed as P

def k(): return base64.b64encode(secrets.token_bytes(32)).decode()

server_priv = k()
peers_data = [
    ("alice-laptop", k(), k(), "10.0.0.2"),
    ("bob-phone",    k(), k(), "10.0.0.3"),
    (None,           k(), k(), "10.0.0.4"),  # no name comment
]

lines = [
    "[Interface]",
    f"Address = 10.0.0.1/24",
    f"PrivateKey = {server_priv}",
    "ListenPort = 51820",
    "",
]
for name, pub, psk, addr in peers_data:
    if name:
        lines.append(f"### {name}")
    lines += [
        "[Peer]",
        f"PublicKey = {pub}",
        f"PresharedKey = {psk}",
        f"AllowedIPs = {addr}/32",
        "",
    ]

text = "\n".join(lines)
result = bare_wg.parse(text.encode())
print(f"source: {result.source}")
print(f"server keypair: {result.server_keypair is not None}")
print(f"warnings: {result.warnings}")
print(f"peers ({len(result.peers)}):")
for p in result.peers:
    print(f"  - {p.name:20s} addr={p.address}  has_priv={p.has_private_key}  status={p.status}  {p.invalid_reason}")

assert result.server_keypair is not None
assert result.server_keypair.private_key == server_priv
assert result.server_keypair.public_key == ""  # not derivable in parser
assert len(result.peers) == 3
assert all(p.has_private_key is False for p in result.peers)
assert all(p.private_key == "" for p in result.peers)
assert result.peers[0].name == "alice-laptop"
assert result.peers[1].name == "bob-phone"
assert result.peers[2].name == "imported-3", f"got {result.peers[2].name!r}"
assert all(p.status == P.STATUS_OK for p in result.peers)
print()
print("BARE-WG PARSER TEST PASSED")
