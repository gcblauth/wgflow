# wgflow

**WireGuard with a professional control panel, real per-peer ACLs, and built-in diagnostics — all from one Docker container.**

```
[ wgflow ]   wireguard control panel · v4.4.0
```

<img src="https://wgflow.2ps.in/stats.svg" alt="community stats" />

wgflow turns a Linux box into a WireGuard gateway you can actually operate: generate peer configs, control exactly what each peer can reach, watch live throughput, run network diagnostics, federate multiple sites, and migrate in from wg-easy or PiVPN — all from a self-contained web UI. One container, one SQLite file, no external dependencies.

> See [CHANGELOG.md](CHANGELOG.md) for full version history.

---

## Screenshots

<!-- TODO: replace with real screenshots -->
<!-- 1. Dashboard — live peer list + throughput -->
<!-- 2. ACL editor — per-peer CIDR/port/proto rules -->
<!-- 3. Multisite panel — federated wgflows -->
<!-- 4. Mobile view — responsive peer cards -->

---

## Why wgflow

Most WireGuard panels stop at "add peer, download config." wgflow is built for people who actually run the thing in production:

- **Real per-peer ACLs.** Not just on/off — each peer gets a rule set of CIDRs, host\:port\:protocol entries, and deny rules, enforced by a dedicated iptables chain. A phone can be restricted to one RDP host while a laptop gets the whole LAN.
- **One-command install.** `setup-one-time.sh` walks you through endpoint, DNS, federation, and panel binding, generates a random admin password, writes a fully-commented `.env`, builds, and verifies. Re-runnable, scriptable for CI.
- **Multisite federation, built in.** Pair two or more wgflows over WireGuard so the LANs behind each become reachable from the others. No third-party mesh service.
- **Migrate in.** Import panel reads wg-easy, PiVPN, and bare WireGuard configs and turns them into wgflow peers — no manual re-entry.
- **SQLite is the source of truth.** The kernel state is *rebuilt* from the database on every change, so the panel never lies about what's actually configured. No drift between "what the UI shows" and "what `wg show` says."
- **Diagnostics that don't need a shell.** ping, traceroute, mtr, dig, curl, tcpdump, iperf3 — all from the panel, scoped to the container.

---

## Quick start (Docker)

```bash
git clone https://github.com/gcblauth/wgflow.git
cd wgflow
sudo ./setup-one-time.sh
```

The installer asks a handful of questions (your public endpoint is the only required one), generates an admin password, builds the image, starts the container, and verifies the panel responds. When it finishes it prints the panel URL and where to find the password.

Then open the panel, log in, **change the admin password**, and add your first peer.

### Bare-metal (no Docker)

```bash
sudo ./setup-one-time.sh --bare-metal
```

Installs into a Python venv with a systemd unit instead of a container. Same `.env`, same features.

### Other install flags

| Flag | Effect |
|------|--------|
| `--force` | Reconfigure an existing install (backs up the old `.env` first) |
| `--noninteractive` | Use defaults + environment variables, no prompts (CI-friendly) |
| `--bare-metal` | systemd + venv instead of Docker |
| `--help` | Usage |

---

## What you can do with it

### Peers
Create peers individually or in batches (by name list or by count). Each peer gets a generated keypair, an allocated address, a downloadable config, and a QR code. Enable/disable without deleting. Inspect live handshake, endpoint, and transfer counters.

### Per-peer ACLs
Every peer has an access-control list controlling which destinations its traffic may reach. Entries are CIDRs, single hosts, `host:port/proto` tuples, or deny rules (`!` prefix). ACLs are enforced by a per-peer iptables chain — not advisory. Named aliases let you reuse common rule sets. The panel shows per-rule hit counts so you can see what's actually being used.

### Local DNS + blocklists *(optional)*
Turn on the built-in dnsmasq and wgflow becomes a DNS-level ad/tracker blocker for every connected peer — Pi-hole-style. Multiple blocklist sources, deduplicated. A live DNS query log shows what's being resolved and what's being blocked. Per-domain overrides for allowlisting or custom answers.

### Multisite federation *(optional)*
Pair this wgflow with other wgflows. Each pairing is a symmetric WireGuard link on a dedicated overlay subnet (`10.99.0.0/24` by default). Advertise LANs on each side; routes are reconciled automatically. The panel shows every link with live handshake status and a one-click "open remote panel" button.

### Migration importer *(optional)*
Coming from another VPN manager? The Import panel reads **wg-easy**, **PiVPN**, and **bare WireGuard** configurations, previews the peers it found, and commits the ones you choose into wgflow's database. Your existing client subnet is preserved so peer configs keep working.

### Diagnostics
ping, traceroute, mtr, dig, curl, tcpdump, and iperf3 (client and server) — run from the panel, output streamed live. Scheduled speed tests with history. Public-IP detection. Reverse-DNS lookups.

### Live metrics
Per-peer and aggregate throughput, updated over a WebSocket. Cumulative transfer counters. Sparkline history per peer. The whole dashboard updates without polling.

---

## Configuration

`setup-one-time.sh` writes a fully-commented `.env`. Every value is documented inline. The most important ones:

| Variable | Default | What it does |
|----------|---------|--------------|
| `WG_ENDPOINT` | *(required)* | Public `host:port` peers connect to |
| `WG_SUBNET` | `10.13.13.0/24` | Address range for client peers |
| `WG_LOCAL_DNS` | `0` | Run the built-in DNS server + blocklists |
| `WG_MULTISITE` | `1` | Enable multisite federation panel |
| `WG_DEFAULT_ACL` | `10.0.0.0/8` | Default reach for new peers |
| `WGFLOW_MIGRATION_DEFAULT_ENABLED` | `0` | Show the Import panel |
| `WGFLOW_IPTABLES_LOG` | `0` | Log rejected packets (debugging) |
| `HOSTBIND_WG_PANEL` | `0.0.0.0` | Panel bind interface |
| `HOSTBIND_WG_PANEL_PORT` | `8080` | Panel host-side port |
| `WGFLOW_TELEMETRY_ENABLED` | `1` | Anonymous usage stats (see below) |

To change anything later: edit `.env`, then `docker compose up -d` (or `systemctl restart wgflow` on bare-metal).

---

## Architecture in one paragraph

wgflow keeps **SQLite as the single source of truth**. Every change — a new peer, an ACL edit, a federation link — is written to the database first, then a reconciler **rebuilds the kernel state** (`wg syncconf`, `ip route`, iptables chains) to match. The kernel is never edited incrementally and trusted afterward; it is treated as a cache that gets regenerated. This means the panel can never drift from reality, schema migrations are safe (SAVEPOINT-wrapped), and a corrupted kernel state self-heals on the next change. The web layer is FastAPI + a single static `index.html` (no build step). See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full breakdown.

---

## Multi-platform

wgflow runs on **Linux x86_64 and ARM64 / ARMv7** — the Docker image is multi-arch and all Python dependencies ship prebuilt wheels for ARM. It runs comfortably on a Raspberry Pi 4 or 5; a Pi 3 works for residential use. The host needs a kernel with the WireGuard module (Linux ≥ 5.6, i.e. any current distro).

---

## Performance tuning

For most installs the defaults are fine. When pushing serious throughput, the host kernel (where WireGuard's data plane actually runs) can be tuned — larger UDP socket buffers, NIC hardware offloads, optionally the `performance` CPU governor. The repo ships an opt-in, reversible script:

```bash
sudo ./scripts/host-tune.sh            # sysctl + NIC offloads
sudo ./scripts/host-tune.sh --governor # also pin the CPU governor
sudo ./scripts/host-tune.sh --revert   # undo everything
```

It runs on the host, autodetects the NIC, and installs systemd units so the settings persist across reboots. Full rationale and the manual equivalents are in [docs/PERFORMANCE.md](docs/PERFORMANCE.md).

---

## Telemetry

When enabled (default), wgflow sends a small anonymous payload to `wgflow.2ps.in` roughly every 30 minutes: version, peer count, total RX/TX bytes, uptime, and a randomly-generated instance ID. **No peer identifiers, no IP addresses, no names, no config contents.** It's used to understand how the software is deployed at scale.

Opt out any time: set `WGFLOW_TELEMETRY_ENABLED=0` in `.env` and restart.

---

## Security model

- The admin panel is password-protected by default (`PANEL_PASSWORD`, bcrypt-hashed at startup). `setup-one-time.sh` generates a random one.
- Peer ACLs are **default-deny capable** — a peer reaches only what its rule set allows.
- The container runs with `NET_ADMIN` + `NET_RAW` (required for WireGuard and iptables) and nothing more.
- Bind the panel to `127.0.0.1` and front it with a reverse proxy if you want TLS or extra auth.
- The WireGuard server keypair and peer keys live in the SQLite database; back it up accordingly (`/data/wgflow.sqlite`).

---

## Day-2 operations

```bash
docker compose logs -f          # watch logs
docker compose restart          # restart
docker compose up -d            # apply .env changes
docker compose down             # stop
```

Bare-metal: replace `docker compose ...` with `systemctl ... wgflow` / `journalctl -u wgflow -f`.

Health check: `GET /healthz` returns `{"ok": true, "version": "...", "uptime_seconds": N}` — suitable for uptime-kuma, Prometheus blackbox, or a systemd watchdog.

---

## Contributing

Issues and pull requests welcome. wgflow is deliberately dependency-light and the codebase is heavily commented — the comments are considered part of the deliverable. Before a structural change, open an issue to discuss; the SQLite-canonical / kernel-reconciled architecture is load-bearing and worth preserving.

---

## License

See [LICENSE](LICENSE).
