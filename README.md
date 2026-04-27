# wgflow

**A single-container WireGuard gateway with a real admin panel.**

Run WireGuard, generate peer configs, manage per-peer ACLs, monitor live throughput, run network diagnostics, and serve everything from a self-contained web UI — all from one Docker container.

```
[ wgflow ]   wireguard control panel · v3.0
```

---

## What it is

wgflow is a WireGuard server with the missing operator interface. You define what each peer can reach, hand them a `.conf` file or QR code, and watch the connection from a dashboard that streams live data over a WebSocket. ACLs are enforced via per-peer iptables chains with a default-deny policy. Optional dnsmasq integration gives you DNS query logging and override rules for split-horizon scenarios.

It is meant for one-operator deployments managing tens to low hundreds of peers — homelab gateways, small office VPNs, family-and-friends nodes. It is **not** a multi-tenant, multi-server, web-scale product.

---

## Screenshots

**Everything you need.**

<img width="700" height="470" alt="image" src="https://github.com/user-attachments/assets/c4095156-6002-448a-81ed-ba6d3288ef10" />

<img width="765" height="470" alt="image" src="https://github.com/user-attachments/assets/bffe2a6a-abde-409f-8307-045669cefc16" />

<img width="828" height="872" alt="image" src="https://github.com/user-attachments/assets/525cb922-4b83-488d-9a98-1cf8ac5c60d0" />

<img width="990" height="927" alt="image" src="https://github.com/user-attachments/assets/b5b4a260-8922-43ab-9a5d-cc38b0fbd11a" />

---

## Why you might want this

- You already understand WireGuard and don't want a full-stack SaaS layer (Tailscale, Twingate) on top of it
- You need per-peer destination filtering — "alice can reach the NAS, bob can only reach the file server on port 22"
- You want to see what's happening — handshakes, throughput, DNS queries, dropped packets — from a browser without SSH'ing in
- You'd like to run a speedtest or `mtr` from the gateway without keeping a tmux session open
- A single Docker container with one volume is the entire deployment

---

## Feature overview

### Peer management
- Single create, batch by names list, or batch by count + prefix
- Per-peer ACLs (host / CIDR / port / protocol) with a server-side default applied to new peers
- Per-peer **DNS preference** at creation: inherit server default, set custom value, or omit entirely (split-tunnel friendly) — overridable at config download time via `?dns=` query param
- Encrypted ZIP installer for Windows recipients (.ps1 + embedded .conf, AES-256, 60-bit Diceware passphrase)
- Hot-reload via `wg syncconf` — peer changes don't disrupt existing sessions

### Live monitoring
- Per-peer throughput sparklines in the table
- Global throughput chart with live / 1h / 6h / 24h ranges
- Cumulative rx/tx counters that **survive container restarts** (with reset detection for wg interface restarts)
- Three-state peer status (never connected / connected before / online now)
- Inspector modal per peer: endpoint info with reverse DNS, top destinations from conntrack, ACL hit counts, live flow list, raw `wg show` output, recent DNS queries
- **Peer ping widget** in the inspector — one-shot or live mode (every 5s), shows split-tunnel filtering hints when ICMP doesn't come back

### DNS (optional, off by default with `WG_LOCAL_DNS=0`)
- dnsmasq inside the container as the DNS resolver for peers
- Configurable upstream resolvers (multiple, with strict-order preference)
- Domain blocklist via [StevenBlack/hosts](https://github.com/StevenBlack/hosts) (~140k entries built into the image)
- DNS override editor — map domains to internal IPs (NAT loopback workaround)
- Recent queries panel with per-source color coding (cached / blocked / forwarded / locally answered)
- AbuseIPDB lookup links on suspicious destinations

### Internet diagnostics
- **Internet status pill** in the top bar — public IP + last speedtest result, click to open the full diagnostics panel
- **Multi-endpoint speedtest** — Cloudflare (anycast, bidirectional), Hetzner Falkenstein/Helsinki/Ashburn (download-only), OVH Roubaix (download-only)
- Speedtest history chart with hover crosshair, per-endpoint color-coded samples, separate Mbps/ms axes
- Auto-test scheduler (off / 15m / 30m / 1h / 6h / 24h) with live daily-volume estimate
- **Diagnostic tools**: ping (configurable count) · traceroute · mtr · dig · curl timing breakdown · TCP port test · iperf3 client

### Logs panel
Four on-demand log streams via WebSocket — opened only when you switch to that tab so resources stay zero when you're not watching:
- **dnsmasq** — full query and resolver activity
- **wireguard** — kernel module events (requires host kern.log mount)
- **iptables drops** — packets that fell through every per-peer ACL chain (requires `WGFLOW_IPTABLES_LOG=1`)
- **access** — uvicorn HTTP access log

500-line buffer per stream, substring filter, export-to-text.

### UI niceties
- Light + dark themes with persistent selection (no FOUC on theme load)
- Matrix-rain boot animation (replayable via the ◆ button next to the brand)
- Authentication: full-page login overlay, `bcrypt`-hashed `PANEL_PASSWORD` env var, 24h cookie session
- Pagination, search, and column sorting on the peer table
- Custom inline SVG charts everywhere (no chart.js dependency at runtime)
- About modal with version + GitHub link

---

## Quick start

```bash
# 1. Get the code
git clone https://github.com/gcblauth/wgflow.git
cd wgflow

# 2. Edit docker-compose.yml — at minimum:
#    - WG_ENDPOINT       your public hostname:port (e.g. vpn.example.com:51820)
#    - WG_DEFAULT_ACL    what new peers can reach by default
#    - PANEL_PASSWORD    set a password (bcrypt hash or plaintext, see below)

# 3. Bring it up
docker compose up -d --build

# 4. Open the admin UI on the docker host
#    http://127.0.0.1:8080
#    (default port-binding is loopback only — see "Exposing the admin UI safely" below)
```

---

## Configuration

Set everything via environment variables in `docker-compose.yml`. Sensible defaults exist for everything except `WG_ENDPOINT`.

### WireGuard

| Variable             | Default                  | Notes                                                          |
|----------------------|--------------------------|----------------------------------------------------------------|
| `WG_INTERFACE`       | `wg0`                    | interface name inside the container                            |
| `WG_LISTEN_PORT`     | `51820`                  | UDP port WireGuard listens on (also exposed in compose ports)  |
| `WG_SUBNET`          | `10.13.13.0/24`          | tunnel subnet — peers get `.2` upward                          |
| `WG_SERVER_ADDRESS`  | `10.13.13.1/24`          | server's IP inside the tunnel                                  |
| `WG_ENDPOINT`        | `vpn.example.com:51820`  | **public** hostname:port peers will dial — set this!           |
| `WG_DEFAULT_ACL`     | `10.0.0.0/8`             | comma-separated ACL applied to new peers                       |
| `WG_PEER_DNS`        | _auto_                   | DNS handed to peers — inherits sensibly from `WG_LOCAL_DNS`    |

### DNS

| Variable           | Default                       | Notes                                                              |
|--------------------|-------------------------------|--------------------------------------------------------------------|
| `WG_LOCAL_DNS`     | `1`                           | run dnsmasq inside container as resolver — set `0` to disable      |
| `WG_DNS_UPSTREAMS` | `8.8.8.8,8.8.4.4,1.1.1.1`     | upstreams dnsmasq forwards to (only used when `WG_LOCAL_DNS=1`)    |

When `WG_LOCAL_DNS=1` (default), `WG_PEER_DNS` auto-derives to the server's tunnel IP so peers query the local dnsmasq. When `WG_LOCAL_DNS=0`, it auto-derives to `1.1.1.1`. Override `WG_PEER_DNS` explicitly only if you have a separate internal resolver.

### Logging

| Variable               | Default | Notes                                                                  |
|------------------------|---------|------------------------------------------------------------------------|
| `WGFLOW_IPTABLES_LOG`  | `0`     | `1` → log packets dropped by ACL with `WGFLOW-DROP:` prefix (rate-limited) |

### Auth

| Variable          | Default | Notes                                                                     |
|-------------------|---------|---------------------------------------------------------------------------|
| `PANEL_PASSWORD`  | `""`    | empty disables auth; can be plaintext or `$2a$` / `$2b$` / `$2y$` bcrypt  |

If you set a plaintext password, wgflow prints a generated bcrypt hash in the container logs at startup — copy that into compose to avoid storing the plaintext.

### Storage

| Variable           | Default  | Notes                                          |
|--------------------|----------|------------------------------------------------|
| `WGFLOW_DATA_DIR`  | `/data`  | where keys, sqlite, and per-peer configs live  |

### Optional volumes

```yaml
volumes:
  - ./data:/data                                  # required
  - "/var/log/kern.log:/var/log/kern.log:ro"      # optional — enables wireguard + iptables log tabs
```

---

## Architecture

```
  ┌──────────────┐          ┌─────────────────── wgflow container ───────────────────┐
  │ peer devices │  udp/    │                                                        │
  │  (laptops,   │  51820   │  wg0  ─►  FORWARD ─►  WGFLOW_FORWARD ─►  WGFLOW_PEER_N │
  │   phones)    │ ───────► │   │                     │                      │       │
  └──────────────┘          │  10.13.13.0/24          │                      │ ACCEPT│
                            │                         │ DROP (default deny)  ▼       │
                            │  FastAPI ◄─► sqlite     │                  MASQUERADE  │
                            │  :8080 (loopback)       │                      │       │
                            │  dnsmasq :53 (optional) │                      │       │
                            └─────────────────────────┼──────────────────────┼───────┘
                                                                             ▼
                                                         whitelisted internal hosts
```

**Key pieces:**

- **wg0** — WireGuard interface, brought up by `wg-quick` from a server-managed `wg0.conf`
- **WGFLOW_FORWARD** — top-level iptables chain that allows `ESTABLISHED,RELATED`, dispatches to per-peer chains by source IP, and ends with `DROP`
- **WGFLOW_PEER_{id}** — one chain per peer holding that peer's ACL rules
- **MASQUERADE** — egress NAT so destination hosts see the container's IP
- **sqlite** at `/data/wgflow.sqlite` — peers, ACLs, metrics samples, DNS queries, speedtest history, network settings, cumulative traffic counters
- **FastAPI** at `:8080` — REST API + WebSocket for live data
- **dnsmasq** at `:53` (when `WG_LOCAL_DNS=1`) — DNS resolver for peers with blocklist + override support

Kernel state (WireGuard config, iptables chains) is **rebuilt from sqlite on every container start** — sqlite is the source of truth, kernel state is derived.

---

## UI walkthrough

When you open `http://127.0.0.1:8080`, you get:

**Top bar** — brand + version + author link + ◆ · internet status pill (public IP + last speedtest, click for diagnostics) · uptime · connection state · theme toggle · logout

**Stats row** — total peers · online · online sparkline · rx rate + Σ cumulative · tx rate + Σ cumulative (with ↺ reset) · cpu · mem · load

**Throughput chart** — live / 1h / 6h / 24h ranges, with rx + tx area fills

**Peer table** — paginated, sortable, searchable, with status dot · sparkline · inspect button (⌕) · actions menu (config / qr / install zip / acl) · delete

**Peer management panel** — tabs for `add one` · `batch · names` · `batch · count` · `dns override` · `server`. Each create form has DNS preference (checkbox + editable input).

**DNS recent queries** — last 100 queries with source pill, search filter, AbuseIPDB lookup link on suspicious entries (hidden when `WG_LOCAL_DNS=0`)

**Logs panel** — 4 source tabs (dnsmasq · wireguard · iptables drops · access), start/stop per source, 500-line buffer, filter input, export

**Internet diagnostics panel** (opened from top-bar pill) — speedtest chart with hover crosshair · endpoint dropdown (5 providers, grouped by upload support) · auto-test scheduler · clear-history button · 7 diagnostic tools

---

## ACL syntax

| Form                  | Meaning                                |
|-----------------------|----------------------------------------|
| `10.0.5.22`           | single host, any port/proto            |
| `10.0.5.0/24`         | CIDR network, any port/proto           |
| `10.0.5.22:5432/tcp`  | single host, specific port + protocol  |
| `10.0.5.0/24:443/tcp` | CIDR network, specific port + protocol |

Multiple entries: comma-separated in `WG_DEFAULT_ACL`, one-per-line in the UI textarea.

---

## Authentication

Set `PANEL_PASSWORD` in compose to enable auth. Login is a full-page overlay; sessions are 24h cookies. The auth check runs as HTTP middleware (skipped on WebSocket handshakes; the WS handler validates the cookie itself).

For non-interactive use, you can store a bcrypt hash directly:

```bash
docker run --rm python:3.12 python -c "import bcrypt; print(bcrypt.hashpw(b'mypass', bcrypt.gensalt()).decode())"
```

Paste the `$2b$...` output into `PANEL_PASSWORD`.

If `PANEL_PASSWORD=""` (default), auth is disabled — fine for SSH-tunnel-only access, dangerous on a shared network.

---

## API reference

All endpoints are under `/api/`. Auth (when enabled) is via the `wgflow_session` cookie set on `/api/auth/login`.

### Peers

| Method   | Path                                  | Notes                                           |
|----------|---------------------------------------|-------------------------------------------------|
| `GET`    | `/api/peers`                          | list all peers                                  |
| `POST`   | `/api/peers`                          | `{name, acl?, dns?}`                            |
| `POST`   | `/api/peers/batch/names`              | `{names: [...], acl?, dns?}`                    |
| `POST`   | `/api/peers/batch/count`              | `{count, prefix?, acl?, dns?}`                  |
| `PUT`    | `/api/peers/{id}/acl`                 | `{acl: [...]}`                                  |
| `DELETE` | `/api/peers/{id}`                     | remove peer + iptables chain + DNS history      |
| `DELETE` | `/api/peers?confirm=DELETE`           | wipe all peers (destructive)                    |
| `GET`    | `/api/peers/{id}/config`              | `?dns=...` overrides stored DNS at download     |
| `GET`    | `/api/peers/{id}/qr`                  | `?dns=...` same override semantics              |
| `GET`    | `/api/peers/{id}/install-script`      | encrypted ZIP, passphrase in `X-WGFlow-Passphrase` header |
| `GET`    | `/api/peers/{id}/inspect`             | endpoint, top destinations, ACL hits, conntrack flows, recent DNS |
| `GET`    | `/api/peers/{id}/ping`                | ping the peer's tunnel IP from the server       |
| `GET`    | `/api/peers/{id}/acl-hits`            | iptables packet/byte counters per ACL rule      |
| `GET`    | `/api/peers/{id}/dns`                 | recent DNS queries from this peer               |

### Server + auth

| Method | Path                  | Notes                                                |
|--------|-----------------------|------------------------------------------------------|
| `GET`  | `/api/server`         | server config including `local_dns_enabled`, `peer_dns`, `dns_upstreams`, `uptime_seconds` |
| `GET`  | `/api/auth/status`    | `{auth_required, authenticated}`                     |
| `POST` | `/api/auth/login`     | `{password}` → sets cookie                           |
| `POST` | `/api/auth/logout`    | clears cookie                                        |

### Metrics

| Method | Path                                            | Notes                                          |
|--------|-------------------------------------------------|------------------------------------------------|
| `GET`  | `/api/metrics/live`                             | last 5 minutes of throughput + host vitals     |
| `GET`  | `/api/metrics/history?window=1h`                | `1h`, `6h`, `24h`                              |
| `GET`  | `/api/metrics/peer/{id}/sparkline`              | last 60s for a single peer                     |
| `GET`  | `/api/metrics/cumulative`                       | persistent rx/tx since last clear              |
| `POST` | `/api/metrics/cumulative/reset?confirm=RESET`   | zero the visible cumulative counters           |

### DNS (only meaningful when `WG_LOCAL_DNS=1`)

| Method   | Path                            | Notes                                            |
|----------|---------------------------------|--------------------------------------------------|
| `GET`    | `/api/dns/recent`               | recent queries across all peers                  |
| `GET`    | `/api/dns/overrides`            | list active overrides                            |
| `POST`   | `/api/dns/overrides`            | `{pattern, target_ip, note?}`                    |
| `DELETE` | `/api/dns/overrides/{id}`       | remove an override                               |
| `GET`    | `/api/rdns/{ip}`                | reverse DNS lookup (24h cache)                   |

### Network diagnostics

| Method   | Path                                            | Notes                                                       |
|----------|-------------------------------------------------|-------------------------------------------------------------|
| `GET`    | `/api/network/status`                           | public IP + last speedtest summary                          |
| `GET`    | `/api/network/speedtest/endpoints`              | catalog of 5 endpoints with `supports_upload` + size hints  |
| `POST`   | `/api/network/speedtest?endpoint=cloudflare`    | run a test (synchronous, 15-30s)                            |
| `GET`    | `/api/network/speedtest/history?limit=200`      | historical samples                                          |
| `DELETE` | `/api/network/speedtest/history?confirm=DELETE` | wipe history                                                |
| `PUT`    | `/api/network/speedtest/schedule`               | `{interval_min, endpoint?}` — 0 disables, min 5             |
| `POST`   | `/api/network/diag/{tool}`                      | `{target, record_type?, count?}` — `tool` ∈ ping/traceroute/mtr/dig/curl/tcp/iperf3 |

### Logs

| Method | Path                       | Notes                                  |
|--------|----------------------------|----------------------------------------|
| `GET`  | `/api/logs/availability`   | which streams are usable + reasons     |
| `WS`   | `/ws/logs/{source}`        | dnsmasq / wireguard / iptables / access |

### Live status

| Method | Path           | Notes                                                  |
|--------|----------------|--------------------------------------------------------|
| `WS`   | `/ws/status`   | combined peer + host + throughput snapshot every 1s    |

---

## Persistence

Everything mutable lives in `./data/`:

```
data/
├── keys/
│   ├── server_private.key   # generated once, never regenerated
│   └── server_public.key
├── peers/                   # one .conf per peer for re-rendering
└── wgflow.sqlite            # everything else
```

The sqlite database has these tables: `peers`, `peer_acls`, `metrics_samples`, `dns_queries`, `dns_overrides`, `speedtest_history`, `network_settings`, `cumulative_traffic`. Migrations run automatically on container startup.

---

## Operational notes

- **Hot reload.** Adding, editing, or deleting peers uses `wg syncconf`. Existing peer sessions stay connected through the change.
- **Default deny.** The `WGFLOW_FORWARD` chain ends with `DROP`. Anything that doesn't match a per-peer rule gets dropped silently — set `WGFLOW_IPTABLES_LOG=1` to see them.
- **Conntrack byte accounting** is needed for the inspector's "top destinations" panel. Enable on the host with `sudo sysctl -w net.netfilter.nf_conntrack_acct=1` (and persist in `/etc/sysctl.conf`).
- **WireGuard kernel logs** are conservative by default — most useful events are errors, not routine handshakes. For richer per-handshake logging: `echo 'module wireguard +p' | sudo tee /sys/kernel/debug/dynamic_debug/control` on the host.
- **AES-encrypted ZIP** installer requires 7-Zip on the recipient (Windows native zip UI doesn't support AES). Linux/Mac `unzip` handles it.
- **iperf3 tool** requires `iperf3 -s` running on the target side. The button works in either direction (the target doesn't have to be a peer; it can be any reachable host).
- **NAT loopback** — if your peers are on the same LAN as the wgflow server, the public endpoint may not work due to your router's NAT. Use the DNS override editor to map the public hostname to an internal IP.
- **iptables LOG rule rate** — capped at 10/min, burst 5. Won't flood `kern.log` even with a misbehaving peer. Bandwidth-limit features (when added) will need stricter per-rule limits.
- **The `↺` cumulative counter reset** affects both rx and tx together (single offset row in DB).

---

## Exposing the admin UI safely

The admin process can rewrite iptables and WireGuard config and read peer private keys. **It must never be directly internet-facing.**

Two reasonable patterns:

**SSH tunnel** for occasional admin sessions:
```bash
ssh -L 8080:127.0.0.1:8080 user@your-host
# then browse http://localhost:8080
```

**Reverse proxy** with TLS (nginx/caddy/traefik) on the same host, configured to talk to `127.0.0.1:8080`. Even with `PANEL_PASSWORD` set, putting auth at the proxy layer (mTLS, oauth2-proxy, basic auth in HA) gives you an extra ring.

The compose file binds to `127.0.0.1:8080` deliberately. Don't change it to `0.0.0.0` unless you've thought about it carefully.

---

## Troubleshooting

| Symptom                                          | Where to look                                                         |
|--------------------------------------------------|-----------------------------------------------------------------------|
| Peer connects but no traffic                     | `docker exec wgflow iptables -L WGFLOW_FORWARD -n -v` — counters      |
| No connection at all                             | UDP/51820 reachable from the peer's network? Check NAT/firewall       |
| `wg-quick up` fails on container start           | `lsmod \| grep wireguard` on the host; load the kernel module         |
| Admin UI empty / WS errors                       | `docker logs wgflow` and check the browser console                    |
| DNS not resolving for peers                      | If `WG_LOCAL_DNS=1`, check `docker logs wgflow` for dnsmasq startup   |
| "Top destinations" inspector panel always empty  | Enable conntrack accounting (see operational notes)                   |
| iperf3 says "connection refused"                 | Make sure `iperf3 -s` is running on the target                        |
| Peer ping says "no ICMP reply" but peer is online| Peer's `AllowedIPs` is split-tunnel without server subnet, OR firewall|

---

## Security surface

This container has `NET_ADMIN` and `NET_RAW`. Anyone who reaches port 8080 can:

- create / delete peers (and download their private keys)
- modify iptables rules indirectly via ACL edits
- run arbitrary network diagnostics from the server (ping, traceroute, port scans via TCP test, iperf3)
- read DNS query history (potential privacy leak about peers' browsing)

**Mitigations:**
- Bind to loopback (default in compose)
- Set `PANEL_PASSWORD`
- Put a reverse proxy with auth in front
- Treat `data/` as secret material (peer private keys live in sqlite + in `data/peers/*.conf`)

---

## Roadmap

Things that have been discussed but aren't built:

- **Per-peer bandwidth limits** via Linux `tc` HTB classes — viable up to ~50 peers before classifier maintenance gets painful
- **Whole-VPN bandwidth cap** via a single `tc tbf` rule on `wg0` — much simpler, ~1 day of work
- **Per-axis cumulative counter reset** (currently rx + tx reset together — needs separate offset rows in DB)
- **WireGuard kernel-debug enable from UI** (currently a manual host-side `dynamic_debug` write)
- **Real Ookla speedtest CLI** as an opt-in alternative to the curl-based one (more accurate, but +30MB image and Ookla telemetry)
- **iperf3 button in the peer inspect modal** (currently only in the diagnostics panel)
- **Multi-server / multi-interface** support (one wgflow → multiple wg interfaces) — would need significant refactoring

---

## Requirements

- Linux host with kernel ≥ 5.6 **or** the `wireguard` DKMS module loaded. Verify with `modprobe wireguard && lsmod | grep wireguard`.
- Docker and Docker Compose.
- `net.ipv4.ip_forward = 1` is set via compose sysctl, but your host must allow Docker to set that sysctl (the default).

---

## License

"This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details."

---

## Credits

Built by [@gcblauth](https://github.com/gcblauth). Issues, PRs, and feedback welcome at [github.com/gcblauth/wgflow](https://github.com/gcblauth/wgflow).
