# wgflow v3.0

A consolidation release: per-peer DNS, persistent traffic counters, multi-endpoint speedtest, expanded diagnostic tools, refreshed UI chrome, and an about modal. **Full container rebuild required** — Dockerfile adds `iperf3`. DB migrations run automatically on startup.

---

## ⚠️ Upgrade notes

```bash
docker compose down
git pull
docker compose up -d --build
```

The DB migrations (new `peers.dns` column, new `cumulative_traffic` table, new `endpoint` column on `speedtest_history`) run idempotently on startup. **No manual migration needed.** Existing peers keep working — they just inherit the server-default DNS.

If you've previously hardcoded `WG_PEER_DNS: "10.13.13.1"` in compose, consider removing it — the default now auto-derives from `WG_SERVER_ADDRESS` (when `WG_LOCAL_DNS=1`) or falls back to `1.1.1.1` (when `WG_LOCAL_DNS=0`).

---

## ✨ New features

### Per-peer DNS preference
Every peer-create form (single, batch by names, batch by count) now has a DNS field:
- **Checkbox** — untick to omit the `DNS = ` line entirely from the generated config (split-tunnel friendly)
- **Editable input** — defaults to the server's `peer_dns` value, accepts any IP or comma-separated list
- **Stored per-peer** in the new `peers.dns` column
- **Overridable at download time** — `?dns=` query param on `/api/peers/{id}/config`, `/api/peers/{id}/qr`, and `/api/peers/{id}/install-script`

### Persistent rx/tx counters
The Σ tiles on the dashboard now show totals that **survive container restarts**:
- New `cumulative_traffic` singleton table accumulates sum-of-peer bytes every 10s
- Reset detection — if the wg interface restarts (counters drop to zero), wgflow resumes from the new baseline rather than going negative
- New `↺` reset button on each Σ tile — type-RESET confirmation, sets offset = total to zero the visible counter without losing accumulation

### Multi-endpoint speedtest
The diagnostics panel now lets you pick which server to test against:

| Endpoint              | Region        | Direction |
|-----------------------|---------------|-----------|
| Cloudflare (anycast)  | nearest PoP   | ↓↑        |
| Hetzner Falkenstein   | DE            | ↓ only    |
| Hetzner Helsinki      | FI            | ↓ only    |
| Hetzner Ashburn       | US-East       | ↓ only    |
| OVH Roubaix           | FR            | ↓ only    |

The dropdown is grouped by upload support. Selecting a download-only endpoint surfaces a warning in the hint text. Each sample in the history is tagged with its endpoint and color-coded on the chart so switching endpoints doesn't create misleading slopes between different network paths.

### Reworked speedtest chart
Major upgrade to match the dashboard chart's polish:
- Proper labelled Y-axes (Mbps left, ms right)
- Time-range readout at the bottom
- Area fills under the down/up lines
- **Hover crosshair** with a floating readout box showing endpoint, time, and all values
- Endpoint-colored sample dots with native SVG tooltips

### Diagnostic tools expansion
The `tools` section in the diagnostics panel now has **7 tools** (was 5):

| Tool         | Purpose                                                    |
|--------------|------------------------------------------------------------|
| `ping`       | ICMP echo — **configurable count (1–50, default 3)**, 1s timeout per probe |
| `traceroute` | path discovery, max 20 hops                                |
| `mtr`        | combined ping+traceroute, 10 samples per hop               |
| `dig`        | DNS query with selectable record type (A/AAAA/CNAME/MX/…)  |
| `curl`       | HTTP(S) timing breakdown (DNS / connect / TLS / TTFB)      |
| `tcp`        | TCP port reachability test (`host:port`)                   |
| `iperf3`     | **NEW** — full bandwidth test against an iperf3 server     |

The `iperf3` button runs against any reachable target with `iperf3 -s` listening (default port 5201, override with `host:port`). JSON output gets pretty-printed with a summary line up top.

### Clear speedtest history
A **clear history** button now sits next to the sample count above the speedtest chart. Type-DELETE confirmation. Wipes the history table only — the schedule and current settings stay.

### About modal + UI chrome
- The `gcblauth@gmail.com` text is gone from the header
- `gcblauth` (no @) is now a clickable link that opens a centered **about modal** with version, tagline, and GitHub link
- Matrix replay moved to a dedicated **◆ button** next to the brand (rotates 180° on hover, replays the boot intro)
- Header reads: `wireguard control panel · v3.0 · gcblauth ◆`

### Login animation tweak
Matrix intro extended from 1.8s → 2.5s. Long enough to feel like a deliberate boot sequence, short enough not to be in the way on repeated logins.

---

## 🔧 Improvements

- **Inspector ping widget** — when you open a peer's inspector, a `latency` bar at the top shows split-tunnel filtering hints when ICMP doesn't come back. One-shot ping by default; click `live` to auto-refresh every 5s. Modal close auto-stops live mode.
- **Speedtest hint text** updates dynamically based on selected endpoint — accurate `~MB per test` per provider, and shows daily volume estimate when an auto-schedule is active
- **Internet status pill** now uses theme-tracked rx/tx colors and shows full speedtest timestamp + ping in the hover tooltip
- **DNS-related panels** auto-hide when `WG_LOCAL_DNS=0`, including the inspector's DNS section and the recent queries panel
- **Speedtest panel** opens with target field defaulted to the first configured DNS upstream (was hardcoded `1.1.1.1`)
- **Logs panel** — 4 on-demand WebSocket streams (dnsmasq · wireguard · iptables · access). Resources stay zero when the panel isn't being watched.

---

## 🐛 Fixes

- **Speedtest upload now works** — fixed `'StreamReader' object has no attribute 'fileno'` AttributeError. The async subprocess pipeline was rewritten to use a single `bash -c "head -c N /dev/zero | curl ..."` shell pipeline instead of trying to chain Python asyncio processes via stdin/stdout (which silently breaks).
- **Internet status pill hover bug** — text was unreadable on hover because the global `button:hover` rule applied `background: var(--accent)` which collided with the per-segment text colors. Pill now has its own hover background override.
- **Tools section UX** — orphaned dig record-type selector replaced with a properly labeled two-field layout (target + dig record type, with hints under each)
- **iptables LOG rule positioning** — now installed via `iptables-manager.ensure_base_chain()` at the correct line position (just before the trailing DROP), with proper idempotent removal when `WGFLOW_IPTABLES_LOG=0`

---

## 📦 New API endpoints

```
GET    /api/peers/{id}/ping
GET    /api/peers/{id}/config?dns=...                  (new query param)
GET    /api/peers/{id}/qr?dns=...                      (new query param)
GET    /api/peers/{id}/install-script?dns=...          (new query param)
GET    /api/metrics/cumulative
POST   /api/metrics/cumulative/reset?confirm=RESET
GET    /api/network/speedtest/endpoints
DELETE /api/network/speedtest/history?confirm=DELETE
POST   /api/network/diag/iperf3                        (new tool)
```

The peer-create endpoints (`POST /api/peers`, `/batch/names`, `/batch/count`) accept an optional `dns` field in the request body.

---

## 🗄️ Schema changes (auto-migrated)

```sql
ALTER TABLE peers ADD COLUMN dns TEXT;
ALTER TABLE speedtest_history ADD COLUMN endpoint TEXT;
CREATE TABLE cumulative_traffic (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    rx_total INTEGER, tx_total INTEGER,
    rx_offset INTEGER, tx_offset INTEGER,
    last_raw_rx INTEGER, last_raw_tx INTEGER,
    updated_at INTEGER
);
```

Migration code in `app/db.py:_migrate()` runs idempotently on every startup.

---

## 🐳 Container changes

The Dockerfile adds:
- `iperf3` — required for the new diagnostic tool

`docker-compose.yml` adds:
- `WGFLOW_IPTABLES_LOG: "0"` — opt-in iptables drop logging
- `WG_LOCAL_DNS: "1"` — explicit toggle (was implicit)
- Capability `NET_RAW` — required for ICMP-based diagnostics
- Commented `kern.log` bind-mount example for the wireguard / iptables log streams

---

## 🛣️ Known limitations / future work

These were considered for v3.0 but deferred:

- **Per-peer bandwidth limits** (would need `tc` HTB classes per peer; ~1 week of work; viable up to ~50 peers before classifier complexity hurts)
- **Per-axis cumulative reset** (currently rx + tx zero together; would need separate offset rows)
- **Better speedtest servers** todo. maybe iperf for internal networks.
- **Multi-interface support** (one wgflow → multiple wg interfaces; significant refactor)
- **Multi-server support** (many wgflow → multiple management; significant refactor)

See the README's "Roadmap" section for the full list.

---

## 🙏 Credits

All the changes since v2.1 were driven by direct operator feedback. Bugs caught early, features scoped tightly, no creep.

Issues and PRs welcome at [github.com/gcblauth/wgflow](https://github.com/gcblauth/wgflow).
