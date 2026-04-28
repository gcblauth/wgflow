# Changelog

All notable changes to wgflow are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [3.1] — 2026-04-28

### Added
- **Deny ACL rules** — prefix any ACL entry with `!` to block that destination
  (`!192.168.1.0/24`, `!10.0.0.1:22/tcp`, etc.)
- Deny rules now install `INPUT` chain DROP rules (scoped to the peer's tunnel
  IP) in addition to the existing `FORWARD` rules, so blocked destinations
  are unreachable even when traffic is addressed directly to the wgflow server
- Full-tunnel mode activates implicitly when any deny rule is present: the
  generated client config gets `AllowedIPs = 0.0.0.0/0`; a catch-all ACCEPT
  is appended to the per-peer chain after all deny rules
- Live colored preview in the ACL editor — deny rules shown in red, allow in
  green, updates as you type
- Warning in ACL editor when a deny rule covers the server's own wg address
  (would block the peer from reaching the admin panel)
- Export DB button in Server tab — downloads `wgflow.sqlite` as a consistent
  snapshot using sqlite's backup API
- Import DB button in Server tab — two-step confirmation (type IMPORT), full
  schema validation, atomic swap, automatic kernel state rebuild after import;
  keeps a `.pre-import.bak` of the previous database
- DB export/import require `python-multipart` (added to `requirements.txt`)
- About modal (click `gcblauth` in the header) showing version, tagline,
  GitHub link
- setup.sh to create .env dedicated file

### Changed
- "Danger zone / delete all peers" moved inside the **Server** tab — no longer
  visible from Add One / Batch Names / Batch Count tabs
- Per-peer ACL count in the peer table now shows just colored numbers with a
  hover tooltip (`3` in green for allow-only; `3/1` green/red for mixed) —
  the old expandable chip list that overlapped the table is gone
- Version bumped to **3.1** in header and about modal

### Fixed
- `_row_to_peer_out` was querying `peer_acls` without the `action` column,
  so deny entries were silently rendered as allow entries (`!` prefix lost).
  API now returns correct `!`-prefixed strings; peer table and ACL editor
  display deny rules correctly
- iptables parser regex was hardcoded to `ACCEPT` — DROP rules were silently
  skipped in ACL hit counts. Parser now captures both `ACCEPT` and `DROP` and
  surfaces the action in the inspect modal
- SQLite `ALTER TABLE ADD COLUMN` only sets `DEFAULT` for new inserts, not
  existing rows. Migration now runs `UPDATE peer_acls SET action = 'allow'
  WHERE action IS NULL` to backfill pre-migration rows

---

## [3.0] — 2026-04-27

### Added
- **Per-peer DNS preference** — each create form (single, batch-names,
  batch-count) has a checkbox + editable input; untick to omit the `DNS =`
  line entirely (split-tunnel friendly). Stored in `peers.dns` column.
  Overridable at download time via `?dns=` query param on `/config`, `/qr`,
  `/install-script`
- **Persistent cumulative rx/tx counters** — survive container restarts;
  reset detection handles wg interface restarts gracefully. New `↺` reset
  button (type RESET to confirm). Polled from server every 30s
- **Multi-endpoint speedtest** — 5 providers: Cloudflare (↓↑), Hetzner
  Falkenstein/Helsinki/Ashburn (↓ only), OVH Roubaix (↓ only). Dropdown
  grouped by upload support; download-only endpoints show a warning
- Reworked speedtest chart: proper labelled Y-axes (Mbps left, ms right),
  X-axis time range, area fills, hover crosshair with floating readout,
  per-endpoint colored sample dots
- Dynamic speedtest hint text — shows correct provider name and MB-per-test
  estimate; shows daily volume estimate when a schedule is active
- **7 diagnostic tools**: ping (configurable count, default 3), traceroute,
  mtr, dig, curl timing, TCP port test, **iperf3** (new)
- `iperf3` added to Dockerfile and apt packages
- Clear speedtest history button (type DELETE to confirm)
- **Peer ping widget** in inspect modal — one-shot or live (5s interval),
  shows split-tunnel ICMP filtering hints, auto-stops on modal close
- `WG_LOCAL_DNS=0` support — disables dnsmasq stack; DNS panels auto-hide;
  `peer_dns` auto-derives to `1.1.1.1` when local DNS is off
- Internet status pill in top bar: public IP + last speedtest colored by
  rx/tx theme variables; hover tooltip shows test timestamp and ping

### Changed
- Version bumped to **3.0** in header
- `WG_PEER_DNS` default removed from compose — now auto-derives from
  `WG_SERVER_ADDRESS` (when `WG_LOCAL_DNS=1`) or `1.1.1.1` (when off)
- `NET_RAW` capability added to compose for ICMP-based diagnostics
- Animation time after login: 1.8s → 2.5s
- Ping tool default count changed from 10 (2s timeout each) to 3 (1s timeout)

### Fixed
- Speedtest upload: `'StreamReader' object has no attribute 'fileno'` — fixed
  by using `bash -c "head -c N /dev/zero | curl ..."` shell pipeline
- Internet status pill hover: text was unreadable (global `button:hover`
  applied `background: var(--accent)` conflicting with per-segment colors)
- iptables LOG rule now positioned correctly just before the trailing DROP

### Schema migrations (auto-applied on startup)
```sql
ALTER TABLE peers ADD COLUMN dns TEXT;
ALTER TABLE speedtest_history ADD COLUMN endpoint TEXT;
CREATE TABLE cumulative_traffic ( ... );
CREATE TABLE network_settings ( ... );
```

---

## [2.1] — 2026-04

### Added
- **Logs panel** — 4 on-demand WebSocket streams (dnsmasq, wireguard,
  iptables drops, access). Zero resource cost when not watching.
  500-line buffer, substring filter, export to .txt
- `WGFLOW_IPTABLES_LOG` env var — opt-in iptables drop logging with rate
  limit (10/min, burst 5). Off by default
- Optional `/var/log/kern.log` bind-mount for wireguard/iptables log streams
- **DNS override tab** — map domains to internal IPs; persisted in sqlite;
  replayed to dnsmasq on startup
- Encrypted ZIP Windows installer per peer — `.ps1` + embedded `.conf`,
  AES-256, 8-word Diceware passphrase in response header
- Per-peer "actions" collapse menu in the peer table
- Three-state peer status dots (never / idle / online) with `last_handshake_at`
  persisted across restarts
- Pagination, search, and ellipsis pages on the peer table
- Cumulative rx/tx stat tiles in the dashboard header
- Container uptime display

### Changed
- Auth switched to HTTP middleware (fixes WebSocket `TypeError` on missing
  request parameter in FastAPI's dependency injection)
- `WG_LOCAL_DNS` toggle for the entire dnsmasq stack

---

## [2.0] — initial release

- Single-container WireGuard gateway with FastAPI admin panel
- Per-peer iptables chains with default-deny ACL enforcement
- Peer CRUD (single and batch), config download, QR code
- Live WebSocket status stream (peers + host vitals + throughput)
- Throughput chart (live / 1h / 6h / 24h)
- Per-peer 60s sparkline
- Host vitals tiles (CPU / mem / load)
- Inspect modal: endpoint, top destinations, ACL hits, live conntrack flows,
  raw wg show, DNS queries
- DNS recent queries panel with per-source color coding
- dnsmasq local resolver with StevenBlack blocklist (~140k entries)
- Light/dark theme with no FOUC
- `PANEL_PASSWORD` auth (bcrypt, 24h cookie session)
- Matrix rain boot animation
