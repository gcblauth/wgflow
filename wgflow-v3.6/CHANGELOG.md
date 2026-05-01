# Changelog

All notable changes to wgflow are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [3.6] — 2026-04-30

### Added
- **Tunnel settings (advanced)** in the server tab:
  - **Client MTU** in generated `.conf` files. New `client_mtu` setting
    in `network_settings` (validated to 576..1500). When set, every
    downloaded peer config gets an `MTU = <value>` line under
    `[Interface]`. Five preset buttons in the UI cover common cases:
    default (clear), 1420 (WireGuard default), 1412 (PPPoE), 1380
    (CGNAT/double-NAT), 1280 (IPv6 minimum / mobile fallback).
    Affects newly-downloaded configs only — existing imported clients
    keep their stored MTU until they re-import.
  - **MSS clamping toggle.** When enabled, installs an iptables mangle
    rule on FORWARD that rewrites TCP SYN packet MSS values to fit the
    path MTU (`-j TCPMSS --clamp-mss-to-pmtu`). Fixes TCP black-hole
    on paths where ICMP fragmentation-needed is filtered (very common
    on consumer ISPs). Idempotent; survives container restarts via
    startup replay.
  - New endpoints: `GET/PUT /api/server/tunnel`
  - New `TunnelSettings` Pydantic model
- **ACL comments.** Each ACL entry can carry an optional human label
  via inline `#` syntax: `192.168.0.0/16 # home LAN`,
  `!10.0.0.5:22/tcp # block ssh from this peer`. Comments persist in
  a new `peer_acls.comment` column (NULL for pre-3.6 rows; capped at
  80 chars in the parser). Surfaced in:
  - the ACL editor's preview chips (italic muted suffix)
  - the ACL stats panel (rendered next to each rule)
  - the `__str__` form returned by `GET /api/peers` so configs round-trip
- **iptables raw viewer.** New "view raw iptables" button in the
  server tab opens a modal showing the full filter+nat dump from
  `iptables -L -n -v --line-numbers`. Auto-refreshes every 3 seconds
  while open; pauses when document is hidden. Substring filter
  hides non-matching lines client-side. WGFLOW-related rules are
  highlighted in the accent color, chain headers in the secondary
  color. Read-only — for inspection, not editing.
  - New endpoint: `GET /api/iptables/dump` returning plain text
- **Drag-to-reorder dashboard panels.** Two top-level panels are now
  reorderable via a drag handle (⋮⋮) on the panel header that appears
  on hover: `throughput` and `dns-recent`. Order persists per-instance
  in `network_settings.panel_order` (JSON array). Native HTML5 DnD;
  drop targets show top/bottom border highlight indicating the
  insertion point.
  - New endpoints: `GET/PUT /api/server/panel-order`
  - New `PanelOrder` Pydantic model
  - **Limitation:** the live-peers + server-settings columns share a
    CSS grid wrapper and are not independently reorderable. The
    `logs` panel is in a separate `<div class="wrap">` and has no
    drag siblings. Future work could restructure the wrap layout to
    enable richer reorder.
- **`scripts/wgflow-update`** — Docker-flavored update script. Takes a
  path to an extracted source tarball, rsyncs new files into the
  compose directory, runs `docker compose build && docker compose up -d`,
  shows the last 30 log lines. Validates that the source has the
  expected layout (`Dockerfile`, `app/`, `entrypoint.sh`) before
  touching anything; refuses to run as non-root. Does NOT touch
  `docker-compose.yml`, `.env`, or the bind-mounted data directory.
- **`scripts/wgflow-backup`** — host-side data backup. Tar+gzip of the
  bind-mounted data directory to `/var/backups/wgflow/`, timestamped,
  with retention pruning (default 14 days). Safe to run while wgflow
  is up (sqlite WAL handles concurrent reads). Inline systemd timer
  install hints at the bottom of the script.

### Changed
- **Bare-metal install path is now experimental.** `entrypoint-baremetal.sh`,
  `install-baremetal.sh`, and the README's deployment-paths section all
  carry an "experimental — Docker is recommended" note. Existing
  bare-metal installs keep working; new features may have Docker-only
  paths and bare-metal-specific bugs are addressed on request rather
  than as a release blocker.

### Database migrations
- `peer_acls` gains a `comment` TEXT column. Existing rows have NULL
  comment, treated as empty string by the loader.
- `network_settings` seeds three new keys on first install:
  `client_mtu` (empty), `mss_clamp` ("0"), `panel_order` (empty).
  Existing 3.5 installs upgrade silently.

### Notes
- The MTU client config knob is global, not per-peer. If half your
  clients are on PPPoE and half on cable, no single value fits both —
  per-peer override is queued for a future release.
- MSS clamping uses `--clamp-mss-to-pmtu` (auto-detect) rather than a
  hardcoded MSS value. If your environment specifically needs a fixed
  MSS (e.g. exactly 1360), the rule shape would need to change in
  `iptables_manager._MSS_CLAMP_ARGS` — say so and I'll add a
  hardcoded-value override knob.
- Drag-to-reorder shipped initially with only 2 reorderable panels, then
  was expanded to 5 in a v3.6 in-place patch (see "Post-release additions"
  below).

### Added (post-release additions to v3.6)
- **ACL stats panel pause/resume button.** Operator-controlled toggle
  that overrides the automatic visibility-based pause. Sits next to
  the reset button. When paused, polling stops regardless of tab
  visibility and stays paused across panel switches until manually
  resumed. Status line reflects state ("paused · last poll HH:MM:SS"
  vs "last poll HH:MM:SS · refreshing every 3s").
- **Drag-to-reorder expanded to 5 panels.** The dashboard's two-column
  CSS grid (live peers + peer management side-by-side) was flattened
  to a stacked single-column layout. All 5 main panels are now drag-
  reorderable as siblings: throughput, dns-recent, live-peers,
  server-management, logs. The previous two-`<div class="wrap">` split
  was merged into a single wrap so the logs panel can reorder with
  the others.
  - **Visual change:** on wide monitors the dashboard is now a single
    tall column rather than two side-by-side. Live peers and peer
    management are stacked vertically by default. This is intentional
    — the tradeoff for full reorder flexibility.
- **Reset panel order button** in the server tab. Clears the persisted
  panel order and reloads the page so panels appear in DOM source
  order. Useful if reorder leaves the layout in an unwanted state.
- **Panel minimize.** Each reorderable panel gets a `−` / `+` button
  (next to the drag handle) that collapses the panel to just its
  header. State persists per-instance in `network_settings.panels_minimized`.
  Per the user's design call: minimize is purely visual — background
  work continues for all panels. The new live-icon tooltip (below) is
  the instrumentation that makes this trade-off observable.
  - New endpoints: `GET/PUT /api/server/panels-minimized`
- **Live-icon tooltip + polling config.** The `status` indicator in the
  header (next to "uptime") is now interactive:
  - **Hover** shows a tooltip with current WebSocket count + breakdown
    by source (e.g. "1 WebSocket open · /ws/status: 1"). Updates live
    via the `ws_count` field added to the `/ws/status` payload.
  - **Right-click** opens a small popup with a slider to adjust the
    global polling interval (1000–6000 ms; default 3000). Affects ACL
    stats, DNS recent, iptables modal. Saves on slider release.
  - New backend: `_WSCounter` class instrumenting `/ws/status` and
    `/ws/logs/<source>` connections (increment on accept, decrement
    in finally so abnormal teardown still reconciles).
  - New endpoints: `GET/PUT /api/server/polling`

---

## [3.5] — 2026-04-29

### Added
- **Per-peer enable/disable.** Pause a peer without deleting them — config
  and ACLs are preserved, but the kernel's `wg syncconf` excludes them
  so they can't connect. Re-enabling restores fully. UI: ▶/⏸ button per
  row, red status dot, dimmed row, "disabled" badge next to the name.
  Active sessions are cut immediately on disable (operator confirmation
  required because of this); enable is non-destructive so no confirm.
  - New endpoint: `PUT /api/peers/{id}/enabled` with `{enabled: bool}`
  - `PeerOut` model gains `enabled: bool` (default `True`)
  - Disabled peers' status dot uses the danger red, distinct from idle
    yellow ("used to be online") and the never-connected grey
- **Instance identity (name + color theme).** Each wgflow install can
  now have a display name shown in the header next to the `[wgflow]`
  logo, plus one of five phosphor-CRT-inspired color themes:
  - `phosphor` (green, default) — historical accent, matches earlier versions
  - `amber` — IBM 3279
  - `cyan` — late-90s SGI / Tron
  - `magenta` — vaporwave / synthwave
  - `ice` — cool oscilloscope / Macintosh aqua

  Each theme has dark and light mode variants. Theme + name persist in
  `network_settings`; survive container restarts. Two entry points:
  - **Header chrome:** right-click the name (or click the ⚙ that
    appears on hover) for a popover with name input + color swatches
  - **Server tab → instance identity** card with the same controls,
    discoverable + mobile-friendly
  - New endpoints: `GET/PUT /api/server/instance` with `{name, color_theme}`
  - New `InstanceConfig` Pydantic model
  - Server-side validation: theme must be in the allow-list, name capped
    at 40 chars, control characters rejected
- DB migration seeds `instance_name=""` and `instance_color_theme="phosphor"`
  on first install. Idempotent on restart; doesn't disturb upgrade-from-3.4
  databases (the existing rows are preserved).

### Changed
- Header markup gains an `instance-chrome` span between `[wgflow]` and
  the `wireguard control panel · v3.5 · …` subline. Hidden by default
  when no name is set, so a fresh install or upgrade-without-naming
  looks visually identical to v3.4.
- Status-dot CSS gains a `disabled` variant (red, no pulse). The default
  three-state semantics (online / idle / never-connected) are unchanged.

### Fixed
- **WebSocket connection leak in `/ws/status`.** Closing a browser tab
  used to leave the corresponding `ws_status` task running for up to
  ~2 hours (until TCP retransmit timeout finally surfaced the dead
  socket on the next `send_text`). Each leaked task kept doing 1 DB
  query + 1 `peer_sparkline` lookup + 1 send per second. Over a day
  of opening/closing tabs, the asyncio event loop got backed up
  enough that the panel stopped accepting new connections; systemd
  would then time out trying to stop the unit and SIGKILL the worker.
  Fix: refactor to `asyncio.wait(FIRST_COMPLETED)` on a send loop +
  recv watchdog, so `receive_text()` detects client disconnect
  promptly and we cancel the send loop. Same pattern already used
  by `_stream_subprocess` for log streams. Cleanup verified via
  three integration tests covering recv-disconnect, send-error, and
  no-orphan-task paths.
- **Wireguard / iptables log streams broken on bare-metal Ubuntu.**
  The streams expected `/var/log/kern.log`, which doesn't exist on
  modern Ubuntu (22.04+) without rsyslog — kernel logs live only in
  journald. Streaming silently failed with a Docker-specific error
  message ("host kernel log not bind-mounted"). Fix: detect the
  absence of `/var/log/kern.log` and fall back to `journalctl -k -f
  --no-pager` (with `--grep` for server-side filtering). Docker
  path unchanged (still uses `tail -F` on the bind-mounted file).
  Error messages updated to mention both paths.
- **Bare-metal entrypoint** now mirrors the Docker one's
  `WGFLOW_IPTABLES_LOG=1` advisory log line so the operator gets
  confirmation in journalctl when drop-logging is enabled.
- **Explicit deny ACLs were silent in the iptables-drops stream**, even
  with `WGFLOW_IPTABLES_LOG=1`. The env-var-gated LOG rule only fired
  on the fall-through path (packets unmatched by any allow rule);
  explicit denies (`!192.168.111.2:22/tcp`) installed plain `-j DROP`
  rules with no LOG. Operators monitoring the iptables panel saw
  nothing even though their denies were correctly blocking traffic.
  Fix: when `WGFLOW_IPTABLES_LOG=1`, `apply_peer_acls` now installs a
  rate-limited LOG rule (10/min, burst 5) flanking each explicit deny
  on both the per-peer FORWARD chain and the INPUT chain. Same
  `WGFLOW-DROP:` prefix as fall-through drops, so the existing stream
  filter catches both. Cleanup path (`_flush_input_deny_rules`)
  extended to remove LOG rules alongside their DROP partners.
- **Peer name column floor** added (`min-width: 180px`) so the name
  column doesn't get squeezed below readability when the endpoint
  column flexes wide. Actions column tightened from 215px to 195px
  to compensate for v3.5's enable/disable icon button taking less
  space than initially budgeted.

### Added (post-release additions to v3.5)
- **Five additional color themes** (10 total): `lime` (electric
  yellow-green), `pink` (saturated hot pink), `purple` (lavender-leaning
  deep purple), `gold` (warm yellow), `mint` (cyan-green). Each has
  dark and light mode variants matching the existing theme system.
  Server-side allow-list extended; client-side picker now renders 2
  rows of 5 swatches.
- **Click-to-edit ACL on the live peers row.** The allow/deny rule
  counts under each peer's name are now a button — one click opens
  the same ACL editor that previously required two clicks via the
  `actions → acl` path. Hover shows a dotted underline + slight
  brightening to signal interactivity. Keyboard-accessible (button
  semantics, focus-visible outline).
- **ACL stats panel** replaces the iptables-drops log stream. The
  log-streaming approach to "iptables drops" doesn't work reliably
  inside Docker containers (kernel netfilter logs are netns-isolated by
  default, requiring `nf_log_all_netns=1` on the host plus working
  rsyslog → kern.log routing — fragile). The new panel polls per-rule
  packet/byte counters every 3 seconds via `iptables-save -c` and
  computes pkts/sec deltas client-side. Works identically on bare-metal
  and Docker. Click "edit acl ↗" on any peer card in the panel to jump
  straight to that peer's ACL editor. Reset button zeros per-peer
  FORWARD chain counters; INPUT-chain counters are preserved (touching
  INPUT could affect operator-managed rules — re-saving the peer's ACL
  is the safe way to reset those).
  - New endpoints: `GET /api/peers/acl-stats` and `POST /api/peers/acl-stats/reset`
  - `iptables` source removed from log_streams DISPATCH and availability()
  - The `stream_iptables` function is preserved in log_streams.py but
    unreachable; future work could re-enable via NFLOG netlink for
    real-time drops without kernel-log delivery dependency

### Notes
- Theme switching takes effect immediately — no page reload needed. The
  CSS uses scoped `[data-instance-theme="…"]` blocks layered over `:root`,
  so all `var(--accent)` consumers update in one paint.
- The popover opens via right-click on the name; on touch devices (no
  right-click) the same controls live in the server tab.
- Peer enable/disable doesn't touch iptables chains. The chain stays in
  place but no traffic ever hits it (kernel doesn't have the [Peer] block
  to source-match against). On re-enable, the chain is already there
  and ACLs apply immediately.

---

## [3.4] — 2026-04-29

### Added
- **Migration toggle.** The migration importer (added in 3.3) is a
  one-time-use feature for most deployments; once it's served its
  purpose, operators typically want the `/api/import/*` endpoints
  locked down. New persistent toggle controls visibility:
  - **Server tab → migration importer** has an enable/disable checkbox
    that flips the state via `PUT /api/server/migration`. Persists in
    `network_settings` so it survives container restarts.
  - **Post-commit nudge.** After a successful import commit, a banner
    on the result screen prompts "migration is still enabled — disable
    now?" with a one-click button. Dismissable; if ignored, the
    importer stays enabled (fail-open default for a reversible op).
  - **Tab visibility.** When disabled, the migrate tab is hidden
    entirely from the peer-management panel. Re-enable any time from
    the server tab.
  - **Fresh-install default** is configurable via
    `WGFLOW_MIGRATION_DEFAULT_ENABLED` env var (default `1`). Once the
    DB row exists, env var is ignored — runtime UI/API toggle is
    authoritative across restarts. Matches the `auto_interval_min`
    pattern: env var seeds, DB wins.
  - All three import endpoints (`POST /api/import/upload`,
    `GET /api/import/preview/{id}`, `POST /api/import/commit`) return
    `403 {"detail": "migration is disabled..."}` when the toggle is off.
- New API: `GET /api/server/migration` returns `{enabled: bool}`,
  `PUT /api/server/migration` with `{enabled: bool}` flips it.
- New `MigrationToggle` Pydantic model in `app/models.py`.

### Changed
- `app/db.py` `_migrate()` seeds the `migration_enabled` row in
  `network_settings` on first install. Backward-compatible: existing
  3.3 databases get the row added on next startup with the env-var-derived
  default.

---

## [3.3] — 2026-04-29

### Added
- **Importers for migrating from other WireGuard managers.** New
  *migrate* tab in the peer-management panel accepts a single upload and
  auto-detects the format. Supported sources:
  - **wg-easy v1-v14** (`wg0.json`)
  - **wg-easy v15+** (`wg-easy.db` SQLite)
  - **PiVPN** (tar/zip of `/etc/wireguard/{wg0.conf,configs/}`)
  - **Bare WireGuard** (`wg0.conf` with `[Interface]` + `[Peer]` blocks)

  Imports go through a dry-run preview that shows each peer's status
  (`ok`, `name-conflict`, `pubkey-conflict`, `address-conflict`,
  `address-out-of-range`, `invalid`) and lets the operator toggle which
  peers to import. Out-of-range source addresses are auto-reassigned
  from the wgflow free pool. Operators must type `IMPORT` to commit.
- **Server-keypair adoption** during import (default ON when source has
  one). Replaces wgflow's server private/public key files with the
  source's so existing client configs continue working without reissue.
  Skipped automatically for bare-WG sources without `[Interface]
  PrivateKey` and v15 SQLite DBs whose schema we couldn't recognise.
- **Bare-WireGuard peer support.** Schema gains a `has_private_key`
  column (default 1, backward-compatible via migration). Peers imported
  from bare-WG sources are stored with `has_private_key=0` and an empty
  `private_key`. The "download config" button is disabled for these
  peers (the operator's clients already have working configs);
  `/api/peers/{id}/config` returns 422 with a descriptive message.
- New API endpoints: `POST /api/import/upload` (multipart),
  `GET /api/import/preview/{id}` (re-fetch a stashed preview),
  `POST /api/import/commit` (apply chosen peers + adopt key + IMPORT
  token).
- New `app/importers/` package: `parsed.py` (universal IR + validators),
  `detector.py` (auto-dispatch by file magic), `wg_easy.py`,
  `pivpn.py`, `bare_wg.py`, `commit.py` (status compute + transactional
  apply), `preview_store.py` (in-memory cache, 10-min TTL),
  `serialize.py` (JSON shape for the UI; never includes secrets).
- Defensive validation in `app/importers/parsed.py` is stricter than
  the existing `/api/peers` validation: peer names limited to a safe
  ASCII regex so values that would break wg0.conf rendering get
  rejected at import.
- Test suite under `app/importers/tests/` exercises parsers + status
  compute + preview store TTL + JSON shape against synthesized
  fixtures (no live WireGuard required).

### Changed
- `PeerOut` model gains `has_private_key: bool` (default `True`).
  Existing API consumers that don't read the field are unaffected.

### Notes
- Importing a wg-easy v15 SQLite DB is best-effort — upstream's schema
  has shifted across point releases. The parser tries multiple known
  table/column name variants and surfaces a clear warning if none
  match. The reliable v15 migration path remains: use wg-easy's own
  "back up to wg0.json" feature first, then upload the JSON to wgflow.
- Importer doesn't translate source `AllowedIPs` into wgflow ACLs —
  AllowedIPs is a routing concept, ACLs are a firewall concept, and
  the mapping isn't clean. Imported peers come in with the server
  default ACL; operator adjusts as needed.

---

## [3.2] — 2026-04-29

### Added
- **Anonymous telemetry** — every 30 minutes the container POSTs a small JSON
  payload (instance UUID, version, peer count, cumulative rx/tx, uptime) to
  `https://wgflow.2ps.in/collect`. Default ON; opt out with
  `WGFLOW_TELEMETRY_ENABLED=0`. Body is HMAC-SHA256 signed; the key is either
  the operator-set `WGFLOW_TELEMETRY_SECRET` or, when unset, a community
  constant baked into the source. Signature is an integrity check only; the
  collector defends against forgery via per-IP rate limits and a pending →
  approved promotion rule (10+ check-ins over ≥24 hours). The README's new
  "Telemetry" section spells out exactly what is sent and how to disable
- Per-instance `instance_id` (uuid4) seeded into `network_settings` on first
  DB init via the existing migration path
- New env vars: `WGFLOW_TELEMETRY_ENABLED` and `WGFLOW_TELEMETRY_SECRET`,
  documented in README's Configuration tables
- `setup.sh` prompts for telemetry preference; .env is now `chmod 600` after
  generation; password prompt is silent (`read -s`)
- `WGFLOW_BIND` (container-side) and `HOSTBIND_WG_PANEL` (host-side) are now
  separate env vars instead of hardcoded values, so operators can set both
  via the wizard
- `httpx==0.27.0` added to `requirements.txt` for the telemetry HTTP client

### Fixed
- `setup.sh` wrote `HOSTBIND_WG_PANEL` to `.env` while `docker-compose.yml`
  read `${HOSTBIND_WGFLOW_PANEL}` — fresh installs failed with an empty
  port-mapping. Both now use `HOSTBIND_WG_PANEL`
- `WGFLOW_TELEMETRY_ENABLED` was parsed as a literal-`"1"` string check
  (`os.getenv(...) == "1"`), so `WGFLOW_TELEMETRY_ENABLED=true` silently
  disabled telemetry. Now uses the same `1|true|yes|on` parsing as
  `WG_LOCAL_DNS`
- `telemetry_enabled` was declared as a class-level default on a `frozen=True`
  dataclass, which prevented `Settings.load()` from controlling it. Moved to
  the proper field list and parsed inside `load()`
- The telemetry task was created without saving its handle, so it was never
  cancelled at shutdown — uvicorn would emit `CancelledError` tracebacks on
  exit. Task is now saved, cancelled, and awaited in the lifespan `finally:`
  block alongside `speedtest_task` and `prune_task`
- Removed the `db.get_db()` lazy factory that instantiated a second `DB`
  pointing at the same sqlite file. Telemetry now receives the live `db`
  from `main.lifespan`, matching how `dns_log.start(db, ...)` works
- `setup.sh`'s deny-rule example included `0.0.0.0/0` after the `!` entry,
  which taught the wrong mental model. Removed: the per-peer chain
  automatically appends a catch-all ACCEPT when any deny is present, so
  the operator never needs to write `0.0.0.0/0` themselves

### Changed
- Telemetry payload now includes a `version` field so the collector can
  break stats down by release without ambiguity
- First telemetry POST is delayed 90s after startup (was: immediate),
  giving operators a chance to opt out and preventing thundering-herd
  on host reboot
- README has a new "Telemetry" section right before "Exposing the admin
  UI safely" — both are operator-trust topics
- Version bumped to **3.2** in header, about modal, and setup.sh banner

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
