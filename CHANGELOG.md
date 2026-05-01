# Changelog

All notable changes to wgflow are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [3.8.3] — 2026-05-01

### Fixed
- **DNS overrides still silently ignored on some setups**, even after
  the v3.8.1 conf-dir fix. Operators reported overrides like
  `reconta.cloud → 192.168.99.132` rendering correctly to
  `/etc/dnsmasq.d/wgflow-overrides.conf`, the conf-dir directive
  appearing in `/etc/dnsmasq.conf`, dnsmasq running and processing
  queries — but the queries were being forwarded upstream and
  answered with the public IP. The smoking gun in the dnsmasq query
  log was `forwarded reconta.cloud to 8.8.8.8`, proving the
  `address=/reconta.cloud/192.168.99.132` directive was not loaded.

  Root cause undetermined — likely a subtle interaction between
  `conf-dir` extension filter parsing (`*.conf` vs `.conf`),
  drop-in load order, and dnsmasq build-time options. Different
  base images parse this differently.

  **Fix:** stop using a drop-in file. Render `address=` directives
  directly into `/etc/dnsmasq.conf` itself, between marker comments
  (`# __WGFLOW_OVERRIDES_BEGIN__` / `# __WGFLOW_OVERRIDES_END__`).
  This eliminates the conf-dir variable entirely — if dnsmasq
  starts with `--conf-file=/etc/dnsmasq.conf` at all, it sees the
  directives.

  Mechanics:
  - `dnsmasq.conf.template` has a `# __WGFLOW_OVERRIDES__` marker.
  - `entrypoint.sh` strips the marker on initial render.
  - `app/dns_overrides.py` reads the live `/etc/dnsmasq.conf`,
    splices the rendered address block in/out via the BEGIN/END
    markers, writes atomically, then SIGTERM+respawns dnsmasq.
  - On startup, the lifespan hook calls the same render path so
    DB-stored overrides are applied immediately.
  - Legacy `/etc/dnsmasq.d/wgflow-overrides.conf` is replaced
    with a comment-only stub on first v3.8.3 mutation, so any
    leftover content from v3.8.x can't sneak entries in.

### Notes
- **Existing operators MUST `docker compose down && up`** (not just
  restart) after deploying v3.8.3. The new template + entrypoint
  must run to render the new `/etc/dnsmasq.conf` with the
  `__WGFLOW_OVERRIDES__` marker in place. Mere `docker compose
  restart wgflow` re-runs entrypoint inside the existing container,
  which IS sufficient — but a fresh `down && up` is recommended
  to also pick up any other changes.
- **The conf-dir directive is removed** from the template. If you
  had drop-in `.conf` files in `/etc/dnsmasq.d/` for other reasons
  (custom blocklists, manual overrides), they'll stop being loaded.
  Move their contents into a custom `addn-hosts=` file or directly
  into `/etc/dnsmasq.conf` via a docker volume mount.
- **The blocklist still works** — it's loaded via the explicit
  `addn-hosts=/etc/dnsmasq.d/blocklist.hosts` line, which doesn't
  depend on conf-dir.

---

## [3.8.2] — 2026-05-01

### Fixed
- **DNS override respawn could fail silently.** The v3.8.1 fix
  spawned a new dnsmasq via `subprocess.Popen` with stdout+stderr
  both redirected to `/dev/null`, then returned without checking
  whether the new process was actually alive. If the new dnsmasq
  failed to bind to port 53 (because the kernel hadn't released the
  socket yet from the old process — a brief TIME_WAIT can linger
  after `bind-interfaces` socket close), it would exit immediately
  with a clear error message — but we'd never see the message and
  no dnsmasq would be running.

  Symptoms: operator added an override, expected entries continued
  to be answered from the previous dnsmasq's cache (because the new
  dnsmasq was dead and the old one was somehow still answering), or
  DNS broke entirely.

  Fix:
  1. Increased the wait-for-old-process-exit window to 3s
     (was 2s), plus 200ms after exit to let the kernel release
     bound sockets cleanly.
  2. The respawn now captures stderr and waits 300ms after spawn
     to see if the new dnsmasq exited immediately. If it did,
     the captured stderr is logged so the operator can see what
     went wrong (e.g. `dnsmasq: failed to bind listening socket
     for 10.1.69.1: Address already in use`).
  3. Logs the new pid on success so operators can confirm via
     `docker exec wgflow ps aux | grep dnsmasq` that the right
     process is running.

### Notes
- **Existing operators experiencing the bug:** restart the container
  (`docker compose restart wgflow`) and try the override again. If
  the override now works, the previous failure was the silent
  respawn bug. If it still doesn't work, the captured stderr will
  now be in the wgflow container logs (`docker compose logs wgflow`)
  and we can investigate from there.

---

## [3.8.1] — 2026-05-01

### Fixed
- **DNS overrides never reached dnsmasq** (regression introduced
  before v3.8 — bug was latent until an operator actually configured
  an override). Two compounding causes:

  1. **No `conf-dir` in dnsmasq.conf.template.** The drop-in file
     `/etc/dnsmasq.d/wgflow-overrides.conf` was being written
     correctly, but dnsmasq's main config never told it to load files
     from `/etc/dnsmasq.d/`. The blocklist was loaded explicitly via
     `addn-hosts=...` so it worked, but the overrides drop-in was
     invisible to dnsmasq.
     **Fix:** added `conf-dir=/etc/dnsmasq.d/,*.conf` to the template.
     The `,*.conf` filter prevents `blocklist.hosts` from being re-loaded
     as a config file.

  2. **SIGHUP doesn't reload `address=` directives.** Even with the
     drop-in loaded at startup, the previous code SIGHUPed dnsmasq
     after writing the file. SIGHUP only reloads `addn-hosts`, the
     leases file, and a handful of other runtime files — it does NOT
     re-parse main config or `conf-dir`-loaded `*.conf` files.
     dnsmasq parses `address=` only at startup.
     **Fix:** `dns_overrides.write_and_reload()` now SIGTERMs the
     running dnsmasq, waits up to 2s for it to exit cleanly, and
     spawns a fresh dnsmasq process with the same `--conf-file=`. Brief
     (~100ms) DNS outage during the swap, which is acceptable for an
     operator-initiated config change.

  Symptoms of the bug: operator added an override via the UI, the
  Active Overrides table showed it, but client queries continued to
  return NXDOMAIN with `UPSTREAM` in the dns recent queries log.

### Notes
- **The respawn path assumes the docker entrypoint shape.** The
  spawn uses `--conf-file=/etc/dnsmasq.conf`, which is what
  `entrypoint.sh` writes. If you've customised the entrypoint to
  use a different path, the new dnsmasq won't have the right
  upstreams. Bare-metal installations are unaffected because
  they use the same conf path.
- **Existing instances need a one-time container restart** to pick
  up the new `conf-dir` line in the rendered dnsmasq.conf. The
  override file is already on disk; once the new template is
  applied + dnsmasq restarts, all overrides start working
  immediately. Subsequent override changes don't need manual
  intervention.

---

## [3.8] — 2026-05-01

### Added
- **Mobile layout.** The dashboard now adapts to small screens
  (viewport ≤ 768px). Layout changes:
  - **Header** stacks vertically (brand on top, controls below).
  - **Stat strip** collapses from 7 cards to a 2-column grid showing
    only peers total + peers online by default. The other five
    (rx/tx/cpu/memory/load) hide behind a `▾ system stats` toggle
    (state persists per-device in localStorage).
  - **Live peers** swap from a wide table to stacked cards. Each card
    has the peer name + online indicator, address, handshake age,
    rx/tx rate, ACL summary, and a row of action buttons (inspect,
    enable/disable, actions, delete) sized for touch.
  - **Panels** get tighter header padding and smaller fonts.
  - **Logs** + throughput chart shrink in height to leave room for
    cards and content.
  - **Modals** become near-full-width.
  - **Drag handles** are hidden — replaced by long-press reorder.
- **Long-press reorder for touch devices.** On mobile, holding any
  panel's header for 500ms opens a small menu with `↑ move up`,
  `↓ move down`, and minimize toggle. Cancels on touchmove (so
  scrolling the panel list doesn't trigger the menu). HTML5
  drag-and-drop doesn't work on iOS Safari, so this is the dedicated
  touch path.
- **Per-form-factor saved layouts.** Panel order and minimize state
  are now stored separately for desktop and mobile, so the same
  wgflow instance can have a custom layout for each.
  - **Backend:** new keys `panel_order_mobile` and
    `panels_minimized_mobile`. Existing `panel_order` and
    `panels_minimized` continue as the desktop slots (backwards
    compat — pre-3.8 clients hitting unparametered endpoints still
    read/write the legacy slots).
  - **Endpoints:** `GET/PUT /api/server/panel-order` and
    `GET/PUT /api/server/panels-minimized` accept an optional
    `?form=mobile|desktop` query parameter. Default = desktop.
  - **Frontend:** detects form factor at boot from `window.innerWidth`
    (≤ 768 = mobile) and sends the matching `?form=` param on every
    save and load.
- **Form-factor toggle override.** The live-icon right-click popup
  now has a 3-button selector: `auto / desktop / mobile`. Selection
  persists in localStorage (per-browser, per-device). Reloads the
  page to apply.
- **Mobile-first-load defaults.** When a mobile session starts with
  no saved minimize state, throughput / dns-recent / server-management
  begin minimized so the visible scroll surface is live-peers + logs.
  As soon as the operator interacts with any panel, their choices
  persist as usual.
- **Layout diagnostic logging.** Set
  `localStorage.setItem('wgflow_layout_debug', '1')` in the browser
  console to enable verbose console logging of every save and load
  of panel order + minimize state. Logs include the active form
  factor and the result. Use to diagnose persistence issues.

### Database migrations
- Two new `network_settings` keys seeded with safe empty defaults:
  `panel_order_mobile`, `panels_minimized_mobile`.
- No table-level changes.

### Notes
- **Backwards compatibility.** A v3.7 client running against a v3.8
  server keeps working — the old endpoints (no form param) write to
  the legacy desktop slot, which is what the v3.7 client expects.
- **Force-mobile on a wide viewport produces a cramped layout.**
  Stat grid becomes 2 cols on a 1920px screen with lots of empty
  space, peers cards are narrower than they need to be. The toggle
  is provided because you asked for one, but the natural use case
  is forcing-desktop on a tablet, not the inverse.
- **Long-press reorder is best-effort on touch.** iOS Safari's
  touchstart/touchmove/scrollstart interaction is fiddly; if you
  find the long-press fights with scroll on a particular device,
  file it. The fallback is the existing minimize button (always
  works).

---

## [3.7] — 2026-04-30

### Added
- **ACL aliases.** Named groups of CIDRs that can be referenced from
  any peer's ACL via `@name` syntax. Operator defines `@home_lan =
  192.168.0.0/16, 192.168.1.0/24` once on the new "acl aliases" tab,
  then peers reference it as `@home_lan` (or `!@home_lan` to deny).
  Editing an alias body re-applies iptables for every referencing peer
  immediately.
  - **Constraints:** allow-only inside the body (deny prefix lives on
    the alias usage); no nesting (flat aliases only); deletion blocked
    while any peer references the alias.
  - **Storage:** new `acl_aliases` table + `acl_alias_refs` index +
    `peer_acls.alias_ref` column for storing alias references in peer
    ACLs without flattening. Alias references in peer_acls.alias_ref
    are expanded at iptables-apply time, so editing an alias's body
    automatically propagates without changing every peer's stored ACL.
  - **Endpoints:** `GET /api/acl-aliases`, `POST /api/acl-aliases`,
    `PUT /api/acl-aliases/{name}`, `DELETE /api/acl-aliases/{name}`.
  - **Editor integration:** the per-peer ACL editor recognizes
    `@name`, renders alias references with a dashed border + accent-blue
    color (vs solid border for literal CIDRs), warns on undefined
    references in the preview, and refuses to save if any reference
    is unresolved (server returns 422 with a clear message).
  - **Editing impact preview:** the alias edit modal shows how many
    peers reference the alias before save, and the toast on save
    reports how many got iptables re-applied.
- **PS1 installer custom passphrase.** When downloading the encrypted
  Windows installer zip, the operator can either auto-generate a
  Diceware passphrase (default, ~100 bits entropy) OR type a custom
  one (12-char minimum enforced server-side, with a 5-band strength
  meter in the UI). The custom passphrase is passed via
  `?passphrase=` on the install-script endpoint; auto-generated case
  matches v3.6 behaviour.
- **Private key view button** in the actions modal. Reveals the bare
  private key in a dedicated viewer with explicit warnings. Copy
  goes through the new `secureClipboardWrite` helper, which:
  - Surfaces a warning toast at copy time
  - After a configurable timeout, overwrites the clipboard with a
    single space (best-effort; browsers may reject out-of-gesture
    clipboard writes, in which case the timeout is silent and the
    operator was warned at copy time)
  - New endpoint: `GET /api/peers/{peer_id}/private-key` returns
    `{"private_key": "..."}` or 410 if the peer was imported without
    a private key.
- **Configurable clipboard auto-clear timer** in the live-icon
  right-click popup. Slider 0-120 seconds (0 = disabled). Same popup
  also has the polling interval slider from v3.6.
  - New endpoints: `GET/PUT /api/server/clipboard`
- **Peer config text viewer** in the actions modal. Replaces the
  download-only flow with a chooser: text view / download / QR. The
  text view shows the rendered .conf with the same secure-copy
  treatment as the private key viewer (warning + auto-clear).
- **Actions modal restructure.** The per-peer "actions" button now
  opens a tile chooser with: conf, qr, ps1 zip, acl, private key.
  All paths (especially conf-view and private-key) carry the
  appropriate security warnings.

### Changed
- The peer ACL save path now validates that every `@name` reference
  resolves to an existing alias before writing. Pre-3.7 peer ACLs
  (literal CIDRs only) save unchanged.

### Database migrations
- New `acl_aliases` table (name PK, JSON body, optional description).
- New `acl_alias_refs` index table (alias_name, peer_id) for fast
  reference counting.
- `peer_acls.alias_ref` column added (nullable). Existing rows have
  it as NULL — they remain literal CIDR rules.
- **`peer_acls` table rebuild for upgraded DBs.** The original v3.5
  schema declared `cidr TEXT NOT NULL`, which blocked alias-reference
  inserts (where cidr is NULL). v3.7 detects the old schema via
  `sqlite_master` introspection and rebuilds the table in-place,
  preserving row ids (and therefore source ordering for iptables
  emission). The UNIQUE constraint is also widened to include
  `alias_ref` so multiple alias rows for the same peer don't collide
  on the all-NULL (cidr, port, proto) tuple. Fresh installs skip the
  rebuild — they get the new schema directly from CREATE TABLE.
- Three new `network_settings` keys seeded with safe defaults:
  `clipboard_timeout_sec` (default "30").

### Notes
- **Aliases are flat by design.** Cannot reference one alias from
  inside another. The parser rejects `@other` inside an alias body
  with a 422. Reasoning: cycle detection adds complexity for marginal
  benefit. Flatten by hand if you find yourself wanting nesting.
- **Allow-only aliases by design.** The body cannot contain `!cidr`
  entries. Deny semantics apply to the alias *usage* — `!@home_lan`
  deny-expands to one DROP per CIDR in the body. Reasoning: aliases
  with internal denies create chain-target collision corner cases
  that the iptables rule generator wasn't designed for.
- **Deletion is gated.** An alias referenced by any peer cannot be
  deleted; the operator must remove the reference from each peer's
  ACL first. Reasoning: silent expansion-to-nothing on a missing
  alias is a footgun.
- **Clipboard auto-clear is best-effort.** Modern browsers may refuse
  clipboard writes that aren't tied to a user gesture; the setTimeout
  callback that overwrites the clipboard is one such case. The UI
  warns the operator at copy time so they know the value is
  sensitive — the auto-clear is a defense-in-depth, not a guarantee.

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
