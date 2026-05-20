# wgflow — Development Context (Claude handoff)

Archive document for resuming wgflow development in a future session.
Hand this to Claude (or any contributor) alongside the v4.3.0 source to
restore full working context.

**Project:** wgflow — single-container WireGuard gateway + admin panel.
**Maintainer:** gcblauth (Italian operator, English work language).
**Repo:** `git@github.com:gcblauth/wgflow.git`, branch `main`.
**Current release:** v4.3.0.

---

## What wgflow is

A Docker-first (bare-metal supported) WireGuard control panel. SQLite is
the canonical state store; the kernel (WireGuard interface, routes,
iptables) is rebuilt from SQLite via `_replay_state_to_kernel()`. The UI
is a single static `index.html` with a CRT / phosphor-green theme — no
build step. Heavy code comments are considered a deliverable.

For how each subsystem works, see `ARCHITECTURE.md` in this directory.

---

## Architecture invariants (must be preserved)

1. SQLite canonical; kernel rebuilt via `_replay_state_to_kernel()`.
2. Migrations: SAVEPOINT + `sqlite_master` regex introspection.
3. Frontend: single `index.html`, no build step.
4. Heavy comments are a deliverable, not optional.
5. Push back on architectural decisions before building — each redesign
   costs days.
6. Multisite stable identity: every link on a wgflow shares one
   `local_overlay_addr`.
7. Routes installed via `multisite.reconcile_routes` (`wg syncconf`
   does not install routes).
8. MASQUERADE for the overlay subnet exits via `!wg0`.
9. Self-healing orphan / self-reference cleanup runs on every replay.
10. `_live_wg0_pubkey()` is the single source of truth for the wg0 pubkey.
11. Both sides of a multisite peer use their respective wg0 server
    keypairs — no per-link keypairs (`importer_privkey` column is
    vestigial, always NULL).

---

## Maintainer working style (preserve these)

- Direct, succinct communication.
- Pushing back on scope creep is welcome and expected.
- Heavy code comments expected throughout.
- Each redesign costs days — give an explicit "are you sure?" before
  large structural changes.
- Trusts code-level diagnosis but expects packet-level / log-level
  evidence for hard bugs (py-spy dumps, `ss` output, journald).
- Work language English; maintainer is Italian — occasional Italian in
  conversation is normal.

---

## Pre-pack ritual (run before shipping any release tarball)

1. `ast.parse(src, feature_version=(3,11))` on every `.py` in `app/`.
2. Regex tokenizer guard for nested same-quote f-strings (the
   `f"...{...}..."` pattern that breaks on older parsers).
3. `node --check` on the JS extracted from `app/static/index.html`.
4. Strip `__pycache__/` and `*.pyc`.
5. `tar` with `--transform` so the tarball extracts to `wgflow-vX.Y.Z/`.

Version string lives in **one place**: `app/telemetry.py` →
`WGFLOW_VERSION`. The frontend header and `/healthz` both read from it
(frontend via `/api/server`-family endpoints / build-time; `/healthz`
directly). When bumping, also `sed` the `vX.Y.Z` strings in
`index.html`.

---

## Environment variables (canonical names)

These names are what `docker-compose.yml`, `app/config.py`, and
`entrypoint.sh` all agree on. `setup-one-time.sh` writes every one of
them explicitly into `.env`.

| Variable | Default | Notes |
|----------|---------|-------|
| `WG_ENDPOINT` | *(required)* | Public `host:port` for peers |
| `WG_INTERFACE` | `wg0` | |
| `WG_LISTEN_PORT` | `51820` | WireGuard UDP port |
| `WG_SUBNET` | `10.13.13.0/24` | Client peer subnet |
| `WG_SERVER_ADDRESS` | derived | First usable + mask |
| `WG_PEER_DNS` | derived | DNS in generated peer configs |
| `WG_DNS_UPSTREAMS` | `8.8.8.8,8.8.4.4,1.1.1.1` | dnsmasq upstreams |
| `WG_LOCAL_DNS` | `0` | Run built-in dnsmasq |
| `WG_DEFAULT_ACL` | `10.0.0.0/8` | Default ACL for new peers |
| `WG_MULTISITE` | `1` | Federation panel |
| `WG_FEDERATION_SUBNET` | `10.99.0.0/24` | Overlay subnet, must ≠ WG_SUBNET |
| `WG_FEDERATION_ENDPOINT` | *(empty)* | Defaults to WG_ENDPOINT |
| `PANEL_PASSWORD` | *(generated)* | Plaintext, bcrypt-hashed at startup |
| `WGFLOW_BIND` | `0.0.0.0:8080` | In-container uvicorn bind |
| `HOSTBIND_WG_PANEL` | `0.0.0.0` | Host-side panel interface (NOT host:port) |
| `HOSTBIND_WG_PANEL_PORT` | `8080` | Host-side panel port |
| `WGFLOW_DATA_DIR` | `/data` | Hardcoded in compose |
| `WGFLOW_IPTABLES_LOG` | `0` | Log dropped packets |
| `WGFLOW_MIGRATION_DEFAULT_ENABLED` | `0` | Seed: show Import panel |
| `WGFLOW_TELEMETRY_ENABLED` | `1` | Anonymous stats |
| `WGFLOW_TELEMETRY_SECRET` | `wgflow-community-default` | Community HMAC key |
| `KERNEL_LOG_PATH` | *(empty)* | Host kernel log to tail; empty = off |

`HOSTBIND_WG_PANEL` is interface-only. The compose port mapping is the
3-part form `${HOSTBIND_WG_PANEL}:${HOSTBIND_WG_PANEL_PORT}:8080/tcp`.

---

## Dependencies (`app/requirements.txt`)

```
fastapi==0.115.0
uvicorn[standard]==0.30.6
pydantic==2.9.2
bcrypt==4.2.0
pyzipper==0.3.6
python-multipart==0.0.9
httpx==0.27.0
```

These exact pins are what the app is tested against. The Dockerfile and
`install-baremetal.sh` both install from this file. Do NOT manually
`pip install` ad-hoc versions — version drift (especially fastapi /
starlette / pydantic) has caused breakage before.

---

## Release history (high level)

- **v3.x** — pre-rebuild. ACLs, INPUT rules, DB import/export. Commits
  for v3.1/3.6/3.7/3.8/3.8.3 exist in git history.
- **v4.0-alpha** — federation groundwork.
- **v4.1.x** — blocklists, upstream connections.
- **v4.2.0** — multisite federation (registration-then-bundle, symmetric
  peering on wg0, overlay subnet, route reconcilers).
- **v4.2.1–4.2.5** — multisite refinements: open-panel button, stable
  identity rule, orphan cleanup, mobile cards, overlay-address override.
- **v4.2.6** — critical fix: fork-from-multithreaded deadlock in
  `public_ip()`, switched to httpx.
- **v4.3.0** — `setup-one-time.sh` one-shot installer; `/healthz` with
  version + uptime; WS reconnect no longer thrashes on auth failure;
  Dockerfile / docker-compose / .env hardening (port mapping, blocklist
  fetch non-fatal, `.dockerignore`, robust `WGFLOW_BIND` parsing).

The repo history was rebuilt so each release v4.0-alpha → v4.3.0 is its
own commit + annotated tag, dates backdated from the CHANGELOG.

---

## Deferred / open work

Items previously identified but not yet done:

- **Telemetry payload additions** — agreed candidates: DNS queries
  blocked, blocklist size, multisite online count, theme, diag tool
  invocation counts, OS/arch/container flag, auth-enabled flag, feature
  use counters. Deliberately deferred to its own focused release.
  Skipped from that list: per-peer record throughput (fingerprinting
  risk), "best latency ever" (anomaly-prone). Needs a small new
  `feature_use_counters` table.
- **systemd watchdog** — `WatchdogSec=120` in the unit + a heartbeat in
  the metrics tick. Belt-and-braces for the bare-metal hang class.
- **README split** — a `docs/CONFIG.md` (full env var reference) and
  `docs/OPERATIONS.md` (upgrade / backup / restore / troubleshooting)
  to slim the README further.
- **Broader async-subprocess refactor** — other `create_subprocess_exec`
  sites in `network_diag.py` remain vulnerable to the fork-multithreaded
  deadlock; cold call frequency makes the race narrow but it's not zero.
- **Panel-to-panel sync API** — hot-update of advertised networks
  between paired multisite wgflows without re-pairing.
- **Cleanup:** delete `app/federation.py` (v4.0 dead code), drop the
  `importer_privkey` column from schema, purge stale iptables ACCEPT
  rules on multisite link delete.
- **iperf3 client+server end-to-end testing** — left as TODO, no
  specific failure mode collected.
- **Second-link no-handshake bug** — when a wgflow pairs a SECOND
  multisite link, the link reaches "completed" status but shows no
  handshake and no live-peers entry. A diagnostic script
  (`second-link-diag.sh`) was written; its output was never collected.
  Root cause not yet found. Override-address path itself works.

---

## Diagnostic scripts (in `scripts/` or delivered ad-hoc)

- `repo-rebuild.sh` — rebuilds git history from release tarballs.
- `wgflow-hang-diag.sh` — bare-metal hang diagnostic: py-spy dumps,
  CLOSE_WAIT counts, FD leaks, subprocess tree.
- `second-link-diag.sh` — multisite second-link no-handshake diagnostic.
- `multisite-diag.sh` — general multisite data-plane diagnostic.

---

## How to resume development

1. Extract the v4.3.0 tarball — it is the source of truth, not any
   working tree.
2. Read `ARCHITECTURE.md` for the function flows.
3. Respect the invariants list above. The SQLite-canonical /
   kernel-reconciled design is load-bearing.
4. For any state-changing feature: write to SQLite, then make
   `_replay_state_to_kernel()` (or a reconciler it calls) rebuild the
   kernel. Never edit the kernel incrementally and trust it.
5. Run the pre-pack ritual before shipping. Bump `WGFLOW_VERSION` in
   `telemetry.py` and the `vX.Y.Z` strings in `index.html`.
6. Update `CHANGELOG.md` — it is the canonical version history and the
   source for commit dates when rebuilding repo history.
