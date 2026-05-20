# wgflow — Architecture & Function Flow

Internal reference for contributors. Describes how each subsystem works,
the data flow, and the invariants that hold the design together.

Current version: **4.3.0** · ~15,400 lines of Python across 24 modules.

---

## Core principle: SQLite is canonical, the kernel is a cache

Every piece of state lives in one SQLite database (`/data/wgflow.sqlite`).
The Linux kernel's WireGuard interface, routing table, and iptables chains
are **derived** from that database — never the other way around.

The reconcile cycle:

```
operator action (API call)
        │
        ▼
write to SQLite  ── inside a transaction
        │
        ▼
_replay_state_to_kernel()
        │
        ├── wg syncconf wg0   (peers, keys, allowed-ips)
        ├── ip route ...      (routes — syncconf does NOT install these)
        ├── iptables chains   (per-peer ACLs, multisite baseline, masquerade)
        └── multisite reconcilers (overlay addrs, routes)
```

Consequences of this design:

- The panel can never show stale data — it reads SQLite, which is the truth.
- A corrupted kernel state self-heals: the next reconcile rebuilds it.
- Schema migrations are safe because they're just SQLite operations.
- There are no incremental kernel edits to get wrong.

`_replay_state_to_kernel()` in `main.py` is the heart of this. It runs on
startup and after every state-changing operation.

---

## Module map

| Module | Lines | Responsibility |
|--------|-------|----------------|
| `main.py` | 4883 | FastAPI app, all ~90 endpoints, the reconcile orchestrator |
| `iptables_manager.py` | 1063 | Per-peer ACL chains, masquerade, multisite baseline rules |
| `db.py` | 777 | SQLite access, schema, migrations (SAVEPOINT + introspection) |
| `multisite.py` | 711 | Federation: pairing, overlay addressing, route reconcilers |
| `network_diag.py` | 711 | Public IP, speed test, ping/traceroute/mtr/dig/curl/tcpdump/iperf3 |
| `federation.py` | 648 | v4.0 federation (legacy — superseded by multisite.py) |
| `metrics.py` | 576 | Throughput collection, cumulative counters, sparkline history |
| `upstream.py` | 558 | Upstream WireGuard client connections (this box as a WG client) |
| `blocklist.py` | 535 | Multi-source DNS blocklist management |
| `dns_overrides.py` | 399 | Per-domain DNS override rules |
| `log_streams.py` | 376 | WebSocket log streaming |
| `importers/commit.py` | 376 | Applies previewed import peers to the DB |
| `importers/pivpn.py` | 382 | PiVPN config parser |
| `dns_log.py` | 357 | DNS query log capture + pruning |
| `models.py` | 356 | Pydantic request/response schemas |
| `importers/wg_easy.py` | 343 | wg-easy config parser |
| `acl.py` | 299 | ACL entry parsing + validation |
| `installer_script.py` | 291 | Per-peer install-script generation |
| `telemetry.py` | 244 | Anonymous usage payload + HMAC signing |
| `wg_manager.py` | 240 | wg / wg-quick wrappers, keypair generation |
| `inspector.py` | 221 | Per-peer live state inspection |
| `auth.py` | 201 | Password auth, session cookies, public-path allowlist |
| `config.py` | 199 | Environment variable loading + validation |
| `importers/parsed.py` | 197 | Shared import data model |
| `importers/bare_wg.py` | 180 | Bare WireGuard `wg0.conf` parser |
| `importers/detector.py` | 93 | Detects which VPN product an uploaded file came from |
| `importers/preview_store.py` | 74 | Holds parsed imports between upload and commit |
| `importers/serialize.py` | 66 | Import preview serialization |

---

## Function flows

### Peer lifecycle

**Create** (`POST /api/peers`, `/api/peers/batch/*`):
1. Generate a WireGuard keypair (`wg_manager.py`).
2. Allocate the next free address from `WG_SUBNET`.
3. Insert a `peers` row (with the default ACL from `WG_DEFAULT_ACL`).
4. `_replay_state_to_kernel()` → `wg syncconf` adds the peer; `iptables_manager`
   builds its ACL chain.

**Config / QR / install-script** (`GET /api/peers/{id}/config|qr|install-script`):
Generated on demand from the stored keypair + server settings. The
install-script endpoint (`installer_script.py`) produces a one-liner the
peer runs to self-configure.

**Enable/disable** (`PUT /api/peers/{id}/enabled`):
Flips a flag; reconcile either includes or omits the peer from `wg syncconf`.
The keypair and config are preserved.

**Delete** (`DELETE /api/peers/{id}`):
Removes the row, reconcile drops it from the kernel, `iptables_manager`
tears down its chain.

**Inspect** (`GET /api/peers/{id}/inspect`):
`inspector.py` reads live `wg show` data — handshake age, endpoint,
transfer counters — and joins it with the DB row.

### Per-peer ACLs

`acl.py` parses ACL strings. Each entry is `[!]IP[/cidr][:port[/proto]]`.
`!` prefix = deny. Entries are comma-separated.

`iptables_manager.py` turns each peer's ACL into a dedicated iptables
chain (`WGFLOW_FORWARD` jumps to it). Allow entries become ACCEPT rules,
deny entries become DROP rules, evaluated in order. The chain ends with
the default policy. Hit counters on each rule are read back via
`iptables -L -v` and surfaced at `GET /api/peers/{id}/acl-hits`.

Named aliases (`/api/acl-aliases`) are reusable ACL fragments stored in
their own table and expanded at rule-build time.

`WGFLOW_IPTABLES_LOG=1` inserts a rate-limited LOG rule with the
`WGFLOW-DROP:` prefix before drops, for debugging.

### Local DNS + blocklists

When `WG_LOCAL_DNS=1`:
- `entrypoint.sh` renders `dnsmasq.conf` from the template and starts dnsmasq.
- `blocklist.py` fetches blocklist sources (multiple, deduplicated), writes
  the merged hosts file dnsmasq reads.
- `dns_log.py` tails dnsmasq's query log into the DB; old rows are pruned
  on a schedule.
- `dns_overrides.py` manages per-domain override entries (allowlist a
  blocked domain, or return a custom answer).

`GET /api/dns/recent` serves the live query log; `GET /api/blocklist/status`
reports source count and total entry count.

When `WG_LOCAL_DNS=0`, dnsmasq never starts and the three DNS panels are
hidden in the UI (`applyLocalDnsVisibility()` in the frontend).

### Multisite federation

`multisite.py`. Design: **registration-then-bundle** pairing, symmetric.

1. **Importer side** (`POST /api/multisite/registration`): generates a
   registration text block. Each wgflow has a stable overlay identity —
   one address from `WG_FEDERATION_SUBNET` reused across all its links.
2. **Creator side** (`POST /api/multisite/links`): pastes the registration,
   accepts it (with collision checks against existing links), returns a
   bundle.
3. **Importer side** (`POST /api/multisite/links/{id}/import-complete`):
   pastes the bundle, pairing completes.

Both sides peer on `wg0` using their respective wg0 server keypairs (no
per-link keypairs). Each gets a secondary `10.99.0.X/32` overlay address.

Reconcilers:
- `reconcile_overlay_address` — keeps the overlay IP on wg0.
- `reconcile_routes` — installs routes to advertised CIDRs (`wg syncconf`
  does NOT install routes, only `wg-quick up` does, so this is needed).
- `iptables_manager.ensure_multisite_baseline_rules` — MASQUERADE for the
  overlay subnet exiting via `!wg0`.

Self-healing: on every replay, orphan multisite peers (rows with no
`federation_links.peer_id` referencing them) and self-references (a
multisite peer whose address equals our own overlay) are cleaned up.

### Upstream connections

`upstream.py`. The inverse of serving peers: makes *this* wgflow a
WireGuard *client* of some other endpoint. Preview an upstream config,
then commit it as a connection. Separate from multisite (which federates
two wgflows symmetrically).

### Metrics

`metrics.py`. A background worker samples `wg show` transfer counters,
computes deltas, stores per-peer and aggregate throughput. Cumulative
counters survive restarts. Sparkline history is a rolling window per peer.
The dashboard subscribes via `WS /ws/status` — push, not poll.

### Diagnostics

`network_diag.py`. Each tool (ping, traceroute, mtr, dig, curl, tcpdump,
iperf3 client + server) runs as a subprocess; output is streamed to the
panel. Speed tests can be scheduled; history is stored and pruned.

Public-IP detection uses `httpx` (not a curl subprocess) — see the
"async subprocess" note below.

### Migration importer

`importers/`. Flow:
1. `POST /api/import/upload` — file uploaded, `detector.py` identifies the
   product (wg-easy / PiVPN / bare WG), the matching parser produces a
   `parsed.py` model, `preview_store.py` holds it.
2. `GET /api/import/preview/{id}` — re-fetch the preview (UI reload).
3. `POST /api/import/commit` — `commit.py` writes the chosen peers into
   the DB. Protected by a typed confirmation string.

### Auth

`auth.py`. One shared password (`PANEL_PASSWORD`), bcrypt-hashed at
startup. Session cookie after login. `PUBLIC_PATHS` allowlist exempts
`/healthz`, `/api/auth/*`, and the multisite handshake endpoint. WS
connections from unauthenticated clients get close code 4401.

---

## Web layer

- **Backend:** FastAPI on uvicorn. ~90 REST endpoints + 2 WebSockets
  (`/ws/status`, `/ws/logs/{source}`).
- **Frontend:** a single `app/static/index.html` (~12,000 lines, no build
  step). CRT / phosphor-green theme. Responsive — desktop tables collapse
  to mobile cards.
- **No SPA framework.** Plain JS. State updates arrive over the WebSocket.

---

## Reconcile invariants (do not break these)

1. SQLite is canonical; the kernel is rebuilt via `_replay_state_to_kernel()`.
2. Migrations use SAVEPOINT + `sqlite_master` introspection.
3. Multisite stable identity: every link on a wgflow shares one
   `local_overlay_addr`.
4. Routes are installed by `multisite.reconcile_routes` — `wg syncconf`
   does not install routes.
5. MASQUERADE for the overlay subnet exits via `!wg0`.
6. Orphan / self-reference multisite-peer cleanup runs on every replay.
7. `_live_wg0_pubkey()` is the single source of truth for the wg0 pubkey.
8. Both sides of a multisite link use their respective wg0 server
   keypairs — no per-link keypairs.

---

## Known sharp edges

- **Async + subprocess + fork:** historically `public_ip()` shelled out
  via `asyncio.create_subprocess_exec`, which `fork()`s. With the metrics
  worker thread concurrently in its own `subprocess.run`, a
  fork-from-multithreaded deadlock could freeze the event loop. Fixed in
  v4.2.6 by switching `public_ip()` to `httpx`. Other `create_subprocess_exec`
  call sites remain but are cold paths — a broader refactor is deferred.
- **Bare-metal deploy:** only sync `app/` (`rsync -a app/ /opt/wgflow/app/`).
  `rsync --delete` of the whole tree destroys the venv and overwrites the
  post-processed `dnsmasq.conf.template`.
- `app/federation.py` is v4.0 dead code, superseded by `multisite.py` —
  scheduled for removal.

---

## Build & deploy

- **Docker:** `setup-one-time.sh` → `.env` → `docker compose up -d --build`.
- **Bare-metal:** `setup-one-time.sh --bare-metal` → venv + systemd unit.
- The Docker image is `debian:bookworm-slim` + WireGuard tools + a Python
  venv. Multi-arch (x86_64 / ARM).
- Pre-pack ritual for releases: `ast.parse(feature_version=(3,11))` +
  a regex tokenizer guard for nested same-quote f-strings +
  `node --check` on the extracted frontend JS.
