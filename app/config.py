"""Runtime configuration, read once from the environment at process start.

Every knob lives here so the rest of the code never touches os.environ.
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path


def _env(name: str, default: str) -> str:
    value = os.environ.get(name, default)
    return value if value != "" else default


@dataclass(frozen=True)
class Settings:
    # WireGuard
    interface: str
    listen_port: int
    subnet: ipaddress.IPv4Network
    server_address: ipaddress.IPv4Interface
    endpoint: str
    peer_dns: str

    # If True (default), the container runs dnsmasq locally and peers are
    # configured to use the wgflow server as DNS. When False, dnsmasq is
    # not started; peers use whatever WG_PEER_DNS resolves to (defaults
    # to 1.1.1.1 in that case). The DNS recent-queries panel and the DNS
    # override tab in the UI are also conditional on this flag.
    local_dns_enabled: bool

    # ACL defaults
    default_acl_raw: str  # comma-separated, parsed per-peer by acl.parse_entry

    # Storage
    data_dir: Path
    db_path: Path
    keys_dir: Path
    peers_dir: Path

    # Telemetry — anonymous usage stats (peer count, total rx/tx, uptime)
    # POSTed every 30 minutes to the project's collection endpoint. Default
    # ON so the project can see real-world usage; operators opt out via
    # WGFLOW_TELEMETRY_ENABLED=0. The optional WGFLOW_TELEMETRY_SECRET, if
    # set, is used as the HMAC key — when unset we sign with a per-instance
    # secret derived from the server private key (see telemetry.py).
    telemetry_enabled: bool
    telemetry_secret: str  # "" = use per-instance derived secret

    # Migration importer (wg-easy / PiVPN / bare WG). Three /api/import/*
    # endpoints + a UI tab. Useful exactly once per deployment, then
    # operators typically want to lock it down. The env var here ONLY
    # seeds the default for fresh installs; once the DB row exists in
    # network_settings the env var is ignored, so toggling it from the
    # UI sticks across container restarts. To force a hard-disabled
    # state from outside the container, edit the network_settings row
    # directly or rely on the runtime API.
    migration_default_enabled: bool

    # v4.0: multi-site federation. When enabled, the panel exposes a
    # Federation section where the operator can pair this wgflow with
    # one or more other wgflow instances over WireGuard. Each pairing
    # produces a per-link WG keypair + PSK, allocated addresses on a
    # dedicated overlay subnet (federation_subnet), and a kernel peer
    # entry on wg0 distinct from client peers. The HTTPS+WS panel ports
    # become reachable over the resulting tunnel — federated wgflows
    # can browse each other's panels privately.
    #
    # Note: the inbound /api/federation/handshake endpoint is gated by
    # a per-pairing one-time code that only exists during an active
    # 10-minute pairing window. Outside that window the endpoint
    # returns 401 to anyone who hits it, so the public attack surface
    # is small even with the feature on by default.
    multisite_enabled: bool
    federation_subnet: ipaddress.IPv4Network
    # The host:port other wgflows should send WireGuard traffic to in
    # order to reach our federation peer. Usually identical to the
    # client-facing WG_ENDPOINT (same UDP port, same public host), but
    # operators with split-port setups can override.
    federation_wg_endpoint: str
    # v4.2-pre: UDP port for the wg1 federation interface. Removed in
    # v4.2-rebuild — the asymmetric wg1 server design was scrapped in
    # favor of mgmt-peers on wg0, which means no separate listener and
    # no new port to expose. The WG_FED_PORT env var is now ignored.

    @property
    def server_public_key_path(self) -> Path:
        return self.keys_dir / "server_public.key"

    @property
    def server_private_key_path(self) -> Path:
        return self.keys_dir / "server_private.key"


def load() -> Settings:
    data_dir = Path(_env("WGFLOW_DATA_DIR", "/data"))

    # Local DNS toggle. Default ON so existing deployments upgrade
    # without surprise. Operators can opt out by setting WG_LOCAL_DNS=0.
    local_dns_raw = _env("WG_LOCAL_DNS", "1").strip().lower()
    local_dns_enabled = local_dns_raw in ("1", "true", "yes", "on")

    # Telemetry toggle. Same boolean parsing as WG_LOCAL_DNS — accept the
    # full set of common truthy spellings rather than just "1", because
    # operators write things like `WGFLOW_TELEMETRY_ENABLED=true` in .env
    # files and "true" != "1" was a real footgun in 3.2.0.
    telemetry_raw = _env("WGFLOW_TELEMETRY_ENABLED", "1").strip().lower()
    telemetry_enabled = telemetry_raw in ("1", "true", "yes", "on")

    # Migration toggle. Default ON so a fresh install discovers the
    # migrate tab without configuration. Same truthy-spelling tolerance.
    migration_raw = _env("WGFLOW_MIGRATION_DEFAULT_ENABLED", "1").strip().lower()
    migration_default_enabled = migration_raw in ("1", "true", "yes", "on")

    # v4.0: multisite/federation. Default ON. The receiving handshake
    # endpoint is still gated by a per-pairing one-time code window,
    # so leaving the feature on by default does not by itself create
    # an unauthenticated control path — see app/federation.py for the
    # state machine.
    multisite_raw = _env("WG_MULTISITE", "1").strip().lower()
    multisite_enabled = multisite_raw in ("1", "true", "yes", "on")

    # Federation overlay subnet. Must not overlap with the client WG
    # subnet (WG_SUBNET); we don't enforce this at parse time because
    # operators may legitimately use private ranges that look adjacent
    # — we just document the requirement. Default 10.99.0.0/24 picked
    # to be far from the typical 10.13.13.0/24 client default.
    federation_subnet = ipaddress.IPv4Network(
        _env("WG_FEDERATION_SUBNET", "10.99.0.0/24")
    )

    # Where remote wgflows should send WG traffic to reach us. Falls
    # back to the regular endpoint, which is what most single-port
    # deployments want.
    fed_wg_endpoint = _env("WG_FEDERATION_ENDPOINT",
                           _env("WG_ENDPOINT", "vpn.example.com:51820"))

    # v4.2-pre: WG_FED_PORT for wg1. Removed in v4.2-rebuild — kept
    # the env var read silently to avoid noisy warnings on operators
    # who haven't cleaned up their compose files yet, but the value
    # is no longer used anywhere.

    # peer_dns default depends on whether local DNS is on:
    #   - local DNS on  → server's wg address (peers query wgflow's dnsmasq)
    #   - local DNS off → 1.1.1.1 (Cloudflare public resolver)
    # Operators can always override explicitly via WG_PEER_DNS.
    server_addr_only = str(ipaddress.IPv4Interface(
        _env("WG_SERVER_ADDRESS", "10.13.13.1/24")
    ).ip)
    default_peer_dns = server_addr_only if local_dns_enabled else "1.1.1.1"

    return Settings(
        interface=_env("WG_INTERFACE", "wg0"),
        listen_port=int(_env("WG_LISTEN_PORT", "51820")),
        subnet=ipaddress.IPv4Network(_env("WG_SUBNET", "10.13.13.0/24")),
        server_address=ipaddress.IPv4Interface(
            _env("WG_SERVER_ADDRESS", "10.13.13.1/24")
        ),
        endpoint=_env("WG_ENDPOINT", "vpn.example.com:51820"),
        peer_dns=_env("WG_PEER_DNS", default_peer_dns),
        local_dns_enabled=local_dns_enabled,
        default_acl_raw=_env("WG_DEFAULT_ACL", "10.0.0.0/8"),
        data_dir=data_dir,
        db_path=data_dir / "wgflow.sqlite",
        keys_dir=data_dir / "keys",
        peers_dir=data_dir / "peers",
        telemetry_enabled=telemetry_enabled,
        telemetry_secret=_env("WGFLOW_TELEMETRY_SECRET", ""),
        migration_default_enabled=migration_default_enabled,
        multisite_enabled=multisite_enabled,
        federation_subnet=federation_subnet,
        federation_wg_endpoint=fed_wg_endpoint,
    )


SETTINGS = load()

# Startup sanity warning. If WG_ENDPOINT was never set the placeholder
# `vpn.example.com:51820` ends up baked into every generated client
# config, producing peers that can't connect from anywhere. We log a
# loud warning at startup so the operator notices BEFORE distributing
# configs. Non-fatal — wgflow still runs (the panel works, internal
# state is fine), but cli output drives the operator to set the var
# via .env / systemd override.
if SETTINGS.endpoint.startswith("vpn.example.com"):
    print(
        "[wgflow] WARNING: WG_ENDPOINT is unset (placeholder "
        f"{SETTINGS.endpoint!r} in use). Client configs generated "
        "by this wgflow will reference vpn.example.com and won't "
        "connect from anywhere. Set WG_ENDPOINT in your .env or "
        "systemd override to your public hostname:port.",
        flush=True,
    )
