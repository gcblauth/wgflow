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
    )


SETTINGS = load()
