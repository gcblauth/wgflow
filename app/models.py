"""Pydantic models for the HTTP API."""
from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field, field_validator

from . import acl


class ACLEntryIn(BaseModel):
    """A single ACL entry as accepted by the API.

    We accept a single `raw` string ("10.0.5.22:443/tcp") and parse it.
    """
    raw: str

    @field_validator("raw")
    @classmethod
    def _validate(cls, v: str) -> str:
        # Throws if malformed; exception bubbles up as a 422.
        acl.parse_entry(v)
        return v


class PeerCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    acl: Optional[List[ACLEntryIn]] = None  # None => use server default
    # Per-peer DNS override for the generated config:
    #   None       → inherit server default (WG_PEER_DNS / auto-derived)
    #   ""         → omit DNS line entirely (split-tunnel friendly)
    #   "1.1.1.1"  → use this DNS verbatim (one or more comma-separated IPs)
    dns: Optional[str] = None


class BatchByNames(BaseModel):
    names: List[str] = Field(..., min_length=1, max_length=500)
    acl: Optional[List[ACLEntryIn]] = None
    dns: Optional[str] = None    # applied to every peer in the batch


class BatchByCount(BaseModel):
    count: int = Field(..., ge=1, le=500)
    prefix: str = Field(default="client", min_length=1, max_length=32)
    acl: Optional[List[ACLEntryIn]] = None
    dns: Optional[str] = None    # applied to every peer in the batch


class ACLUpdate(BaseModel):
    acl: List[ACLEntryIn]


class PeerOut(BaseModel):
    id: int
    name: str
    public_key: str
    address: str
    created_at: str
    acl: List[str]
    dns: Optional[str] = None    # surfaced so the UI shows what was stored
    # True for normal wgflow-managed peers; False only for peers imported
    # from bare-WG sources where the privkey is unknown server-side. The
    # UI uses this to disable the "download config" button — those peers
    # already have working clients, but we can't re-issue their configs.
    has_private_key: bool = True
    # True = peer is active (kernel has the [Peer] block, traffic flows).
    # False = operator paused them; row stays in DB but `wg syncconf`
    # excludes them and they can't connect. ACLs and config are
    # preserved across enable/disable so re-enabling restores fully.
    enabled: bool = True
    # 'client' for normal user peers, 'multisite' for federation
    # mgmt peers. The panel distinguishes via this — multisite peers
    # render with a badge and restricted affordances (no ACL editor,
    # no downloadable conf, delete redirects to the multisite panel).
    peer_type: str = "client"


class PeerEnabledUpdate(BaseModel):
    """Body of PUT /api/peers/{id}/enabled.

    Single-field flip. We use a separate endpoint rather than overloading
    PUT /api/peers/{id} because there's no other peer field that's
    runtime-flippable like this (name + key are immutable, ACL has its
    own endpoint, dns is set at creation). Cleanest API surface.
    """
    enabled: bool


class InstanceConfig(BaseModel):
    """Body of PUT /api/server/instance.

    Both fields optional so the UI can update one without touching the
    other (e.g. user picks a color but doesn't change the name). Empty
    string for `name` means "no name shown"; the header swallows the
    separator chrome too in that case.
    """
    name: Optional[str] = None
    color_theme: Optional[str] = None


class TunnelSettings(BaseModel):
    """Body of PUT /api/server/tunnel.

    v3.6 additions:
      - client_mtu: when set, generated peer .conf files include
        `MTU = <value>` under [Interface]. Empty string = no override
        (client kernel picks default ~1420). Common useful values:
          1420  WireGuard default
          1412  PPPoE (DSL/fibre with PPPoE)
          1380  CGNAT / double-NAT paths
          1280  IPv6 minimum / mobile / safest fallback
        Validation: must be empty or in 576..1500. Out-of-range rejected.
      - mss_clamp: when True, install TCPMSS --clamp-mss-to-pmtu rule
        in iptables mangle/FORWARD on wg0. Helps TCP black-hole problems
        where PMTUD is broken (very common because of ICMP filtering).
        Idempotent on the iptables side; safe to toggle freely.
    """
    client_mtu: Optional[str] = None
    mss_clamp: Optional[bool] = None


class PanelOrder(BaseModel):
    """Body of PUT /api/server/panel-order.

    `order` is a list of panel-id strings in the desired display order.
    Unknown ids are ignored at render time (defensive against UI version
    skew). Empty list resets to default order.
    """
    order: list


class PeerLive(BaseModel):
    """Peer enriched with runtime info from `wg show`."""
    id: int
    name: str
    address: str
    public_key: str
    endpoint: Optional[str]
    latest_handshake: int  # unix timestamp, 0 = never
    rx_bytes: int
    tx_bytes: int
    online: bool


class ImportCommit(BaseModel):
    """Body of POST /api/import/commit.

    `accepted_indices` is the list of peer indices (zero-based, matching
    the order of `peers` in the preview) that the operator chose to import.
    Anything not in this list is dropped silently.

    `adopt_server_keypair` is the toggle: True replaces wgflow's server
    keypair with the source's. Ignored if the parsed import had no
    server keypair (bare-WG without [Interface].PrivateKey, or a v15 DB
    we couldn't extract from).

    `confirm_token` is a typed-string check: the UI requires the operator
    to type "IMPORT" to commit, mirroring the existing destructive-action
    style elsewhere in the panel. Required even for non-server-keypair
    imports because a 30-peer commit is itself non-trivial to undo.
    """
    preview_id: str
    accepted_indices: List[int]
    adopt_server_keypair: bool = False
    confirm_token: str = ""


class MigrationToggle(BaseModel):
    """Body of PUT /api/server/migration.

    Single-field on/off control for the migration importer. When
    `enabled=False`, all three /api/import/* endpoints respond 403 and
    the UI hides the migrate tab.

    Persists to the network_settings table so the choice survives
    container restarts.
    """
    enabled: bool


# ---------------------------------------------------------------------------
# v4.0: federation
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# v4.2-rebuild: multisite federation (registration-then-bundle)
# ---------------------------------------------------------------------------

class MultisiteRegistrationRequest(BaseModel):
    """Body of POST /api/multisite/registration — STEP 1 (importer).

    Operator on wgB clicks '+ import' → 'start'. Picks a label for
    the link, optionally overrides the endpoint (defaults to
    WG_ENDPOINT), optionally lists CIDRs wgB will advertise to wgA.

    Server generates a fresh keypair locally, allocates an overlay
    address (.2 by default), persists a pending-bundle row with the
    privkey stashed, returns a registration text block. Operator
    copies into wgA's '+ create from registration' form.
    """
    name: str = Field(..., min_length=1, max_length=64)
    endpoint: str = Field(default="", max_length=200)
    advertised_networks: List[str] = Field(default_factory=list)


class MultisiteCreateLinkRequest(BaseModel):
    """Body of POST /api/multisite/links — STEP 2 (creator).

    Operator on wgA clicks '+ create from registration', pastes the
    registration string from wgB, optionally overrides the link name,
    fills in own endpoint + advertised networks.

    Server parses the registration, allocates own overlay (.1 by
    default), generates PSK, INSERTS wgB AS A wg0 PEER IMMEDIATELY
    (so the moment wgB has wgA's pubkey, the tunnel handshakes),
    returns the bundle text block. Operator copies back into wgB.
    """
    registration: str = Field(..., min_length=50, max_length=10000)
    name: Optional[str] = Field(default=None, max_length=64)
    endpoint: str = Field(default="", max_length=200)
    advertised_networks: List[str] = Field(default_factory=list)


class MultisiteImportCompleteRequest(BaseModel):
    """Body of POST /api/multisite/links/{id}/import-complete — STEP 3
    (importer).

    Operator on wgB pastes the bundle string from wgA. Server uses
    the link_id from the URL to find the pending-bundle row created
    in step 1 (with the stashed privkey), parses the bundle, inserts
    wgA as a wg0 peer using the stashed privkey, transitions to
    established. Tunnel handshakes within ~5s.
    """
    bundle: str = Field(..., min_length=50, max_length=10000)


class MultisiteUpdateRequest(BaseModel):
    """Body of PUT /api/multisite/links/{id}. Rename + enable toggle.
    Other changes are delete + repair."""
    name: Optional[str] = Field(default=None, min_length=1, max_length=64)
    enabled: Optional[bool] = None


# ---------------------------------------------------------------------------
# v4.1: blocklist sources
# ---------------------------------------------------------------------------

class BlocklistSourceCreate(BaseModel):
    """Body of POST /api/blocklist/sources — operator adding a custom URL.

    The name must be unique. URL must be http(s); we don't currently
    validate beyond scheme — fetching it will surface real problems
    with a clean error message and the operator can correct the URL.
    """
    name: str = Field(..., min_length=1, max_length=64)
    url: str = Field(..., min_length=10, max_length=500)


class BlocklistSourceUpdate(BaseModel):
    """Body of PUT /api/blocklist/sources/{id} — toggle enabled."""
    enabled: bool


class BlocklistSourceOut(BaseModel):
    """One source row as surfaced to the UI."""
    id: int
    name: str
    url: str
    enabled: bool
    is_preset: bool
    last_fetched_ts: Optional[int] = None
    last_entry_count: Optional[int] = None
    last_overlap_count: Optional[int] = None
    last_error: Optional[str] = None
    created_at: str


# ---------------------------------------------------------------------------
# v4.1.1: upstream WG client connections
# ---------------------------------------------------------------------------

class UpstreamPreviewRequest(BaseModel):
    """Body of POST /api/upstream/preview.

    Operator pastes a wg-client.conf; we parse, run the AllowedIPs
    safety filter, and return what WOULD be inserted if they confirm.
    Two-step flow (preview → confirm) so the operator sees the
    filtered AllowedIPs and DNS before any kernel state changes.
    """
    conf_text: str = Field(..., min_length=20, max_length=10000)


class UpstreamCreateRequest(BaseModel):
    """Body of POST /api/upstream/connections — confirm step.

    Carries the operator-chosen name plus the (possibly edited) applied
    AllowedIPs the operator agreed to. The conf_text is re-parsed
    server-side so we never trust client-side parsing.
    """
    name: str = Field(..., min_length=1, max_length=64)
    conf_text: str = Field(..., min_length=20, max_length=10000)
    # Override the safety-filtered AllowedIPs if the operator explicitly
    # edited them in the preview UI. None = use the filter's default.
    allowed_ips_override: Optional[List[str]] = None


class UpstreamConnectionOut(BaseModel):
    """One upstream connection as surfaced to the UI."""
    id: int
    name: str
    interface_name: str           # 'wg1', 'wg2', ...
    enabled: bool
    local_address: str
    upstream_dns: Optional[str] = None
    mtu: Optional[int] = None
    remote_endpoint: str
    remote_allowed_ips_declared: str   # comma-separated as written in conf
    remote_allowed_ips_applied: str    # comma-separated, what we actually route
    persistent_keepalive: Optional[int] = None
    last_handshake_ts: Optional[int] = None
    last_error: Optional[str] = None
    created_at: str


class UpstreamPreviewOut(BaseModel):
    """Result of POST /api/upstream/preview — what would be created."""
    local_address: str
    upstream_dns: List[str]
    mtu: Optional[int] = None
    remote_endpoint: str
    remote_allowed_ips_declared: List[str]
    remote_allowed_ips_applied: List[str]
    full_tunnel_replaced: bool        # operator wanted 0.0.0.0/0
    stripped_overlaps: List[str]      # CIDRs filter removed + reason
    persistent_keepalive: Optional[int] = None
    has_psk: bool


class UpstreamUpdateRequest(BaseModel):
    """Body of PUT /api/upstream/connections/{id}. Limited fields —
    rename + enable toggle + applied AllowedIPs override. Changing
    keys / endpoint / declared AllowedIPs would be a re-import."""
    name: Optional[str] = Field(default=None, min_length=1, max_length=64)
    enabled: Optional[bool] = None
    allowed_ips_override: Optional[List[str]] = None
