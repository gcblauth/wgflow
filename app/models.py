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
