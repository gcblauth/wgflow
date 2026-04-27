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
