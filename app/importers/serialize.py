"""JSON serialization for ParsedImport → API response shape.

Kept separate from the IR module so the IR doesn't grow a JSON dependency.
The shape here is what the frontend consumes — it's the wire contract,
versioned implicitly by being part of /api/import/preview/{id}.
"""
from __future__ import annotations

from typing import Any, Dict

from . import parsed as P


def serialize_preview(parsed: P.ParsedImport, preview_id: str) -> Dict[str, Any]:
    """Turn a ParsedImport into the JSON shape the UI consumes.

    Returns a plain dict (not a Pydantic model) because the IR is loose
    enough that a strongly-typed model would just shadow it. FastAPI is
    happy to serialize a dict to JSON.

    Privacy note: we do NOT include private keys or PSKs in the preview
    response. The UI doesn't need them and shipping them over the
    network — even on a localhost-bound dev panel — is more secret
    movement than necessary. Commit step pulls them from the in-memory
    store, never from the wire.
    """
    server_kp_summary = None
    if parsed.server_keypair is not None:
        server_kp_summary = {
            "public_key": parsed.server_keypair.public_key,  # may be ""
            "has_private_key": bool(parsed.server_keypair.private_key),
        }

    return {
        "preview_id": preview_id,
        "source": parsed.source,
        "server_keypair": server_kp_summary,
        "warnings": list(parsed.warnings),
        "peers": [_peer_to_json(i, p) for i, p in enumerate(parsed.peers)],
        "summary": _summarize(parsed),
    }


def _peer_to_json(index: int, peer: P.ParsedPeer) -> Dict[str, Any]:
    return {
        "index": index,
        "name": peer.name,
        "public_key": peer.public_key,
        "address": peer.address,
        "assigned_address": peer.assigned_address,
        "has_private_key": peer.has_private_key,
        "enabled": peer.enabled,
        "dns": peer.dns,
        "status": peer.status,
        "invalid_reason": peer.invalid_reason or None,
        "notes": peer.notes,
    }


def _summarize(parsed: P.ParsedImport) -> Dict[str, int]:
    """Compute counts the UI uses to drive the preview header."""
    counts: Dict[str, int] = {}
    for peer in parsed.peers:
        counts[peer.status] = counts.get(peer.status, 0) + 1
    counts["total"] = len(parsed.peers)
    return counts
