"""In-memory preview store with TTL.

Holds parsed imports between the upload step and the commit step so the
upload bytes don't have to be re-sent. Each preview gets a random hex id
returned to the client, keyed in a process-local dict, expiring after
PREVIEW_TTL seconds.

Process-local is intentional and matches the existing wgflow auth pattern
(auth.py also keeps session tokens in memory). Restart loses pending
previews — operators just re-upload, which takes seconds.

Concurrency: a single threading.Lock serialises mutations. The expected
qps is "one operator, occasional uploads" so contention is irrelevant.
"""
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional

from . import parsed as P


PREVIEW_TTL = 600  # 10 minutes


@dataclass
class _Entry:
    parsed: P.ParsedImport
    created_at: float


_LOCK = threading.Lock()
_STORE: Dict[str, _Entry] = {}


def store(parsed: P.ParsedImport) -> str:
    """Stash a parsed import, return its preview id."""
    pid = secrets.token_hex(16)
    with _LOCK:
        _gc_locked()
        _STORE[pid] = _Entry(parsed=parsed, created_at=time.time())
    return pid


def get(pid: str) -> Optional[P.ParsedImport]:
    """Look up a preview. Returns None if expired or never existed.

    Idempotent — a successful lookup does NOT remove the entry. The
    commit endpoint calls get() and then explicitly drop()s on success
    so a failed commit can be retried with the same preview id.
    """
    with _LOCK:
        _gc_locked()
        entry = _STORE.get(pid)
        if entry is None:
            return None
        return entry.parsed


def drop(pid: str) -> None:
    """Remove a preview. Safe to call on already-removed ids."""
    with _LOCK:
        _STORE.pop(pid, None)


def _gc_locked() -> None:
    """Evict expired entries. Caller must hold _LOCK."""
    now = time.time()
    expired = [pid for pid, e in _STORE.items() if now - e.created_at > PREVIEW_TTL]
    for pid in expired:
        _STORE.pop(pid, None)
