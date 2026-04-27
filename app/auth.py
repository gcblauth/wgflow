"""Authentication for the wgflow admin panel.

Design:
    - One shared password, set via the PANEL_PASSWORD environment variable.
      The value can be either:
        * a bcrypt hash (starts with "$2a$", "$2b$", or "$2y$"). Recommended.
        * a plaintext password. Hashed once on startup and held in memory.
    - On successful login the server returns an opaque session token (32-byte
      random hex) that the client sends as a cookie or Authorization header.
    - Tokens live in a process-local dict; lost on restart. That's fine for a
      single-instance admin tool.
    - Tokens expire 24h after issue.

If PANEL_PASSWORD is unset or empty, auth is disabled entirely — the panel
behaves exactly as before. This preserves the original "loopback-only, auth
upstream" deployment model for users who prefer it.
"""
from __future__ import annotations

import os
import secrets
import threading
import time
from typing import Dict, Optional

import bcrypt
from fastapi import Cookie, Depends, Header, HTTPException, Request

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

SESSION_TTL_SECONDS = 24 * 3600
COOKIE_NAME = "wgflow_session"

# Endpoints that bypass auth (login itself and basic health probes).
PUBLIC_PATHS = {
    "/api/auth/login",
    "/api/auth/status",     # so the UI can ask "is auth required?"
    "/healthz",
}


# ---------------------------------------------------------------------------
# Password setup
# ---------------------------------------------------------------------------

class _AuthState:
    def __init__(self) -> None:
        self.enabled: bool = False
        self.password_hash: Optional[bytes] = None
        self.sessions: Dict[str, float] = {}     # token -> expires_at unix ts
        self.lock = threading.Lock()


STATE = _AuthState()


def init_from_env() -> None:
    """Read PANEL_PASSWORD and configure auth state.

    Called once at FastAPI startup. We deliberately do NOT log the password
    or its hash. We do log whether auth is enabled.
    """
    raw = os.environ.get("PANEL_PASSWORD", "").strip()
    if not raw:
        STATE.enabled = False
        print("[wgflow] PANEL_PASSWORD unset — admin panel auth DISABLED",
              flush=True)
        return

    if raw.startswith(("$2a$", "$2b$", "$2y$")):
        # Already a bcrypt hash. Use as-is.
        STATE.password_hash = raw.encode()
    else:
        # Plaintext. Hash now (12 rounds = ~250ms per compare on modern CPU).
        STATE.password_hash = bcrypt.hashpw(raw.encode(), bcrypt.gensalt(12))

    STATE.enabled = True
    print("[wgflow] admin panel auth ENABLED", flush=True)


# ---------------------------------------------------------------------------
# Login / logout
# ---------------------------------------------------------------------------

def verify_password(plaintext: str) -> bool:
    if not STATE.enabled or STATE.password_hash is None:
        return False
    try:
        return bcrypt.checkpw(plaintext.encode(), STATE.password_hash)
    except ValueError:
        return False


def issue_token() -> str:
    """Mint a new session token, store it, return the string."""
    token = secrets.token_hex(32)
    expires = time.time() + SESSION_TTL_SECONDS
    with STATE.lock:
        STATE.sessions[token] = expires
        _gc_expired_locked()
    return token


def revoke_token(token: str) -> None:
    with STATE.lock:
        STATE.sessions.pop(token, None)


def _gc_expired_locked() -> None:
    """Remove expired sessions. Caller must hold STATE.lock."""
    now = time.time()
    expired = [t for t, exp in STATE.sessions.items() if exp < now]
    for t in expired:
        STATE.sessions.pop(t, None)


def is_valid_token(token: Optional[str]) -> bool:
    if not token:
        return False
    with STATE.lock:
        exp = STATE.sessions.get(token)
        if exp is None:
            return False
        if exp < time.time():
            STATE.sessions.pop(token, None)
            return False
        return True


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------

def _extract_token(
    cookie_token: Optional[str],
    auth_header: Optional[str],
) -> Optional[str]:
    """Pull a token from either a cookie or an Authorization: Bearer header."""
    if cookie_token:
        return cookie_token
    if auth_header:
        parts = auth_header.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()
    return None


async def require_auth(
    request: Request,
    session: Optional[str] = Cookie(default=None, alias=COOKIE_NAME),
    authorization: Optional[str] = Header(default=None),
) -> None:
    """FastAPI dependency that 401s on missing/invalid session.

    Used for HTTP routes only. WebSocket routes do their own cookie check
    inside the handler before `await websocket.accept()` — see ws_status
    in main.py — because FastAPI's dependency injection doesn't pass
    `Request` to WebSocket route deps.

    Auth-disabled mode: always passes. Public paths: always pass even when
    auth is enabled. Everything else: token must be present and valid.
    """
    if not STATE.enabled:
        return
    if request.url.path in PUBLIC_PATHS:
        return
    if request.url.path.startswith("/static/") or request.url.path == "/":
        return
    token = _extract_token(session, authorization)
    if not is_valid_token(token):
        raise HTTPException(
            401, "authentication required",
            headers={"X-WGFlow-Auth": "required"},
        )


def is_authenticated_ws(websocket) -> bool:
    """Cookie-based auth check for WebSocket routes.

    WS routes can't use the require_auth dep because FastAPI doesn't inject
    Request into WS deps. The handler calls this directly before accept().
    Returns True if the WS connection is authorized to proceed.
    """
    if not STATE.enabled:
        return True
    token = websocket.cookies.get(COOKIE_NAME)
    return is_valid_token(token)
