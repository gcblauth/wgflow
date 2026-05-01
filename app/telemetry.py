"""Anonymous usage telemetry.

Every TELEMETRY_INTERVAL seconds (default 30 minutes), POSTs a small JSON
payload to the project's collection endpoint:

    {
      "instance_id":     "<uuid4 generated on first DB init>",
      "version":         "<wgflow version string>",
      "peers_total":     <int>,
      "rx_bytes":        <int>,    # cumulative since first install
      "tx_bytes":        <int>,
      "uptime_seconds":  <int>     # process uptime, not host uptime
    }

The body is HMAC-SHA256 signed; signature goes in the `X-Signature` header.
The HMAC key is one of:
  1. WGFLOW_TELEMETRY_SECRET env var if set (operator-configured, used when
     someone runs their own collector with a shared key arrangement)
  2. Otherwise, the community default constant `wgflow-community-default`,
     which the public collector at wgflow.2ps.in accepts.

About the security posture: the signature is an integrity check, not proof
of origin. The community default is in this source file — anyone can read
it and produce valid signatures. That is intentional. The collector defends
against fake-instance flooding with per-IP rate limits and a pending →
approved promotion rule (10+ check-ins spanning at least 24 hours before
an instance counts toward public stats), not by trusting the signature.

To opt out: set WGFLOW_TELEMETRY_ENABLED=0 in the environment. The README
documents this prominently. Default is ON.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import sys
import time
from typing import Optional

import httpx

from .config import SETTINGS
from .db import DB

# wgflow version included in every payload so the collector can break stats
# down by release. Update on each tagged release.
WGFLOW_VERSION = "3.6"

# Where telemetry goes. Hardcoded — operators who want to redirect or block
# this run a local DNS override, or set WGFLOW_TELEMETRY_ENABLED=0.
TELEMETRY_URL = "https://wgflow.2ps.in/collect"

# 30 minutes between samples. Short enough that an opt-out takes effect
# quickly; long enough that 1k instances at default settings produce
# ~48k POSTs/day, which is comfortable on cheap hosting.
TELEMETRY_INTERVAL = 1800

# First POST happens this many seconds after startup. Long enough that the
# collector won't be hammered if 100 containers start simultaneously after
# a host reboot; short enough that a fresh install doesn't have to wait
# 30 minutes to verify telemetry is working.
TELEMETRY_FIRST_DELAY = 90

# HTTP client timeout. The collector should answer quickly; a slow response
# means the operator's network is bad or the collector is overloaded.
# Either way, we drop the sample silently and try again next tick.
TELEMETRY_HTTP_TIMEOUT = 15.0

# Track wgflow process start so uptime_seconds reflects this process,
# not the host (/proc/1 uptime is a different number — we want time since
# the wgflow application booted).
_START_TIME = time.time()


def _process_uptime() -> int:
    return int(time.time() - _START_TIME)


# The HMAC key used to sign telemetry payloads, by default. Operators
# running their own collector can override via WGFLOW_TELEMETRY_SECRET.
#
# This default is a community-known constant — anyone reading this source
# can compute valid signatures. That is on purpose: the HMAC here is an
# integrity check (catches transit corruption / proxy mangling), not
# authentication of origin. The collector applies its own anti-abuse
# policy (per-IP rate limits, per-instance pending → approved promotion)
# rather than treating the signature as proof.
_COMMUNITY_SECRET = b"wgflow-community-default"


def _resolve_secret() -> bytes:
    """Pick the HMAC key for signing telemetry payloads.

    Operator-set WGFLOW_TELEMETRY_SECRET wins if present (useful when an
    organization runs its own collector and wants per-deployment signing).
    Otherwise the community default is used so the public collector at
    wgflow.2ps.in accepts the payload.

    Returns bytes ready for use with hmac.new().
    """
    if SETTINGS.telemetry_secret:
        return SETTINGS.telemetry_secret.encode("utf-8")
    return _COMMUNITY_SECRET


async def run_telemetry_loop(db: DB) -> None:
    """Background loop. Receives the live DB instance from main.lifespan
    so we share thread-locals with the rest of the app.

    The loop catches CancelledError explicitly so shutdown is silent.
    Any other exception inside the body is logged once and swallowed —
    we don't want a transient HTTP failure or a sqlite hiccup to take
    down the loop.
    """
    if not SETTINGS.telemetry_enabled:
        return

    secret = _resolve_secret()

    # Initial delay: gives the operator a chance to disable telemetry
    # before the first POST, and avoids thundering-herd at host reboot.
    try:
        await asyncio.sleep(TELEMETRY_FIRST_DELAY)
    except asyncio.CancelledError:
        return

    async with httpx.AsyncClient(timeout=TELEMETRY_HTTP_TIMEOUT) as client:
        while True:
            try:
                payload = _build_payload(db)
                if payload is not None:
                    await _send(client, payload, secret)
            except asyncio.CancelledError:
                return
            except Exception as e:
                # Catch-all so a transient error never kills the loop.
                print(f"[telemetry] tick error: {e!r}", file=sys.stderr,
                      flush=True)

            try:
                await asyncio.sleep(TELEMETRY_INTERVAL)
            except asyncio.CancelledError:
                return


def _build_payload(db: DB) -> Optional[dict]:
    """Read counters from sqlite. Returns None if the DB isn't ready
    (which would only happen during a corrupted-state edge case)."""
    conn = db.conn

    row = conn.execute(
        "SELECT value FROM network_settings WHERE key = 'instance_id'"
    ).fetchone()
    if not row:
        # instance_id is seeded in db._migrate; if it's missing, something
        # is wrong with the DB — skip this tick rather than send an
        # "unknown" id.
        return None

    instance_id = row["value"]
    peers_total = conn.execute("SELECT COUNT(*) FROM peers").fetchone()[0]

    traffic = conn.execute(
        "SELECT rx_total, tx_total FROM cumulative_traffic WHERE id=1"
    ).fetchone()
    rx_total = traffic["rx_total"] if traffic else 0
    tx_total = traffic["tx_total"] if traffic else 0

    return {
        "instance_id": instance_id,
        "version": WGFLOW_VERSION,
        "peers_total": peers_total,
        "rx_bytes": rx_total,
        "tx_bytes": tx_total,
        "uptime_seconds": _process_uptime(),
    }


async def _send(client: httpx.AsyncClient, payload: dict,
                secret: bytes) -> None:
    """Sign and POST one payload. Errors are logged via the caller."""
    # Compact JSON so the signature is computed over the exact bytes the
    # server will receive. separators=(',', ':') matches what httpx sends
    # if we passed json= directly, but doing it explicitly keeps the
    # signed-bytes path obvious.
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    signature = hmac.new(secret, body, hashlib.sha256).hexdigest()

    try:
        response = await client.post(
            TELEMETRY_URL,
            content=body,
            headers={
                "X-Signature": signature,
                "Content-Type": "application/json",
                "User-Agent": f"wgflow/{WGFLOW_VERSION}",
            },
        )
    except httpx.RequestError as e:
        # Network-level failure (DNS, connection refused, timeout). Common
        # when the operator's network is intermittent. Log once at debug
        # volume; not worth surfacing every 30 min.
        print(f"[telemetry] post failed: {type(e).__name__}: {e}",
              file=sys.stderr, flush=True)
        return

    if response.status_code == 403:
        # Signature rejected — the collector decided this payload's HMAC
        # didn't match. With our derive-from-private-key scheme, this
        # would mean either (a) the operator regenerated the server key
        # without telling the collector, or (b) the collector changed its
        # validation rule. Surface clearly so the operator can investigate.
        print("[telemetry] signature rejected by collector (HTTP 403)",
              file=sys.stderr, flush=True)
    elif response.status_code == 429:
        # Rate-limited. Server is asking us to back off. Our 30-min
        # cadence shouldn't trigger this normally; if it does, the next
        # tick will just be another 30 min later anyway.
        print("[telemetry] rate-limited by collector (HTTP 429)",
              file=sys.stderr, flush=True)
    elif response.status_code >= 500:
        # Server-side problem. Not our concern; will fix itself.
        print(f"[telemetry] collector error (HTTP {response.status_code})",
              file=sys.stderr, flush=True)
    # 2xx and 3xx fall through silently — happy path.
