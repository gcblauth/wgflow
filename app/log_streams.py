"""On-demand log streaming over WebSocket.

Four sources, each opened on demand by a separate WS connection:
  - dnsmasq:  tails /var/log/dnsmasq.log (already exists; we already have
              a parser hooking it for query records)
  - wireguard: tails the host kernel log filtered for `wireguard:` lines.
              Requires the operator to bind-mount /var/log/kern.log.
  - iptables: tails the same kernel log filtered for `WGFLOW-DROP:` lines,
              which only exist if WGFLOW_IPTABLES_LOG=1 (entrypoint adds
              the LOG rules in that case).
  - access:   uvicorn access logs. Captured via a logging.Handler that
              writes into a deque; the WS handler tails the deque.

Subprocess management: each WS handler that uses `tail -F` spawns the
subprocess on accept and `terminate()`s it on disconnect. There's no
shared subprocess; if two clients open the same stream we get two tails.
That's wasteful but correct, and "two admins watching at once" is
extremely rare in practice.

Resource posture: when no client is connected, NO log work happens for
that source. The uvicorn access log is the exception — we keep its
ring buffer always populated since it's already routed through
Python's logging machinery and the cost is essentially nothing.
"""
from __future__ import annotations

import asyncio
import collections
import logging
import os
import time
from pathlib import Path
from typing import Awaitable, Callable, Optional

from fastapi import WebSocket, WebSocketDisconnect


# ---------------------------------------------------------------------------
# Constants & config
# ---------------------------------------------------------------------------

DNSMASQ_LOG = Path("/var/log/dnsmasq.log")
KERN_LOG    = Path("/var/log/kern.log")     # bind-mounted from host

# How many lines `tail -F` should print before following. Matches the UI
# buffer cap so opening a stream feels like "you start with the last 500
# lines already in view".
INITIAL_LINES = 500

# In-memory ring for the access log. Always populated (cheap), even when
# no one is watching. Tail-stream just iterates this and then waits for
# new entries via the asyncio event.
_access_ring: collections.deque = collections.deque(maxlen=1000)
_access_event = asyncio.Event()


def access_log_handler() -> logging.Handler:
    """Return a logging.Handler that pushes formatted records onto our ring.

    Wire this into uvicorn.access logger at app startup.
    """
    class _RingHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            try:
                msg = self.format(record)
            except Exception:
                msg = record.getMessage()
            _access_ring.append({"ts": time.time(), "line": msg})
            # Wake any waiting tailer. setting an already-set event is a no-op.
            try:
                _access_event.set()
            except RuntimeError:
                # No running event loop — happens during tests / shutdown.
                pass

    h = _RingHandler()
    h.setFormatter(logging.Formatter("%(message)s"))
    return h


# ---------------------------------------------------------------------------
# Source availability probes
# ---------------------------------------------------------------------------

def availability() -> dict:
    """Return a JSON-friendly dict describing which streams are usable.

    The UI calls this once on panel open so it can grey-out unavailable
    streams and display a helpful message instead of opening a WS that
    immediately closes with an error.
    """
    iptables_log_enabled = os.environ.get("WGFLOW_IPTABLES_LOG", "").lower() in (
        "1", "true", "yes",
    )
    return {
        "dnsmasq":   {"available": DNSMASQ_LOG.exists(),
                      "reason": None if DNSMASQ_LOG.exists()
                                else "dnsmasq log not found at /var/log/dnsmasq.log"},
        "wireguard": {"available": KERN_LOG.exists(),
                      "reason": None if KERN_LOG.exists()
                                else "host kernel log not bind-mounted — see docker-compose.yml"},
        "iptables":  {"available": KERN_LOG.exists() and iptables_log_enabled,
                      "reason": (None
                                 if (KERN_LOG.exists() and iptables_log_enabled)
                                 else ("set WGFLOW_IPTABLES_LOG=1 in docker-compose"
                                       if KERN_LOG.exists()
                                       else "host kernel log not bind-mounted"))},
        "access":    {"available": True, "reason": None},
    }


# ---------------------------------------------------------------------------
# Streaming primitives
# ---------------------------------------------------------------------------

async def _stream_subprocess(
    websocket: WebSocket,
    cmd: list,
    line_filter: Optional[Callable[[str], bool]] = None,
) -> None:
    """Run `cmd`, forward each stdout line to the WS until either side closes.

    The subprocess is terminated cleanly when the WebSocket disconnects.
    """
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )

    async def reader() -> None:
        assert proc.stdout is not None
        try:
            while True:
                raw = await proc.stdout.readline()
                if not raw:
                    return
                text = raw.decode("utf-8", errors="replace").rstrip("\n")
                if line_filter is not None and not line_filter(text):
                    continue
                await websocket.send_json({"line": text, "ts": time.time()})
        except WebSocketDisconnect:
            return
        except Exception as e:
            # Send the error to the client so they see it instead of a
            # silent connection close.
            try:
                await websocket.send_json({"error": f"reader: {e!r}"})
            except Exception:
                pass

    async def watchdog() -> None:
        """Detect WS disconnect via receive() — if the client closes,
        receive() raises WebSocketDisconnect, and we kill the subprocess."""
        try:
            while True:
                # We don't expect the client to send anything; this just
                # tells us when they hang up.
                await websocket.receive_text()
        except WebSocketDisconnect:
            return
        except Exception:
            return

    reader_task = asyncio.create_task(reader())
    watch_task  = asyncio.create_task(watchdog())

    done, pending = await asyncio.wait(
        {reader_task, watch_task},
        return_when=asyncio.FIRST_COMPLETED,
    )
    for t in pending:
        t.cancel()
    # Tear down subprocess.
    try:
        proc.terminate()
    except ProcessLookupError:
        pass
    try:
        await asyncio.wait_for(proc.wait(), timeout=2.0)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        await proc.wait()


# ---------------------------------------------------------------------------
# Per-source handlers
# ---------------------------------------------------------------------------

async def stream_dnsmasq(websocket: WebSocket) -> None:
    """All dnsmasq log lines, raw. The DNS panel already extracts query
    records — this stream gives operators access to everything else
    (upstream errors, refused replies, cache stats, reload events)."""
    if not DNSMASQ_LOG.exists():
        await websocket.send_json({"error": "dnsmasq log not found"})
        return
    await _stream_subprocess(
        websocket,
        ["tail", "-n", str(INITIAL_LINES), "-F", str(DNSMASQ_LOG)],
    )


async def stream_wireguard(websocket: WebSocket) -> None:
    """Kernel log lines containing `wireguard:`. Note that WG's kernel
    module is conservative about what it logs — most useful entries are
    handshake errors, not routine traffic."""
    if not KERN_LOG.exists():
        await websocket.send_json({
            "error": "host kernel log not bind-mounted — see docker-compose.yml",
        })
        return
    await _stream_subprocess(
        websocket,
        ["tail", "-n", str(INITIAL_LINES), "-F", str(KERN_LOG)],
        line_filter=lambda s: "wireguard:" in s.lower(),
    )


async def stream_iptables(websocket: WebSocket) -> None:
    """Kernel log lines tagged `WGFLOW-DROP:` — packets that hit the
    default DROP rule on WGFLOW_FORWARD. Only meaningful when
    WGFLOW_IPTABLES_LOG=1 (entrypoint adds the LOG rules in that mode)."""
    if not KERN_LOG.exists():
        await websocket.send_json({
            "error": "host kernel log not bind-mounted — see docker-compose.yml",
        })
        return
    iptables_log_enabled = os.environ.get("WGFLOW_IPTABLES_LOG", "").lower() in (
        "1", "true", "yes",
    )
    if not iptables_log_enabled:
        await websocket.send_json({
            "error": "iptables drop logging not enabled — "
                     "set WGFLOW_IPTABLES_LOG=1 in docker-compose",
        })
        return
    await _stream_subprocess(
        websocket,
        ["tail", "-n", str(INITIAL_LINES), "-F", str(KERN_LOG)],
        line_filter=lambda s: "WGFLOW-DROP:" in s,
    )


async def stream_access(websocket: WebSocket) -> None:
    """uvicorn access log. Reads from the in-memory ring populated by
    access_log_handler. No subprocess; we just iterate the ring and
    then wait on _access_event for new entries."""
    # Replay everything currently in the ring so the user gets immediate
    # context.
    for entry in list(_access_ring):
        try:
            await websocket.send_json(entry)
        except Exception:
            return

    # Now stream new entries as they arrive. We do this by snapshotting
    # the ring length each iteration and sending anything beyond it.
    last_len = len(_access_ring)
    try:
        while True:
            # Wait until something is added (event set by the handler).
            _access_event.clear()
            try:
                await asyncio.wait_for(_access_event.wait(), timeout=30)
            except asyncio.TimeoutError:
                # Periodic ping so we notice broken connections.
                try:
                    await websocket.send_json({"ping": time.time()})
                except Exception:
                    return
                continue

            current = list(_access_ring)
            new_entries = current[last_len:] if last_len <= len(current) else current
            for entry in new_entries:
                await websocket.send_json(entry)
            last_len = len(current)
    except WebSocketDisconnect:
        return
    except Exception:
        return


# ---------------------------------------------------------------------------
# Dispatcher (called from main.py's WS route)
# ---------------------------------------------------------------------------

DISPATCH: dict[str, Callable[[WebSocket], Awaitable[None]]] = {
    "dnsmasq":   stream_dnsmasq,
    "wireguard": stream_wireguard,
    "iptables":  stream_iptables,
    "access":    stream_access,
}
