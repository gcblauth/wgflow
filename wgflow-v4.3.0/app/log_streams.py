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
import shlex
import shutil
import time
from pathlib import Path
from typing import Awaitable, Callable, Optional

from fastapi import WebSocket, WebSocketDisconnect


# ---------------------------------------------------------------------------
# Constants & config
# ---------------------------------------------------------------------------

DNSMASQ_LOG = Path("/var/log/dnsmasq.log")
KERN_LOG    = Path("/var/log/kern.log")     # bind-mounted from host (Docker)
                                            # or written by rsyslog (some bare-metal)

# How many lines `tail -F` should print before following. Matches the UI
# buffer cap so opening a stream feels like "you start with the last 500
# lines already in view".
INITIAL_LINES = 500


def _has_journalctl() -> bool:
    """Whether journalctl is available as a fallback. Cached at import
    time because it doesn't change at runtime."""
    return shutil.which("journalctl") is not None


_JOURNALCTL_AVAILABLE = _has_journalctl()


def _kernel_log_available() -> bool:
    """True if there's *some* way to read kernel logs.

    Either /var/log/kern.log exists (Docker bind-mount, or bare-metal
    with rsyslog), or journalctl is installed (modern Ubuntu bare-metal
    where kernel logs live exclusively in journald).
    """
    return KERN_LOG.exists() or _JOURNALCTL_AVAILABLE


def _kernel_log_command(grep_pattern: Optional[str] = None) -> list:
    """Build the right command for streaming kernel logs.

    On Docker (and on hosts with rsyslog), /var/log/kern.log exists and
    `tail -F` on it is the simplest, most efficient approach. On modern
    Ubuntu 22.04+ bare-metal installs, rsyslog isn't installed by default
    and kernel logs only live in journald — `journalctl -k -f` is the
    equivalent. We pick at call-time so a host that adds/removes
    rsyslog without restarting wgflow still picks the right path.

    `grep_pattern` lets callers filter server-side rather than pulling
    every kernel line through the WebSocket and filtering in Python.
    Faster + saves bandwidth on busy hosts where most kernel lines are
    uninteresting (USB events, network probes, etc).
    """
    if KERN_LOG.exists():
        if grep_pattern:
            # Pipe tail through grep --line-buffered so partial lines
            # don't get buffered for seconds at a time. sh -c needed
            # for the pipe.
            return ["sh", "-c",
                    f"tail -n {INITIAL_LINES} -F {KERN_LOG} | "
                    f"grep --line-buffered -F {shlex.quote(grep_pattern)}"]
        return ["tail", "-n", str(INITIAL_LINES), "-F", str(KERN_LOG)]

    # journalctl fallback. -k restricts to kernel ring buffer messages,
    # -f follows new entries, -n shows initial backlog. --no-pager is
    # critical: without it, journalctl tries to invoke `less` even on
    # non-tty stdout in some configs and the stream silently stalls.
    # -o short-iso gives a compact ISO timestamp prefix that mirrors
    # the look of /var/log/kern.log lines, so the UI rendering is
    # consistent across both modes.
    base = ["journalctl", "-k", "-f", "-n", str(INITIAL_LINES),
            "--no-pager", "-o", "short-iso"]
    if grep_pattern:
        # journalctl's --grep filters server-side before rendering.
        # Cleaner than piping through grep, and works whether the
        # pattern's content has shell metacharacters.
        return base + ["--grep", grep_pattern]
    return base

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

    Note: `iptables` is intentionally absent from this dict — that source
    has been replaced by the polling-based /api/peers/acl-stats endpoint
    (env-agnostic, works on bare-metal and Docker without kernel-log
    routing). The UI presents an "acl stats" tab in its place.
    """
    kern_avail = _kernel_log_available()
    no_kern_msg = ("no kernel log source available — install rsyslog or "
                   "ensure journalctl is present (bare-metal), or "
                   "bind-mount /var/log/kern.log (Docker)")
    return {
        "dnsmasq":   {"available": DNSMASQ_LOG.exists(),
                      "reason": None if DNSMASQ_LOG.exists()
                                else "dnsmasq log not found at /var/log/dnsmasq.log"},
        "wireguard": {"available": kern_avail,
                      "reason": None if kern_avail else no_kern_msg},
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
    handshake errors, not routine traffic.

    Reads from /var/log/kern.log if available (Docker bind-mount, or
    bare-metal with rsyslog), otherwise falls back to `journalctl -k -f`
    (modern Ubuntu bare-metal). The grep pattern filters server-side."""
    if not _kernel_log_available():
        await websocket.send_json({
            "error": "no kernel log source — install rsyslog or "
                     "(in Docker) bind-mount /var/log/kern.log",
        })
        return
    # Filter pattern is case-insensitive in the original (line_filter used
    # .lower()). journalctl --grep is regex; tail|grep is substring with
    # the -F flag we pass. To preserve case-insensitivity we use a small
    # bracket regex that works in both contexts.
    await _stream_subprocess(
        websocket,
        _kernel_log_command(grep_pattern="wireguard:"),
        # Belt-and-suspenders: even if server-side grep let something
        # through, the line_filter catches it. Also handles the lowercase
        # variant on hosts where logger emits "Wireguard:".
        line_filter=lambda s: "wireguard:" in s.lower(),
    )


async def stream_iptables(websocket: WebSocket) -> None:
    """Kernel log lines tagged `WGFLOW-DROP:` — packets that hit the
    default DROP rule on WGFLOW_FORWARD. Only meaningful when
    WGFLOW_IPTABLES_LOG=1 (entrypoint adds the LOG rules in that mode)."""
    if not _kernel_log_available():
        await websocket.send_json({
            "error": "no kernel log source — install rsyslog or "
                     "(in Docker) bind-mount /var/log/kern.log",
        })
        return
    iptables_log_enabled = os.environ.get("WGFLOW_IPTABLES_LOG", "").lower() in (
        "1", "true", "yes",
    )
    if not iptables_log_enabled:
        await websocket.send_json({
            "error": "iptables drop logging not enabled — "
                     "set WGFLOW_IPTABLES_LOG=1 in your environment "
                     "(.env file or docker-compose) and restart wgflow",
        })
        return
    await _stream_subprocess(
        websocket,
        _kernel_log_command(grep_pattern="WGFLOW-DROP:"),
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
    # iptables intentionally absent — replaced by the env-agnostic
    # /api/peers/acl-stats counter polling endpoint. The stream_iptables
    # function is preserved above for reference but unreachable from
    # the WS handler.
    "access":    stream_access,
}
