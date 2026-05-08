"""Network diagnostics: public IP detection, curl-based speed test, and
on-demand ping/traceroute/mtr/dig/curl-timing tool runners.

Speed test methodology:
    Cloudflare's `speed.cloudflare.com/__down?bytes=N` and `__up` are public
    test endpoints used by speed.cloudflare.com itself. They allow third-
    party use, have a global anycast presence, and require no auth. We
    use them as the single source. A more rigorous test would round-robin
    multiple providers, but Cloudflare alone is plenty for "is my upstream
    behaving."

    Each test:
      1. Tiny warmup request (5 MB) to escape TCP slow-start
      2. Real test (50 MB down, 10 MB up) — sized to take 5-15s on
         typical home upload links
      3. Latency: average of 5 small HEAD requests to /__down?bytes=0
      4. Jitter: stddev of those 5 latency samples

    Caveat: tests measure CURRENT throughput including whatever else is
    happening on the link. They do NOT measure max capacity — only what
    you can use right now. The UI surfaces this.
"""
from __future__ import annotations

import asyncio
import json
import re
import shlex
import statistics
import subprocess
import time
from typing import Optional

import httpx


# ---------------------------------------------------------------------------
# Public IP detection
# ---------------------------------------------------------------------------

# Multiple sources for resilience. Try in order; first 200 wins.
_PUBLIC_IP_SOURCES = [
    "https://api.ipify.org",
    "https://icanhazip.com",
    "https://checkip.amazonaws.com",
    "https://ifconfig.me/ip",
]

_PUBLIC_IP_CACHE = {"ip": None, "fetched_at": 0.0}
_PUBLIC_IP_TTL = 300        # 5 minutes


async def public_ip(force: bool = False) -> Optional[str]:
    """Return the server's public IPv4 address. Cached for 5 minutes.

    Returns None if every source fails (offline, captive portal, etc.).

    v4.2.6: switched from `asyncio.create_subprocess_exec("curl", ...)`
    to `httpx`. The subprocess approach calls `fork()` from the asyncio
    event loop while a worker thread (the metrics tick) may
    concurrently be inside its own `subprocess.run("wg show")` call.
    Linux fork from a multithreaded Python process can wedge the
    child if it inherits a held lock with no thread to release it —
    we observed the asyncio main thread frozen at
    `create_subprocess_exec` with a still-running ghost child
    process, hanging the entire event loop indefinitely (manifested
    as the panel becoming unresponsive after a day or two of
    uptime). httpx does no fork, no subprocess; the request rides
    on the asyncio event loop directly. No lock interaction with
    threads.
    """
    now = time.time()
    if not force and _PUBLIC_IP_CACHE["ip"] and (now - _PUBLIC_IP_CACHE["fetched_at"]) < _PUBLIC_IP_TTL:
        return _PUBLIC_IP_CACHE["ip"]

    # 4-second per-source timeout (matches the old curl --max-time).
    # connect+read covered by the same budget.
    timeout = httpx.Timeout(4.0, connect=4.0)
    # transport=AsyncHTTPTransport(retries=0) — we already iterate
    # sources, no need for httpx-level retries.
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            for url in _PUBLIC_IP_SOURCES:
                try:
                    resp = await client.get(url)
                    ip = resp.text.strip()
                    parts = ip.split(".")
                    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                        _PUBLIC_IP_CACHE["ip"] = ip
                        _PUBLIC_IP_CACHE["fetched_at"] = now
                        return ip
                except Exception:
                    continue
    except Exception:
        # AsyncClient construction itself failed — exotic, but don't
        # crash the request just to learn our public IP.
        pass
    return None


# ---------------------------------------------------------------------------
# Speed test
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Speed test endpoints
# ---------------------------------------------------------------------------
# Each entry describes one provider/region pair. Cloudflare supports both
# directions via dynamic-byte URLs; the others (Hetzner, OVH) are static
# files and are download-only.
#
# Why these specifically (from an Italy-based operator's perspective):
#   - cloudflare:    anycast, will hit nearest PoP (usually Milan). Best default.
#   - hetzner-fsn1:  Germany, common path for Italian → European traffic
#   - hetzner-hel1:  Finland, longer route, useful for "is northern peering ok"
#   - hetzner-ash:   USA East, transatlantic — checks long-haul performance
#   - ovh-rbx:       France, French peering point, alternative European target
#
# The "supports_upload" flag drives UI behaviour: download-only endpoints
# show "—" for the upload number rather than zero, with a tooltip
# explaining why.
# ---------------------------------------------------------------------------

ENDPOINTS = {
    "cloudflare": {
        "label": "Cloudflare (anycast)",
        "down_url": "https://speed.cloudflare.com/__down?bytes={size}",
        "up_url":   "https://speed.cloudflare.com/__up",
        "ping_url": "https://speed.cloudflare.com/__down?bytes=0",
        "supports_upload": True,
        "default": True,
        # 50 MB real download + 5 MB warmup + 10 MB upload = ~65 MB
        "est_mb_per_test": 65,
    },
    "hetzner-fsn1": {
        "label": "Hetzner Falkenstein (DE)",
        "down_url": "https://fsn1-speed.hetzner.com/100MB.bin",
        "up_url":   None,
        "ping_url": "https://fsn1-speed.hetzner.com/",
        "supports_upload": False,
        # Static 100 MB file; no warmup since the file itself is large enough
        # to cover slow-start naturally.
        "est_mb_per_test": 100,
    },
    "hetzner-hel1": {
        "label": "Hetzner Helsinki (FI)",
        "down_url": "https://hel1-speed.hetzner.com/100MB.bin",
        "up_url":   None,
        "ping_url": "https://hel1-speed.hetzner.com/",
        "supports_upload": False,
        "est_mb_per_test": 100,
    },
    "hetzner-ash": {
        "label": "Hetzner Ashburn (US-East)",
        "down_url": "https://ash-speed.hetzner.com/100MB.bin",
        "up_url":   None,
        "ping_url": "https://ash-speed.hetzner.com/",
        "supports_upload": False,
        "est_mb_per_test": 100,
    },
    "ovh-rbx": {
        "label": "OVH Roubaix (FR)",
        "down_url": "http://proof.ovh.net/files/100Mb.dat",
        "up_url":   None,
        "ping_url": "http://proof.ovh.net/files/",
        "supports_upload": False,
        "est_mb_per_test": 100,
    },
}

# Sizes chosen so a typical home connection takes 5–15s per direction.
# Larger = more accurate (TCP slow-start matters less) but slower test.
# Hetzner/OVH only offer fixed file sizes (100MB.bin etc) — we just
# download it whole, the size is determined by the server.
DOWN_BYTES = 50 * 1024 * 1024       # 50 MB (cloudflare; ignored elsewhere)
UP_BYTES   = 10 * 1024 * 1024       # 10 MB
WARMUP_BYTES = 5 * 1024 * 1024      # 5 MB

# Lock so two concurrent speedtest requests don't trample each other —
# they'd compete for upload bandwidth and skew both results low.
_speedtest_lock = asyncio.Lock()


def list_endpoints() -> list[dict]:
    """JSON-friendly endpoint list for the UI dropdown."""
    return [
        {"id": k, "label": v["label"],
         "supports_upload": v["supports_upload"],
         "default": v.get("default", False),
         "est_mb_per_test": v.get("est_mb_per_test", 0)}
        for k, v in ENDPOINTS.items()
    ]


async def _curl_download_url(url: str, timeout: int = 60) -> tuple[float, int]:
    """Download a URL fully, return (seconds, bytes_received).

    Caller pre-formats the URL (substituting `{size}` for Cloudflare-style
    parametric endpoints, or passing the static URL as-is for fixed files).
    """
    start = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        "curl", "-s", "-4", "--max-time", str(timeout),
        "-o", "/dev/null",
        "-w", "%{size_download}",
        url,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    elapsed = time.monotonic() - start
    try:
        bytes_recv = int(stdout.decode().strip())
    except ValueError:
        bytes_recv = 0
    return elapsed, bytes_recv


async def _curl_upload_bytes(url: str, size: int, timeout: int = 60) -> tuple[float, int]:
    """Upload `size` bytes of /dev/zero to `url`, return (seconds, bytes_sent).

    Uses a shell pipeline because chaining two asyncio subprocesses (head's
    stdout → curl's stdin) tries to call .fileno() on a StreamReader, which
    doesn't have one. The shell does the plumbing natively.
    """
    # Build the pipeline as a single shell command. Both pieces (head, curl)
    # take their args from us, not from user input — no injection surface.
    pipeline = (
        f"head -c {int(size)} /dev/zero | "
        f"curl -s -4 --max-time {int(timeout)} "
        f"-o /dev/null -w '%{{size_upload}}' "
        f"-X POST -H 'Content-Type: application/octet-stream' "
        f"--data-binary @- {shlex.quote(url)}"
    )
    start = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        "bash", "-c", pipeline,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    elapsed = time.monotonic() - start
    try:
        bytes_sent = int(stdout.decode().strip())
    except ValueError:
        bytes_sent = 0
    return elapsed, bytes_sent


async def _measure_latency(ping_url: str, samples: int = 5) -> tuple[float, float]:
    """Hit a tiny URL, return (avg_ms, jitter_ms) over N samples."""
    rtts = []
    for _ in range(samples):
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-4", "--max-time", "5",
                "-o", "/dev/null",
                "-w", "%{time_total}",
                ping_url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await proc.communicate()
            t = float(stdout.decode().strip())
            rtts.append(t * 1000)        # seconds → ms
        except Exception:
            continue
        await asyncio.sleep(0.1)         # space the samples a bit

    if not rtts:
        return 0.0, 0.0
    avg = statistics.mean(rtts)
    jit = statistics.stdev(rtts) if len(rtts) > 1 else 0.0
    return avg, jit


def _build_url(template: str, size: int) -> str:
    """Substitute {size} in the URL template if present, else return as-is."""
    if "{size}" in template:
        return template.replace("{size}", str(size))
    return template


async def run_speedtest(endpoint_id: str = "cloudflare") -> dict:
    """Run a speed test against the named endpoint and return the result.

    Result shape:
        {
          "ts": <unix timestamp>,
          "endpoint": <endpoint_id>,
          "ping_ms": <float>,
          "jitter_ms": <float>,
          "down_mbps": <float>,
          "up_mbps": <float>,            # 0.0 if endpoint doesn't support upload
          "duration_s": <float>,
          "error": <str or None>,
        }
    """
    ep = ENDPOINTS.get(endpoint_id)
    if ep is None:
        return {
            "ts": int(time.time()),
            "endpoint": endpoint_id,
            "ping_ms": 0.0, "jitter_ms": 0.0,
            "down_mbps": 0.0, "up_mbps": 0.0,
            "duration_s": 0.0,
            "error": f"unknown endpoint: {endpoint_id}",
        }

    async with _speedtest_lock:
        started = time.time()
        try:
            # Latency first.
            ping_ms, jitter_ms = await _measure_latency(ep["ping_url"], samples=5)

            # Warmup download — only for Cloudflare-style parametric URLs.
            # Static-file endpoints (Hetzner/OVH) — we just go straight to
            # the real download; the file is large enough to cover slow-start
            # naturally.
            if "{size}" in ep["down_url"]:
                await _curl_download_url(_build_url(ep["down_url"], WARMUP_BYTES), timeout=20)

            # Real download.
            down_url = _build_url(ep["down_url"], DOWN_BYTES)
            dt, bytes_recv = await _curl_download_url(down_url, timeout=120)
            down_mbps = (bytes_recv * 8) / (dt * 1_000_000) if dt > 0 else 0.0

            # Upload — only if the endpoint supports it.
            up_mbps = 0.0
            if ep["supports_upload"] and ep.get("up_url"):
                ut, bytes_sent = await _curl_upload_bytes(ep["up_url"], UP_BYTES, timeout=120)
                up_mbps = (bytes_sent * 8) / (ut * 1_000_000) if ut > 0 else 0.0

            return {
                "ts": int(started),
                "endpoint": endpoint_id,
                "ping_ms": round(ping_ms, 2),
                "jitter_ms": round(jitter_ms, 2),
                "down_mbps": round(down_mbps, 2),
                "up_mbps": round(up_mbps, 2),
                "duration_s": round(time.time() - started, 1),
                "error": None,
            }
        except Exception as e:
            return {
                "ts": int(started),
                "endpoint": endpoint_id,
                "ping_ms": 0.0, "jitter_ms": 0.0,
                "down_mbps": 0.0, "up_mbps": 0.0,
                "duration_s": round(time.time() - started, 1),
                "error": f"{type(e).__name__}: {e}",
            }


# ---------------------------------------------------------------------------
# Diagnostic tools — ping/traceroute/mtr/dig/curl-timing
# ---------------------------------------------------------------------------
# These run with bounded timeouts so a borked target can't hang forever.
# Output is captured raw and returned to the UI as a single string —
# the UI displays it in a <pre> block, no parsing on our side.
# ---------------------------------------------------------------------------

# Allowed targets are validated server-side: hostname or IP only, no shell
# metacharacters. We pass the target to subprocess as an arg (not a shell),
# so injection is impossible — but we still validate to prevent users
# typing `; rm -rf /` and being confused that it errors.
_TARGET_OK = __import__("re").compile(r"^[a-zA-Z0-9.:_-]+$")


def _validate_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("empty target")
    if not _TARGET_OK.match(target):
        raise ValueError(f"invalid target: {target!r}")
    if len(target) > 255:
        raise ValueError("target too long")
    return target


async def _run_tool(cmd: list, timeout: int = 30) -> dict:
    """Run a diagnostic command, return {output, exit_code, error}."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return {"output": "", "exit_code": -1, "error": f"timeout after {timeout}s"}

        return {
            "output": stdout.decode("utf-8", errors="replace"),
            "exit_code": proc.returncode,
            "error": None,
        }
    except FileNotFoundError as e:
        return {"output": "", "exit_code": -1, "error": f"tool not found: {e}"}
    except Exception as e:
        return {"output": "", "exit_code": -1, "error": f"{type(e).__name__}: {e}"}


async def tool_ping(target: str, count: int = 3) -> dict:
    """ICMP ping. Count is configurable (1-50); default is 3 for fast feedback.
    Per-probe timeout is 1s so a fully unresponsive target returns within
    `count` seconds rather than the old 2s × 10 probe pattern."""
    target = _validate_target(target)
    try:
        count = int(count)
    except (TypeError, ValueError):
        count = 3
    count = max(1, min(count, 50))
    # Wall-clock budget: 1s per probe + 2s margin for kernel/curl wrapping.
    return await _run_tool(
        ["ping", "-4", "-c", str(count), "-W", "1", target],
        timeout=count + 2,
    )


async def tool_traceroute(target: str) -> dict:
    target = _validate_target(target)
    return await _run_tool(
        ["traceroute", "-n", "-w", "2", "-q", "1", "-m", "20", target],
        timeout=60,
    )


async def tool_mtr(target: str) -> dict:
    """mtr in report mode (-r): sends 10 packets per hop and exits.

    --no-dns / -n: skip reverse DNS lookups (faster, plus DNS failures
                   wouldn't add value to the operator's diagnosis).
    """
    target = _validate_target(target)
    return await _run_tool(
        ["mtr", "-r", "-n", "-c", "10", "-w", target],
        timeout=60,
    )


async def tool_dig(target: str, record_type: str = "A") -> dict:
    target = _validate_target(target)
    record_type = record_type.upper()
    if record_type not in {"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR", "ANY"}:
        raise ValueError(f"unsupported record type: {record_type}")
    return await _run_tool(
        ["dig", "+time=3", "+tries=2", target, record_type],
        timeout=15,
    )


async def tool_curl_timing(target: str) -> dict:
    """Curl with a timing breakdown — DNS, TCP connect, TLS handshake,
    server processing, total. Useful for 'why is this URL slow' questions."""
    target = _validate_target(target)
    # Add scheme if not present so curl doesn't refuse.
    url = target if "://" in target else f"https://{target}"
    fmt = (
        "DNS lookup     : %{time_namelookup}s\n"
        "TCP connect    : %{time_connect}s\n"
        "TLS handshake  : %{time_appconnect}s\n"
        "Pretransfer    : %{time_pretransfer}s\n"
        "Time to first  : %{time_starttransfer}s\n"
        "Total          : %{time_total}s\n"
        "\n"
        "HTTP code      : %{http_code}\n"
        "Bytes received : %{size_download}\n"
        "Avg speed (B/s): %{speed_download}\n"
        "Server IP      : %{remote_ip}\n"
    )
    return await _run_tool(
        ["curl", "-s", "-o", "/dev/null", "-w", fmt, "-L", "--max-time", "20", url],
        timeout=25,
    )


async def tool_tcp(target: str) -> dict:
    """Test TCP connectivity to host:port. Reports connect time + outcome.

    Uses bash's /dev/tcp builtin — no extra package dependency.
    Target format must be `host:port`. Both halves are validated:
      - host: passed through _validate_target (alphanumerics, dots, etc.)
      - port: integer 1-65535
    """
    raw = target.strip()
    if ":" not in raw:
        raise ValueError("tcp target must be host:port (e.g. 1.1.1.1:443)")
    # rsplit so IPv6 brackets don't break us in the future; for now we
    # only accept IPv4/hostnames so this is just defensive.
    host, _, port_str = raw.rpartition(":")
    if not host:
        raise ValueError("tcp target missing host")
    _validate_target(host)            # raises on bad chars
    try:
        port = int(port_str)
    except ValueError:
        raise ValueError(f"port must be a number: {port_str!r}")
    if not (1 <= port <= 65535):
        raise ValueError(f"port out of range (1-65535): {port}")

    # Bash's /dev/tcp/host/port opens a TCP connection. We use `exec` to
    # bind FD 3 to it, which gives a clean error path if the connection
    # fails. `time` reports wall-clock duration. The 3-second timeout is
    # via the `timeout` command — bash itself has no per-operation timeout.
    script = (
        f"exec 3<>/dev/tcp/{host}/{port} && "
        f"echo OPEN && exec 3<&- && exec 3>&-"
    )
    cmd = ["timeout", "3", "bash", "-c", script]
    return await _run_tool(cmd, timeout=5)


DIAG_TOOLS = {
    "ping":       tool_ping,
    "traceroute": tool_traceroute,
    "mtr":        tool_mtr,
    "dig":        tool_dig,
    "curl":       tool_curl_timing,
    "tcp":        tool_tcp,
    "iperf3":     None,        # populated below after function definition
}


async def tool_iperf3(target: str) -> dict:
    """iperf3 client, 5-second test against the named target.

    Target accepts `host` or `host:port` — port defaults to 5201 (iperf3
    default). Requires an iperf3 SERVER on the target side (`iperf3 -s`);
    without it the client will fail with a connection refused error which
    we surface verbatim. Uses -J for JSON output that we display raw.

    Connect timeout 3000ms (3s) so a dead target fails fast instead of
    the default 30s.
    """
    raw = target.strip()
    port = 5201
    if ":" in raw:
        host, _, port_str = raw.rpartition(":")
        if not host:
            raise ValueError("iperf3 target missing host")
        try:
            port = int(port_str)
        except ValueError:
            raise ValueError(f"port must be a number: {port_str!r}")
        if not (1 <= port <= 65535):
            raise ValueError(f"port out of range (1-65535): {port}")
    else:
        host = raw
    _validate_target(host)
    return await _run_tool(
        ["iperf3", "-c", host, "-p", str(port),
         "-t", "5", "-J", "--connect-timeout", "3000"],
        timeout=15,
    )

DIAG_TOOLS["iperf3"] = tool_iperf3


# ---------------------------------------------------------------------------
# iperf3 server (one-shot)
# ---------------------------------------------------------------------------
#
# Different shape from the client tool: we run `iperf3 -s -1` which
# means "listen, accept ONE client test, print results, exit". The
# operator points another machine at this wgflow with `iperf3 -c
# <host> -p <port>`, and the result of that test prints here.
#
# Bounded by a 60-second wrapper timeout so the server doesn't hang
# forever if no client connects. Honors a custom port via the target
# field (e.g. "5202" or ":5202") — defaults to 5201.

async def tool_iperf3_server(target: str) -> dict:
    """One-shot iperf3 server — listens for a single client test."""
    raw = (target or "").strip()
    port = 5201
    if raw:
        # Accept "5202", ":5202", or "host:5202" (host part ignored;
        # we always bind to 0.0.0.0). Just extract the port if
        # present.
        port_str = raw.rsplit(":", 1)[-1] if ":" in raw else raw
        try:
            port = int(port_str)
        except ValueError:
            raise ValueError(f"port must be a number: {port_str!r}")
        if not (1 <= port <= 65535):
            raise ValueError(f"port out of range (1-65535): {port}")

    # `-s` server, `-1` one-shot exit-after-one-test, `-p` port.
    # `-J` JSON output for parseability — but we'll display raw text
    # because the frontend's iperf3-client branch is the JSON
    # consumer; the server output is a transcript we pass through.
    # No `-J`: keep human-readable output.
    return await _run_tool(
        ["iperf3", "-s", "-1", "-p", str(port)],
        timeout=60,
    )


DIAG_TOOLS["iperf3-server"] = tool_iperf3_server


# ---------------------------------------------------------------------------
# tcpdump
# ---------------------------------------------------------------------------
#
# Operator picks an interface (one of the allowlist below) plus an
# optional BPF filter expression. We run tcpdump for at most ~10s OR
# until N packets are captured, whichever comes first, then return
# the captured trace.
#
# Risk model:
#   - Interface is picked from an allowlist (we don't let the operator
#     tcpdump on something we don't expect to exist).
#   - Filter expression is passed as a single argv element, never via
#     a shell. tcpdump's own BPF parser validates it — bad filters
#     come back as a stderr error which we surface verbatim.
#   - Output is capped at 200 packets so a busy interface doesn't
#     return a megabyte of text.
#   - We use -c (max packets) instead of a separate timeout. tcpdump
#     exits naturally after -c packets. The wrapping _run_tool
#     timeout is the safety net.

# Interfaces we allow operators to capture on. wg0 is the gateway.
# Other interfaces: docker eth0 (for debugging upstream connectivity),
# loopback (rare but useful for local-only services), and any wg<N>
# upstream interface that may exist (legacy v4.1.1 feature). We don't
# allow arbitrary interface names — caller-supplied strings are
# checked against this set.
_TCPDUMP_ALLOWED_IFACES_PREFIXES = ("wg", "eth", "lo", "any")
_TCPDUMP_FILTER_RE = re.compile(r"^[A-Za-z0-9 .:/_\-=&|!()<>]*$")
_TCPDUMP_MAX_PACKETS = 200
_TCPDUMP_TIMEOUT = 12      # 10s of capture + 2s margin


async def tool_tcpdump(target: str) -> dict:
    """Run tcpdump on a chosen interface with optional BPF filter.

    Target convention (we shoehorn into the existing single-string
    target field rather than adding a new parameter shape — keeps the
    diag-tools wiring consistent):

        target = "<iface>" — capture everything on iface for ~10s
        target = "<iface>:<bpf>" — capture matching BPF, e.g.
                 "wg0:icmp", "wg0:host 10.99.0.1", "any:port 53"

    Returns up to 200 packets or 10 seconds, whichever comes first.
    """
    raw = target.strip()
    if not raw:
        raise ValueError("specify an interface, e.g. 'wg0' or 'wg0:icmp'")

    if ":" in raw:
        iface, _, bpf = raw.partition(":")
        iface = iface.strip()
        bpf = bpf.strip()
    else:
        iface = raw
        bpf = ""

    # Interface allowlist — must start with a known prefix and contain
    # only safe chars.
    if not iface or not re.fullmatch(r"[a-zA-Z0-9_-]{1,16}", iface):
        raise ValueError(f"interface name invalid: {iface!r}")
    if not any(iface.startswith(p) for p in _TCPDUMP_ALLOWED_IFACES_PREFIXES):
        raise ValueError(
            f"interface {iface!r} not allowed. permitted prefixes: "
            f"{', '.join(_TCPDUMP_ALLOWED_IFACES_PREFIXES)}"
        )

    # Filter expression: bounded length, character-class allowlist
    # (sufficient for typical BPF: ip/host/port/net/and/or/not/etc).
    if bpf:
        if len(bpf) > 200:
            raise ValueError("filter expression too long (max 200 chars)")
        if not _TCPDUMP_FILTER_RE.match(bpf):
            raise ValueError(
                "filter contains characters not in the safe set "
                "(letters, digits, space, .:/_-=&|!()<>)"
            )

    # Wrap with `timeout -s INT N` so tcpdump receives SIGINT after N
    # seconds even if it hasn't hit the -c packet count. tcpdump
    # handles SIGINT gracefully — flushes captured packets to stdout,
    # prints a summary line ("N packets captured"), exits 0. Without
    # the explicit signal, _run_tool's asyncio timeout would SIGKILL
    # the process and we'd lose every captured packet.
    #
    # The capture window is _TCPDUMP_TIMEOUT - 2 (10s) so the wrapping
    # _run_tool budget (12s) has slack for the SIGINT round-trip and
    # the post-exit stdout flush.
    capture_secs = max(1, _TCPDUMP_TIMEOUT - 2)
    cmd = [
        "timeout", "-s", "INT", str(capture_secs),
        "tcpdump",
        "-n",                              # don't resolve DNS
        "-i", iface,
        "-c", str(_TCPDUMP_MAX_PACKETS),   # exit early if N packets seen
        "-tt",                             # timestamps as unix epoch (compact)
        "-q",                              # quick mode (less noise per packet)
    ]
    if bpf:
        cmd.append(bpf)

    return await _run_tool(cmd, timeout=_TCPDUMP_TIMEOUT)


DIAG_TOOLS["tcpdump"] = tool_tcpdump
