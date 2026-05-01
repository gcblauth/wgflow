"""DNS override management.

Operators can map specific or wildcard domains to internal IPs. The classic
use case is NAT-loopback workarounds: a phone connected via VPN tries to
reach `mysite.example.com`, DNS returns the operator's PUBLIC IP, the
packet has to traverse the home router's NAT twice, most consumer routers
mishandle that path. With an override, dnsmasq returns the internal IP
directly so the phone connects straight to the local NGINX/proxy box.

Storage: sqlite `dns_overrides` table.
Application: rendered into `/etc/dnsmasq.d/wgflow-overrides.conf` and
applied via SIGHUP to dnsmasq. SIGHUP makes dnsmasq reload its hosts files
and addn-hosts/address rules without dropping in-flight queries.

Pattern syntax (validated by `validate_pattern`):
    example.com           — matches example.com and any subdomain
    *.example.com         — same effect (dnsmasq treats both identically
                            for `address=/.../...` directives)
    mysite.example.com    — matches mysite.example.com and any sub-sub-domain

Target IP: validated as IPv4 in RFC1918 space — using a public IP here is
almost always a misconfig and we refuse it with a clear error.
"""
from __future__ import annotations

import ipaddress
import os
import re
import signal
import subprocess
from pathlib import Path
from typing import List, Optional

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

# Domain segments: letters/digits/hyphens, can't start/end with hyphen, 1-63 chars.
_LABEL_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")


class OverrideError(ValueError):
    """Raised on invalid pattern or target."""


def normalize_pattern(raw: str) -> str:
    """Lower-case, strip leading '*.' since dnsmasq's address= matches
    both bare-domain and wildcard automatically. Also strip trailing dot.

    Returns the normalized form to store in the DB.
    """
    p = raw.strip().lower()
    if p.startswith("*."):
        p = p[2:]
    if p.endswith("."):
        p = p[:-1]
    return p


def validate_pattern(raw: str) -> str:
    """Normalize and validate. Returns the normalized form. Raises OverrideError."""
    p = normalize_pattern(raw)
    if not p:
        raise OverrideError("pattern cannot be empty")
    if "/" in p or " " in p:
        raise OverrideError(f"invalid characters in pattern: {raw!r}")
    labels = p.split(".")
    if len(labels) < 2:
        raise OverrideError(
            f"pattern must contain at least one dot (e.g. 'example.com'): {raw!r}"
        )
    for lbl in labels:
        if not _LABEL_RE.match(lbl):
            raise OverrideError(f"invalid label {lbl!r} in pattern {raw!r}")
    return p


# RFC1918 + a few other ranges that are reasonable internal targets.
_PRIVATE_NETS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("100.64.0.0/10"),     # CGNAT — Tailscale, etc.
    ipaddress.IPv4Network("127.0.0.0/8"),       # loopback (rare but valid)
]


def validate_target(raw: str) -> str:
    """Validate the target IP is private. Returns it as a clean string."""
    raw = raw.strip()
    try:
        ip = ipaddress.IPv4Address(raw)
    except (ipaddress.AddressValueError, ValueError) as e:
        raise OverrideError(f"not a valid IPv4 address: {raw!r} ({e})") from e
    for net in _PRIVATE_NETS:
        if ip in net:
            return str(ip)
    raise OverrideError(
        f"refusing public IP target {raw!r} — DNS overrides should point at "
        f"internal hosts (RFC1918 / 100.64/10 / 127/8). Pointing at a public "
        f"IP almost always indicates a misconfig. If you're certain you want "
        f"this, edit /etc/dnsmasq.d/ on the host directly."
    )


# ---------------------------------------------------------------------------
# Render & apply
# ---------------------------------------------------------------------------

OVERRIDES_FILE = Path("/etc/dnsmasq.d/wgflow-overrides.conf")
DNSMASQ_PIDFILE = Path("/run/dnsmasq/dnsmasq.pid")    # default Debian location


def render_dnsmasq_lines(rows: List[dict]) -> str:
    """Convert DB rows into the dnsmasq drop-in body.

    Format: `address=/<domain>/<ip>`. dnsmasq applies this to the domain
    AND all subdomains, so this single directive handles both wildcard
    and specific use cases.
    """
    lines = [
        "# wgflow DNS overrides — managed file, regenerated on every change.",
        "# To add or remove entries use the wgflow admin UI.",
        "",
    ]
    for r in rows:
        if r.get("note"):
            lines.append(f"# {r['note']}")
        lines.append(f"address=/{r['pattern']}/{r['target_ip']}")
    lines.append("")
    return "\n".join(lines)


def write_and_reload(rows: List[dict]) -> None:
    """Write the drop-in file and HUP dnsmasq to apply.

    Failure modes we tolerate:
      - dnsmasq pidfile missing (process not running yet) → write file, don't HUP
      - SIGHUP fails (permission, race) → log warning, the next dnsmasq start
        will pick up the file
    Failure modes we DON'T tolerate:
      - file write fails (no disk, perms) → raises so the API returns 500
    """
    OVERRIDES_FILE.parent.mkdir(parents=True, exist_ok=True)
    body = render_dnsmasq_lines(rows)
    OVERRIDES_FILE.write_text(body)
    OVERRIDES_FILE.chmod(0o644)

    # SIGHUP via pidfile. Falls back to pgrep if the pidfile is missing.
    pid: Optional[int] = None
    if DNSMASQ_PIDFILE.exists():
        try:
            pid = int(DNSMASQ_PIDFILE.read_text().strip())
        except (ValueError, OSError):
            pid = None
    if pid is None:
        try:
            out = subprocess.run(
                ["pgrep", "-f", "dnsmasq"], capture_output=True, text=True, check=False,
            )
            if out.returncode == 0 and out.stdout.strip():
                pid = int(out.stdout.strip().split()[0])
        except Exception:
            pass

    if pid is None:
        print("[dns_overrides] dnsmasq not running — file written, will apply on next start",
              flush=True)
        return

    try:
        os.kill(pid, signal.SIGHUP)
    except ProcessLookupError:
        print(f"[dns_overrides] pid {pid} from pidfile is stale — file written, "
              f"will apply on next dnsmasq start", flush=True)
    except PermissionError as e:
        print(f"[dns_overrides] could not signal dnsmasq (pid {pid}): {e}",
              flush=True)


# ---------------------------------------------------------------------------
# DB-facing helpers (called from main.py)
# ---------------------------------------------------------------------------

def list_all(conn) -> List[dict]:
    rows = conn.execute(
        "SELECT id, pattern, target_ip, note, created_at FROM dns_overrides "
        "ORDER BY pattern"
    ).fetchall()
    return [dict(r) for r in rows]


def replay_to_dnsmasq(conn) -> None:
    """Called at process startup. Writes the current DB contents to the
    drop-in file so dnsmasq reflects sqlite state from the very first query."""
    rows = list_all(conn)
    write_and_reload(rows)
