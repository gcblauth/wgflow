"""DNS override management.

Operators can map specific or wildcard domains to internal IPs. The classic
use case is NAT-loopback workarounds: a phone connected via VPN tries to
reach `mysite.example.com`, DNS returns the operator's PUBLIC IP, the
packet has to traverse the home router's NAT twice, most consumer routers
mishandle that path. With an override, dnsmasq returns the internal IP
directly so the phone connects straight to the local NGINX/proxy box.

Storage: sqlite `dns_overrides` table.
Application: rendered into `/etc/dnsmasq.d/wgflow-overrides.conf` and
applied by killing + respawning dnsmasq. v3.8.1: previously this used
SIGHUP, which is wrong — SIGHUP only reloads `addn-hosts` and the lease
file, not `address=` directives in main config or drop-in files. dnsmasq
parses config files only at startup, so any `address=` change requires a
restart.

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
#
# v3.8.3 architecture: we render `address=` lines DIRECTLY INTO
# /etc/dnsmasq.conf (the file dnsmasq starts with via --conf-file=)
# rather than via a /etc/dnsmasq.d/ drop-in. Reason: drop-ins require
# a `conf-dir=` directive in the main config, and different dnsmasq
# builds parse the conf-dir extension filter (`*.conf` vs `.conf`)
# inconsistently. Operators reported overrides being silently ignored
# even when the drop-in file existed and the conf-dir line was present.
# Inline rendering eliminates that variable: if dnsmasq starts at all,
# it reads the directives.
#
# Mechanics:
#   - The template /etc/dnsmasq.conf.template has a marker line:
#       # __WGFLOW_OVERRIDES__
#   - At entrypoint time, the marker is stripped (overrides are blank).
#   - The python app, on every override mutation, re-reads the template,
#     replaces the marker with the rendered address= lines, writes the
#     result to /etc/dnsmasq.conf, then SIGTERMs+respawns dnsmasq.
#   - Same flow runs at app startup (replay_to_dnsmasq) so the running
#     dnsmasq picks up DB state immediately on container boot.

DNSMASQ_TEMPLATE = Path("/etc/dnsmasq.conf.template")
DNSMASQ_CONF = Path("/etc/dnsmasq.conf")
DNSMASQ_PIDFILE = Path("/run/dnsmasq/dnsmasq.pid")    # default Debian location

# v3.8.x kept this for cleanup of legacy drop-ins from older releases.
# Pre-v3.8.3 instances may still have this file on disk; we delete it
# proactively so a stale file doesn't sneak entries into dnsmasq via
# any addn-hosts/conf-dir config the operator might have manually added.
LEGACY_OVERRIDES_FILE = Path("/etc/dnsmasq.d/wgflow-overrides.conf")


def render_address_block(rows: List[dict]) -> str:
    """Render the `address=` directives that get spliced into dnsmasq.conf.

    Format for each entry:
        # comment line (if note is non-empty)
        address=/<domain>/<ip>

    The block has no leading or trailing newline (the marker substitution
    handles whitespace context). Empty rows produce an empty string.
    """
    if not rows:
        return ""
    lines = []
    for r in rows:
        if r.get("note"):
            lines.append(f"# {r['note']}")
        lines.append(f"address=/{r['pattern']}/{r['target_ip']}")
    return "\n".join(lines)


def render_full_conf(rows: List[dict]) -> str:
    """Read the template, substitute the overrides marker, return the
    resulting dnsmasq.conf body.

    The __WGFLOW_UPSTREAMS__ marker is left as-is — entrypoint.sh handles
    that one at container start, and the running dnsmasq.conf already
    has the substituted `server=` lines. Re-reading the TEMPLATE here
    would lose the upstreams; instead we substitute against the LIVE
    /etc/dnsmasq.conf and just splice in the override block.

    Strategy:
      - Read /etc/dnsmasq.conf (which has upstreams already substituted
        by entrypoint.sh, and has the __WGFLOW_OVERRIDES__ marker line
        either as a comment OR replaced with previous overrides).
      - Find the override section bounds via marker comments we add
        (BEGIN/END). Replace everything between them with the new block.
      - On first run (no markers yet), find the position by looking for
        the bare `# __WGFLOW_OVERRIDES__` marker and replace it with our
        BEGIN/END markers wrapping the new block.
    """
    # Read whatever dnsmasq is currently configured with. This preserves
    # the upstream `server=` lines that entrypoint.sh substituted at boot.
    if DNSMASQ_CONF.exists():
        body = DNSMASQ_CONF.read_text()
    elif DNSMASQ_TEMPLATE.exists():
        # Fallback for first run before entrypoint completes — shouldn't
        # happen in practice but defensive.
        body = DNSMASQ_TEMPLATE.read_text()
    else:
        # Neither exists — we're not in the docker environment, give up.
        return ""

    address_block = render_address_block(rows)

    BEGIN = "# __WGFLOW_OVERRIDES_BEGIN__"
    END = "# __WGFLOW_OVERRIDES_END__"

    # Build the replacement block, surrounded by BEGIN/END so subsequent
    # re-renders can find and replace it cleanly.
    new_section = BEGIN + "\n"
    if address_block:
        new_section += address_block + "\n"
    new_section += END

    # Case 1: BEGIN/END markers already present (re-render). Replace
    # everything between them.
    import re
    if BEGIN in body and END in body:
        # Match BEGIN through END inclusive across multiple lines.
        pattern = re.compile(
            re.escape(BEGIN) + r".*?" + re.escape(END),
            re.DOTALL,
        )
        return pattern.sub(new_section, body, count=1)

    # Case 2: Only the original template marker present (first render).
    if "# __WGFLOW_OVERRIDES__" in body:
        return body.replace("# __WGFLOW_OVERRIDES__", new_section, 1)

    # Case 3: Neither marker present. The conf was generated from an
    # older entrypoint that stripped the marker entirely. Append at
    # the end of the file. Better than failing — the override directive
    # will still take effect.
    return body.rstrip() + "\n\n" + new_section + "\n"


def write_conf_atomic(body: str) -> None:
    """Write /etc/dnsmasq.conf atomically (temp file + rename)."""
    tmp = DNSMASQ_CONF.with_suffix(".conf.tmp")
    tmp.write_text(body)
    tmp.chmod(0o644)
    tmp.replace(DNSMASQ_CONF)


def write_and_reload(rows: List[dict]) -> None:
    """Render the new /etc/dnsmasq.conf and restart dnsmasq.

    v3.8.3: switched from drop-in file to inline rendering of the
    address= directives directly into /etc/dnsmasq.conf, eliminating
    the conf-dir parsing variability that caused v3.8/v3.8.1/v3.8.2 to
    silently ignore overrides on some operators' setups. See module
    docstring for rationale.

    Steps:
      1. Read the current /etc/dnsmasq.conf, splice the rendered
         address= block into the marker section, write atomically.
      2. Clean up any legacy /etc/dnsmasq.d/wgflow-overrides.conf so
         it can't conflict if the operator has a stray conf-dir line
         lying around.
      3. SIGTERM the running dnsmasq, wait for clean exit, respawn.
      4. Verify the respawn succeeded and capture stderr if it didn't.

    Failure modes:
      - file write fails (perms, no space) → raises, API returns 500
      - dnsmasq not running yet (startup race) → write file, log,
        return cleanly. The running config will pick up overrides at
        next start.
      - dnsmasq respawn fails to bind → captured stderr is logged so
        the operator can see why; the file IS still on disk so the
        next manual restart will recover.
    """
    # 1. Render and write the new /etc/dnsmasq.conf.
    new_body = render_full_conf(rows)
    if not new_body:
        # Template/conf both missing — likely a non-docker dev environment.
        # Don't crash; the API caller will get its own 500 if the operator
        # is in a broken state.
        print("[dns_overrides] dnsmasq.conf not present — skipping render "
              "(probably a dev environment)", flush=True)
        return
    write_conf_atomic(new_body)

    # 2. Clean up legacy drop-in (only present on instances upgraded
    # from v3.8.0–v3.8.2). Writing an empty file rather than deleting,
    # to avoid surprising operators who may have intentionally added
    # content there. If the file existed and had wgflow content,
    # it gets a benign comment; otherwise we leave it alone.
    try:
        if LEGACY_OVERRIDES_FILE.exists():
            existing = LEGACY_OVERRIDES_FILE.read_text()
            if "wgflow DNS overrides" in existing:
                LEGACY_OVERRIDES_FILE.write_text(
                    "# wgflow DNS overrides moved to /etc/dnsmasq.conf "
                    "directly in v3.8.3.\n"
                    "# This file is no longer used and may be deleted.\n"
                )
    except OSError as e:
        # Non-fatal; the legacy cleanup is best-effort.
        print(f"[dns_overrides] legacy file cleanup failed: {e!r}", flush=True)

    # 3-4. Restart dnsmasq.
    _restart_dnsmasq()


def _restart_dnsmasq() -> None:
    """SIGTERM the running dnsmasq and respawn. Internal helper.

    Extracted from write_and_reload so the startup-replay path can call
    it without going through the full file-render dance (which is also
    valuable on its own — it's run from main.py's startup hook).
    """
    # Find dnsmasq pid.
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
        print("[dns_overrides] dnsmasq not running — config written, "
              "will apply on next dnsmasq start", flush=True)
        return

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except PermissionError as e:
        print(f"[dns_overrides] could not signal dnsmasq (pid {pid}): {e} — "
              f"config written; restart container or `kill -TERM {pid}` "
              f"to apply", flush=True)
        return

    # Wait up to 3s for the old process to exit.
    import time
    for _ in range(30):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    # Extra settle time for socket release.
    time.sleep(0.2)

    # Spawn new dnsmasq with stderr captured so failures are visible.
    try:
        proc = subprocess.Popen(
            ["dnsmasq", "--conf-file=" + str(DNSMASQ_CONF), "--no-daemon"],
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        print("[dns_overrides] dnsmasq binary not found — config written "
              "but cannot restart", flush=True)
        return
    except Exception as e:
        print(f"[dns_overrides] dnsmasq respawn failed: {e!r}", flush=True)
        return

    # Verify it's still alive after a moment.
    time.sleep(0.3)
    if proc.poll() is not None:
        try:
            err = proc.stderr.read().decode('utf-8', errors='replace').strip()
        except Exception:
            err = '(could not read stderr)'
        print(f"[dns_overrides] new dnsmasq exited immediately "
              f"(rc={proc.returncode}). stderr: {err}", flush=True)
        return

    try:
        proc.stderr.close()
    except Exception:
        pass

    print(f"[dns_overrides] dnsmasq restarted (pid {proc.pid})", flush=True)


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
