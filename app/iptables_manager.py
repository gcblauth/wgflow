"""iptables orchestration for per-peer ACLs.

Design:
    - Baseline chain `WGFLOW_FORWARD` is created by entrypoint.sh and hooked
      into FORWARD for packets arriving on wg0.
    - Each peer gets its own chain `WGFLOW_PEER_<id>`.
    - WGFLOW_FORWARD contains one jump rule per peer, matching by source IP.
    - If no peer chain accepts the packet, it falls off the end of
      WGFLOW_FORWARD and is dropped by the final DROP rule.

Rule application is idempotent: replacing a peer's ACL flushes that peer's
chain and repopulates it. Other peers are not touched.
"""
from __future__ import annotations

import os
import subprocess
from typing import List

from .acl import ACLEntry
from .config import SETTINGS


class IPTablesError(RuntimeError):
    pass


def _run(args: List[str]) -> None:
    proc = subprocess.run(
        ["iptables", *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise IPTablesError(
            f"iptables {' '.join(args)} failed: {proc.stderr.strip()}"
        )


def _exists(args: List[str]) -> bool:
    """Check existence using -C (check). Returns False on non-zero exit."""
    proc = subprocess.run(
        ["iptables", "-C", *args],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode == 0


def _chain_name(peer_id: int) -> str:
    return f"WGFLOW_PEER_{peer_id}"


def _strip_mask(address: str) -> str:
    """'10.13.13.5/32' -> '10.13.13.5'."""
    return address.split("/", 1)[0]


def ensure_base_chain() -> None:
    """Make sure WGFLOW_FORWARD exists and ends with a DROP.

    entrypoint.sh sets up the basics; we call this from the app on startup
    as a belt-and-braces measure. Calling iptables -N on an existing chain
    returns non-zero; that is fine, we ignore it.

    If WGFLOW_IPTABLES_LOG=1, also insert a rate-limited LOG rule just
    before the trailing DROP, so packets that fall through every per-peer
    chain get logged with the WGFLOW-DROP: prefix to the kernel log.
    """
    subprocess.run(["iptables", "-N", "WGFLOW_FORWARD"], capture_output=True)
    # Ensure the final DROP is present.
    if not _exists(["WGFLOW_FORWARD", "-j", "DROP"]):
        _run(["-A", "WGFLOW_FORWARD", "-j", "DROP"])

    # Optional drop logging.
    log_enabled = os.environ.get("WGFLOW_IPTABLES_LOG", "").lower() in (
        "1", "true", "yes",
    )
    log_rule = [
        "WGFLOW_FORWARD",
        "-m", "limit", "--limit", "10/min", "--limit-burst", "5",
        "-j", "LOG", "--log-prefix", "WGFLOW-DROP: ", "--log-level", "4",
    ]
    if log_enabled:
        # Idempotent: only insert if not already present. Insert before
        # the trailing DROP — `-I` defaults to position 1 which would put
        # it before per-peer chains too. We need it at position N-1 (just
        # before DROP), so we delete-then-insert via reverse logic:
        # delete any existing copy, then insert at position 1 of a chain
        # whose only fixed tail rule is DROP — wait, that puts it at the
        # top. We actually want it at the bottom-but-one, which is what
        # iptables's `-I CHAIN <pos>` does relative to existing rules.
        #
        # Simplest: delete it if present, then re-insert just before DROP
        # by computing the current line count and inserting at that
        # position. iptables doesn't expose line count directly, so we
        # use -L --line-numbers and find the DROP.
        if _exists(log_rule):
            _run(["-D"] + log_rule)
        # Find the DROP line number.
        out = subprocess.run(
            ["iptables", "-L", "WGFLOW_FORWARD", "-n", "--line-numbers"],
            capture_output=True, text=True, check=True,
        ).stdout
        drop_line = None
        for ln in out.splitlines():
            parts = ln.split()
            if len(parts) >= 2 and parts[1] == "DROP":
                drop_line = parts[0]
                break
        if drop_line:
            _run(["-I", "WGFLOW_FORWARD", drop_line] + log_rule[1:])
        else:
            # No DROP found (shouldn't happen, we just ensured it above);
            # fall back to appending which is at-least-correct for now.
            _run(["-A"] + log_rule)
    else:
        # If the env var is OFF but a previous run left the LOG rule, remove it.
        while _exists(log_rule):
            _run(["-D"] + log_rule)


def _input_deny_args(src_ip: str, e: ACLEntry) -> List[str]:
    """Build the iptables args for one INPUT DROP rule for a deny entry.

    The rule is scoped to: interface wg0, source = peer tunnel IP, destination
    and port/proto from the ACL entry. This ensures it only blocks this
    specific peer, not all VPN peers.
    """
    args = [
        "INPUT",
        "-i", SETTINGS.interface,
        "-s", src_ip,
        "-d", e.cidr,
    ]
    if e.proto is not None:
        args += ["-p", e.proto]
        if e.port is not None:
            args += ["--dport", str(e.port)]
    args += ["-j", "DROP"]
    return args


def _flush_input_deny_rules(src_ip: str, entries: List[ACLEntry] = None) -> None:
    """Remove INPUT DROP rules for a specific peer source IP.

    If `entries` is provided (the exact rules we installed), we delete by
    full rule spec using -C/-D — precise and reliable.

    If `entries` is None (destroy path or unknown state), we use iptables-save
    to find all INPUT DROP rules for this source IP and delete them by spec.
    This is more reliable than line-number deletion which is sensitive to
    concurrent changes.
    """
    if entries is not None:
        # Fast path: delete exactly what we know we installed.
        for e in entries:
            if not e.is_deny:
                continue
            args = _input_deny_args(src_ip, e)
            while _exists(args):
                subprocess.run(["iptables", "-D"] + args,
                               capture_output=True, check=False)
        return

    # Fallback: use iptables-save which gives us full rule specs, not the
    # display-format output of -L. Each line is in the format:
    #   -A INPUT -i wg0 -s 10.1.69.3 -d ... -j DROP
    # We can delete directly using -D with those args.
    out = subprocess.run(
        ["iptables-save", "-t", "filter"],
        capture_output=True, text=True, check=False,
    ).stdout

    for line in out.splitlines():
        line = line.strip()
        # Match: INPUT chain, DROP target, source matches this peer.
        if (line.startswith("-A INPUT ") and
                f"-s {src_ip}" in line and
                line.endswith("-j DROP")):
            # Convert -A to -D and run.
            delete_line = line.replace("-A INPUT ", "-D INPUT ", 1)
            parts = delete_line.split()
            subprocess.run(
                ["iptables"] + parts,
                capture_output=True, check=False,
            )


def create_peer_chain(peer_id: int, address: str) -> None:
    """Create the per-peer chain and hook it up by source IP.

    Must be called before `apply_peer_acls`. Safe to call if already present.
    """
    chain = _chain_name(peer_id)
    src = _strip_mask(address)

    subprocess.run(["iptables", "-N", chain], capture_output=True)

    # Jump from WGFLOW_FORWARD into this peer's chain. Insert BEFORE the
    # trailing DROP. Using -I at position 2 works as long as position 1 is
    # the established/related rule installed by entrypoint.sh. We make this
    # robust by removing any pre-existing jump first.
    while _exists(["WGFLOW_FORWARD", "-s", src, "-j", chain]):
        _run(["-D", "WGFLOW_FORWARD", "-s", src, "-j", chain])

    # Insert at position 2 (after the conntrack ESTABLISHED rule).
    _run(["-I", "WGFLOW_FORWARD", "2", "-s", src, "-j", chain])


def destroy_peer_chain(peer_id: int, address: str) -> None:
    """Tear down a peer's chain, all FORWARD references, and INPUT deny rules."""
    chain = _chain_name(peer_id)
    src = _strip_mask(address)

    # Remove FORWARD jump.
    while _exists(["WGFLOW_FORWARD", "-s", src, "-j", chain]):
        _run(["-D", "WGFLOW_FORWARD", "-s", src, "-j", chain])

    # Remove any INPUT deny rules for this peer.
    _flush_input_deny_rules(src, entries=None)

    # Flush and drop chain.
    subprocess.run(["iptables", "-F", chain], capture_output=True)
    subprocess.run(["iptables", "-X", chain], capture_output=True)


def apply_peer_acls(
    peer_id: int,
    entries: List[ACLEntry],
    peer_address: str = "",
) -> None:
    """Atomically replace this peer's ACL with the given entries.

    Builds the per-peer FORWARD chain in the correct iptables order:

      1. DENY rules first  (-j DROP)
      2. ALLOW rules after (-j ACCEPT)
      3. Catch-all ACCEPT  (-j ACCEPT) if ANY deny rule is present

    For each deny entry, also adds a matching INPUT DROP rule scoped to
    this peer's source IP and the wg0 interface. This ensures deny rules
    also block traffic destined for the server itself (e.g. the admin
    panel), not just forwarded traffic.

    `peer_address` must be the peer's tunnel address (e.g. "10.1.69.3/32").
    When empty, INPUT rules are skipped (safe fallback — FORWARD rules still
    apply; INPUT rules are the new addition).
    """
    chain = _chain_name(peer_id)
    src = _strip_mask(peer_address) if peer_address else ""

    # Flush the FORWARD chain for this peer.
    _run(["-F", chain])

    # Flush any existing INPUT deny rules for this peer before replacing them.
    # Pass None so _flush_input_deny_rules uses iptables-save to find the
    # actual installed rules — we don't know what was there before this call.
    if src:
        _flush_input_deny_rules(src, entries=None)

    # Sort: deny first, then allow.
    denies  = [e for e in entries if e.is_deny]
    allows  = [e for e in entries if not e.is_deny]
    ordered = denies + allows

    for e in ordered:
        # FORWARD chain rule (unchanged behaviour).
        args = ["-A", chain, "-d", e.cidr]
        if e.proto is not None:
            args += ["-p", e.proto]
            if e.port is not None:
                args += ["--dport", str(e.port)]
        args += ["-j", "DROP" if e.is_deny else "ACCEPT"]
        _run(args)

        # INPUT chain rule — only for deny entries and only when we have
        # the peer's source IP.
        if e.is_deny and src:
            _run(["-I"] + _input_deny_args(src, e))

    # Catch-all ACCEPT for full-tunnel mode.
    if denies:
        _run(["-A", chain, "-j", "ACCEPT"])


def dump_all() -> str:
    """Return the full iptables filter + nat tables as text (for debugging)."""
    out_filter = subprocess.run(
        ["iptables", "-L", "-n", "-v", "--line-numbers"],
        capture_output=True, text=True, check=False,
    ).stdout
    out_nat = subprocess.run(
        ["iptables", "-t", "nat", "-L", "-n", "-v", "--line-numbers"],
        capture_output=True, text=True, check=False,
    ).stdout
    return f"=== filter ===\n{out_filter}\n=== nat ===\n{out_nat}"
