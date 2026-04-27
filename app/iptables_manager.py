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
    """Tear down a peer's chain and all references."""
    chain = _chain_name(peer_id)
    src = _strip_mask(address)

    # Remove jump.
    while _exists(["WGFLOW_FORWARD", "-s", src, "-j", chain]):
        _run(["-D", "WGFLOW_FORWARD", "-s", src, "-j", chain])

    # Flush and drop chain.
    subprocess.run(["iptables", "-F", chain], capture_output=True)
    subprocess.run(["iptables", "-X", chain], capture_output=True)


def apply_peer_acls(peer_id: int, entries: List[ACLEntry]) -> None:
    """Atomically replace this peer's ACL with the given entries.

    Flushes the peer's chain then appends allow rules. Packets that do not
    match any rule in this chain fall back to WGFLOW_FORWARD which drops them.
    """
    chain = _chain_name(peer_id)
    _run(["-F", chain])

    for e in entries:
        args = ["-A", chain, "-d", e.cidr]
        if e.proto is not None:
            args += ["-p", e.proto]
            if e.port is not None:
                args += ["--dport", str(e.port)]
        args += ["-j", "ACCEPT"]
        _run(args)


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
