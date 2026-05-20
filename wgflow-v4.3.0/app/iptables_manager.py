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
import time
from typing import Any, Dict, List

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


def _purge_jump(chain_args: List[str]) -> None:
    """Idempotently remove a FORWARD jump rule, however it got there.

    The naive `while _exists: _run("-D")` pattern crashes when iptables
    semantics around half-broken state diverge from common sense — for
    example when the target chain referenced by a jump rule was
    flushed/dropped externally, `-C` may still report the rule as
    present but `-D` errors with "No chain/target/match by that name".
    Different iptables versions (legacy vs nft) disagree about which
    of those two operations is the source of truth.

    This helper does what the caller actually wants: "after I return,
    that jump rule is not in the table." It tolerates both kinds of
    iptables error and bails out the moment iptables says no.

    Caller passes the rule body without the operation flag — e.g.
    ["WGFLOW_FORWARD", "-s", "10.0.0.1", "-j", "WGFLOW_PEER_5"].
    """
    # Bound the loop. In practice we expect 0 or 1 iterations; >5 is a
    # sign something's pathologically wrong and we should give up
    # rather than spin.
    for _ in range(10):
        if not _exists(chain_args):
            return
        proc = subprocess.run(
            ["iptables", "-D", *chain_args],
            capture_output=True, text=True, check=False,
        )
        if proc.returncode != 0:
            # iptables refused to delete the rule. Most common reason:
            # the target chain no longer exists, but the jump rule's
            # entry in -C still resolves. We can't make this state
            # consistent from here. Log and move on — the caller's
            # next step (recreate the chain + re-insert the jump) will
            # resolve the inconsistency.
            print(f"[iptables] _purge_jump: iptables refused to delete "
                  f"{' '.join(chain_args)}: {proc.stderr.strip()}; "
                  f"continuing — recreate will reconcile",
                  flush=True)
            return


def _chain_name(peer_id: int) -> str:
    return f"WGFLOW_PEER_{peer_id}"


def _strip_mask(address: str) -> str:
    """'10.13.13.5/32' -> '10.13.13.5'."""
    return address.split("/", 1)[0]


# ---------------------------------------------------------------------------
# MSS clamping (v3.6)
# ---------------------------------------------------------------------------
# When enabled, install a single iptables rule in the `mangle` table on
# FORWARD that rewrites TCP SYN packet MSS to clamp to the path MTU.
# Fixes TCP black-hole on paths where ICMP PMTUD doesn't work — very
# common because many ISPs block ICMP fragmentation-needed. Without
# clamping, large transfers stall mid-stream; with it, TCP endpoints
# size their segments to fit.
#
# Rule:
#   iptables -t mangle -A FORWARD -o wg0 -p tcp --tcp-flags SYN,RST SYN
#       -j TCPMSS --clamp-mss-to-pmtu
#
# `-o wg0` scopes to packets exiting through the tunnel. The opposite
# direction (peer → server SYN) carries the client's own MSS choice;
# if the client's path is constrained, set client_mtu in the generated
# config instead (different knob, see _peer_client_conf).
#
# The mangle table is not flushed on each apply_peer_acls call — only
# the filter table's WGFLOW chains are. So this rule, once installed,
# stays installed across ACL changes. We only touch it when the toggle
# itself flips (or on startup replay if the persisted state says so).

_MSS_CLAMP_ARGS = [
    "-t", "mangle", "FORWARD",
    "-o", SETTINGS.interface,
    "-p", "tcp",
    "--tcp-flags", "SYN,RST", "SYN",
    "-j", "TCPMSS", "--clamp-mss-to-pmtu",
]


def mss_clamp_present() -> bool:
    """Whether the MSS clamp rule is currently installed."""
    # iptables -C returns 0 if the rule exists, nonzero otherwise.
    proc = subprocess.run(
        ["iptables", "-C"] + _MSS_CLAMP_ARGS,
        capture_output=True, check=False,
    )
    return proc.returncode == 0


def enable_mss_clamp() -> None:
    """Install the MSS clamp rule. Idempotent."""
    if mss_clamp_present():
        return
    subprocess.run(
        ["iptables", "-A"] + _MSS_CLAMP_ARGS,
        capture_output=True, check=False,
    )


def disable_mss_clamp() -> None:
    """Remove the MSS clamp rule. Idempotent.

    Loops because earlier buggy code paths could have inserted it twice;
    `-D` removes one occurrence per call.
    """
    safety = 0
    while mss_clamp_present() and safety < 8:
        subprocess.run(
            ["iptables", "-D"] + _MSS_CLAMP_ARGS,
            capture_output=True, check=False,
        )
        safety += 1


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
        #
        # v4.2-rebuild: tolerate iptables refusal on -D. The naive
        # `_run("-D")` pattern crashes when iptables -C reports the rule
        # as present but -D refuses (legacy vs nft semantics, or LOG
        # target module load issue). Same fix as the env-var-OFF path
        # below at the LOG cleanup site. We cap the loop at 10 iterations
        # to defend against a pathological state machine that always
        # claims the rule exists but always refuses to delete it.
        for _ in range(10):
            if not _exists(log_rule):
                break
            proc = subprocess.run(
                ["iptables", "-D"] + log_rule,
                capture_output=True, text=True, check=False,
            )
            if proc.returncode != 0:
                print(f"[iptables] LOG rule pre-insert cleanup refused: "
                      f"{proc.stderr.strip()}; continuing — re-insert "
                      f"will reconcile", flush=True)
                break
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
        # Same idempotent-tolerant pattern as _purge_jump — bound the loop
        # and don't crash on any iptables refusal, since this cleanup is
        # best-effort.
        for _ in range(10):
            if not _exists(log_rule):
                break
            proc = subprocess.run(
                ["iptables", "-D"] + log_rule,
                capture_output=True, text=True, check=False,
            )
            if proc.returncode != 0:
                print(f"[iptables] LOG rule cleanup refused: "
                      f"{proc.stderr.strip()}", flush=True)
                break

    # v4.2-pre: ensure baseline FORWARD rules for the multisite overlay
    # (10.99.0.0/24 on wg1). These are idempotent — safe to call on
    # every replay even though they only need to exist once.
    _ensure_multisite_baseline_rules()


def ensure_multisite_baseline_rules(conn=None) -> None:
    """Public wrapper for _ensure_multisite_baseline_rules.

    Called from _replay_state_to_kernel with a live DB conn so per-link
    advertised-network ACCEPT rules can be installed alongside the
    overlay baseline. Also called internally from ensure_base_chain
    at boot (before DB is open) with no conn — installs only the
    baseline overlay↔overlay + overlay→8080 rules at that point.
    """
    _ensure_multisite_baseline_rules(conn=conn)


def _ensure_multisite_baseline_rules(conn=None) -> None:
    """Install (or no-op if already present) the FORWARD rules that
    govern multisite overlay traffic.

    Default policy = deny. We add specific allow rules for:
      1. Overlay ↔ overlay (10.99.0.0/24 ↔ 10.99.0.0/24): the panel-
         federation handshake + future cross-panel API traffic flows
         here. Bidirectional: matters for the responder side too.
      2. Overlay → host 8080/tcp: the panel's HTTP listener. Reached
         BY the overlay peers TO our panel. The conntrack-established
         rule already in WGFLOW_FORWARD handles return traffic, so
         we only need the forward direction allowed.
      3. v4.2-rebuild: per-link advertised network ACCEPTs. For each
         enabled multisite link, ACCEPT FORWARD from the remote's
         overlay /32 to each CIDR in local_advertised. Read from the
         optional `conn` parameter so tests / standalone calls can
         skip per-link rules cleanly.

    Anything else from 10.99.0.0/24 falls through to the WGFLOW_FORWARD
    tail DROP. This is the "default deny" the operator asked for.

    NOTE on inserting before DROP: WGFLOW_FORWARD ends in -A WGFLOW_FORWARD
    -j DROP. We use -I (insert) which adds at position 1 by default,
    placing our rules before the DROP. Multiple invocations of -I would
    pile up duplicates; we guard with -C (check) before -I.
    """
    if not SETTINGS.multisite_enabled:
        return

    overlay_cidr = "10.99.0.0/24"
    rules = [
        # 1. overlay ↔ overlay (panel federation, cross-panel API).
        ["WGFLOW_FORWARD", "-s", overlay_cidr, "-d", overlay_cidr,
         "-j", "ACCEPT"],
        # 2. overlay → host:8080 (any local panel listener).
        # Note: "-d <host_ip>" is hard to predict at iptables setup time
        # (the host IP varies). We match on the destination port
        # instead — any TCP traffic to port 8080 from the overlay is
        # ACCEPT. This is the correct shape because the panel always
        # listens on 8080 inside the container; the SNAT/routing
        # delivers overlay packets bound for the panel to that port.
        # Note: panel traffic locally-destined goes through INPUT,
        # not FORWARD — this rule is defense-in-depth in case INPUT
        # default changes from ACCEPT.
        ["WGFLOW_FORWARD", "-s", overlay_cidr,
         "-p", "tcp", "--dport", "8080", "-j", "ACCEPT"],
    ]

    # 3. v4.2-rebuild: per-link advertised network rules. For each
    # established multisite link, allow FORWARD from the remote's
    # overlay /32 to each CIDR in our local_advertised list. This is
    # the data-plane reach: the remote wgflow's clients can route
    # through us to networks we explicitly advertised. Without these
    # rules the WGFLOW_FORWARD tail DROP would kill those packets
    # even though AllowedIPs let them through cryptokey routing.
    #
    # Per-link rules are read from federation_links via the conn
    # passed in (caller supplies it from the replay context). They
    # don't auto-update on link mutation, so we re-install on every
    # replay. This is idempotent — the _exists check below
    # short-circuits if the rule is already in place. On disable/
    # delete we don't bother removing the rules; they become orphaned
    # ACCEPTs that don't match anything (the source overlay IP isn't
    # bound to any active peer) so they're effectively dead.
    if conn is not None:
        try:
            link_rows = conn.execute(
                "SELECT remote_overlay_addr, local_advertised "
                "FROM federation_links WHERE enabled=1"
            ).fetchall()
            for lr in link_rows:
                src = (lr["remote_overlay_addr"] or "").split("/", 1)[0]
                if not src:
                    continue
                advertised = (lr["local_advertised"] or "").strip()
                if not advertised:
                    continue
                for cidr in advertised.split(","):
                    cidr = cidr.strip()
                    if not cidr or cidr in ("0.0.0.0/0", "::/0"):
                        continue
                    rules.append([
                        "WGFLOW_FORWARD", "-s", f"{src}/32",
                        "-d", cidr, "-j", "ACCEPT",
                    ])
        except Exception as e:
            print(f"[iptables] per-link advertised-network rule build failed: "
                  f"{e}", flush=True)

    for r in rules:
        if not _exists(r):
            try:
                _run(["-I"] + r)
            except IPTablesError as e:
                # Don't crash the whole replay if a rule install fails —
                # log and continue. Loss of multisite forwarding is
                # bad but not as bad as a failed boot.
                print(f"[iptables] failed to install multisite rule "
                      f"{' '.join(r)}: {e}", flush=True)

    # v4.2-rebuild data-plane SNAT: when an overlay-source packet exits
    # via something OTHER than wg0 (i.e. it's heading onto a local LAN
    # via eth0 to reach an advertised-network destination), masquerade
    # it. Otherwise the LAN host sees source 10.99.0.X — for which it
    # has no return route — and the reply goes nowhere. This is the
    # exact same pattern as the client-subnet MASQUERADE in
    # entrypoint.sh, just for the multisite overlay subnet.
    #
    # The `-t nat -A POSTROUTING` rule isn't in the WGFLOW_FORWARD
    # chain (different table), so it can't go through the rules-list
    # loop above. Handle it directly with subprocess.
    #
    # Idempotent: -C check before -A. Operator can disable this by
    # setting WG_MULTISITE_NO_SNAT=1 (future flag — for now SNAT-by-
    # default is hardcoded since that's the "it just works" path; the
    # alternative — setting up reverse routes on every LAN host —
    # isn't reasonable for a default config).
    # Build as: iptables -t nat -A POSTROUTING <match-args> -j MASQUERADE
    # match_args is the slice that goes between the chain spec and the
    # target. We split the full rule into the iptables-binary-and-table
    # prefix (3 elements: "iptables", "-t", "nat") and the rest, then
    # insert "-A POSTROUTING" or "-C POSTROUTING" between them.
    nat_prefix = ["iptables", "-t", "nat"]
    nat_match = [
        "-s", overlay_cidr,
        "!", "-o", SETTINGS.interface,
        "-j", "MASQUERADE",
    ]
    check_proc = subprocess.run(
        nat_prefix + ["-C", "POSTROUTING"] + nat_match,
        capture_output=True, text=True, check=False,
    )
    if check_proc.returncode != 0:
        add_proc = subprocess.run(
            nat_prefix + ["-A", "POSTROUTING"] + nat_match,
            capture_output=True, text=True, check=False,
        )
        if add_proc.returncode != 0:
            print(f"[iptables] failed to install multisite SNAT rule: "
                  f"{add_proc.stderr.strip()}", flush=True)


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


def _input_log_args(src_ip: str, e: ACLEntry) -> List[str]:
    """Build the iptables args for one INPUT LOG rule mirroring a deny entry.

    Same match clauses as _input_deny_args (interface, source, destination,
    port/proto) but with a LOG target instead of DROP. Rate-limited to
    10/min with a burst of 5 — matches the fall-through LOG rule in
    WGFLOW_FORWARD so a flood of denied traffic doesn't spam the kernel
    log. Uses the same `WGFLOW-DROP:` prefix as the fall-through path
    so the iptables-drops stream catches both with one filter.

    Only installed when WGFLOW_IPTABLES_LOG=1 is set in the environment;
    apply_peer_acls gates the call accordingly.
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
    args += [
        "-m", "limit", "--limit", "10/min", "--limit-burst", "5",
        "-j", "LOG", "--log-prefix", "WGFLOW-DROP: ", "--log-level", "4",
    ]
    return args


def _forward_log_args(chain: str, e: ACLEntry) -> List[str]:
    """LOG rule mirroring a FORWARD-chain deny entry.

    Same match clauses as the per-peer chain's DROP rule built in
    apply_peer_acls. Used to log explicit deny hits in the forwarded
    traffic path (the INPUT path covers traffic to the server itself;
    this covers traffic to other LAN hosts).
    """
    args = ["-A", chain, "-d", e.cidr]
    if e.proto is not None:
        args += ["-p", e.proto]
        if e.port is not None:
            args += ["--dport", str(e.port)]
    args += [
        "-m", "limit", "--limit", "10/min", "--limit-burst", "5",
        "-j", "LOG", "--log-prefix", "WGFLOW-DROP: ", "--log-level", "4",
    ]
    return args


def _flush_input_deny_rules(src_ip: str, entries: List[ACLEntry] = None) -> None:
    """Remove INPUT DROP rules (and matching LOG rules) for a peer source IP.

    If `entries` is provided (the exact rules we installed), we delete by
    full rule spec using -C/-D — precise and reliable. We delete both
    the DROP and the LOG variant for each deny entry; if WGFLOW_IPTABLES_LOG
    was off when the rule was installed (so no LOG was added), the LOG
    delete attempt simply finds nothing and is a no-op.

    If `entries` is None (destroy path or unknown state), we use iptables-save
    to find all INPUT rules for this source IP — both DROP and LOG variants.
    More reliable than line-number deletion which is sensitive to concurrent
    changes.
    """
    if entries is not None:
        # Fast path: delete exactly what we know we installed. We try to
        # delete both DROP and LOG variants for each deny — whichever is
        # actually present gets deleted, the other call is a no-op (the
        # iptables -D returns an error code that we ignore via check=False).
        for e in entries:
            if not e.is_deny:
                continue
            for args in (_input_deny_args(src_ip, e),
                         _input_log_args(src_ip, e)):
                while _exists(args):
                    subprocess.run(["iptables", "-D"] + args,
                                   capture_output=True, check=False)
        return

    # Fallback: use iptables-save which gives us full rule specs, not the
    # display-format output of -L. Each line is in the format:
    #   -A INPUT -i wg0 -s 10.1.69.3 -d ... -j DROP
    #   -A INPUT -i wg0 -s 10.1.69.3 -d ... -j LOG --log-prefix "..." ...
    # We delete both: anything matching this peer's source IP.
    out = subprocess.run(
        ["iptables-save", "-t", "filter"],
        capture_output=True, text=True, check=False,
    ).stdout

    for line in out.splitlines():
        line = line.strip()
        if not (line.startswith("-A INPUT ") and f"-s {src_ip}" in line):
            continue
        # Match either DROP terminator OR a LOG rule with our prefix.
        # Both are scoped to the peer's source IP and our wg interface,
        # so the IP match alone narrows it tight enough — but we still
        # check the target to avoid touching unrelated INPUT rules
        # (e.g. an operator's hand-added ACCEPT for management traffic).
        is_drop = line.endswith("-j DROP")
        is_our_log = ("-j LOG" in line and "WGFLOW-DROP:" in line)
        if not (is_drop or is_our_log):
            continue
        # Convert -A to -D and run.
        delete_line = line.replace("-A INPUT ", "-D INPUT ", 1)
        # iptables-save quotes the log prefix; shlex.split parses it back
        # into the right argv shape that iptables -D needs.
        import shlex
        parts = shlex.split(delete_line)
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
    # robust by removing any pre-existing jump first — see _purge_jump for
    # why a naive while-loop here was crash-prone.
    _purge_jump(["WGFLOW_FORWARD", "-s", src, "-j", chain])

    # Insert at position 2 (after the conntrack ESTABLISHED rule).
    _run(["-I", "WGFLOW_FORWARD", "2", "-s", src, "-j", chain])


def destroy_peer_chain(peer_id: int, address: str) -> None:
    """Tear down a peer's chain, all FORWARD references, and INPUT deny rules."""
    chain = _chain_name(peer_id)
    src = _strip_mask(address)

    # Remove FORWARD jump (idempotent, tolerant of half-broken state).
    _purge_jump(["WGFLOW_FORWARD", "-s", src, "-j", chain])

    # Remove any INPUT deny rules for this peer.
    _flush_input_deny_rules(src, entries=None)

    # Flush and drop chain.
    subprocess.run(["iptables", "-F", chain], capture_output=True)
    subprocess.run(["iptables", "-X", chain], capture_output=True)


# ---------------------------------------------------------------------------
# Federation chains (v4.0)
# ---------------------------------------------------------------------------
# Each federation_links row gets its own FORWARD-side chain. The chain
# does ONE thing: drop everything. Federation peers can talk to THIS box
# (handled implicitly by INPUT — we don't add a default-drop on INPUT for
# fed addresses, so the panel listener accepts them naturally) but cannot
# transit through this box to reach client peers or other fed peers.
#
# The trust model is "operators paired this link, they can panel-into us"
# — but even so, we don't want a compromised remote wgflow to be able to
# pivot into our client tunnels. So FORWARD from the federation overlay
# is hard-blocked at iptables, regardless of what any peer ACL might say.
#
# Naming: WGFLOW_FED_<link_id>. Stays out of WGFLOW_PEER_<id> namespace
# so the existing dump/stats code doesn't pick them up as ACL chains.

def _fed_chain_name(link_id: int) -> str:
    return f"WGFLOW_FED_{link_id}"


def create_federation_chain(link_id: int, remote_fed_addr: str) -> None:
    """Hook a federation peer's source address into a drop-everything chain.

    Idempotent. The chain only contains a DROP — we don't expose any
    ACCEPT rules from federation peers into the client subnet. INPUT
    traffic (panel access etc.) is unaffected; this is FORWARD-only.

    Note: we deliberately do NOT add this jump to WGFLOW_FORWARD's
    chain-of-jumps for client peers. WGFLOW_FORWARD's structure is
    "client source IP → that client's chain → DROP at end". Federation
    sources don't match any client chain. Without this addition, fed
    traffic falls through to the trailing DROP — which is the right
    behavior! So why have a dedicated chain at all?
    Two reasons:
    1. Visibility: `iptables -L WGFLOW_FED_<id>` with packet counters
       lets the operator confirm the rule is in the path.
    2. Future-proofing: when v4.1 adds opt-in cross-site routing, the
       chain is where the ACCEPT rules will land. Today it's a DROP-only
       no-op layered on top of the WGFLOW_FORWARD trailing DROP, but
       it's where the policy hook will live.
    """
    chain = _fed_chain_name(link_id)
    src = _strip_mask(remote_fed_addr)

    subprocess.run(["iptables", "-N", chain], capture_output=True)
    # Idempotent install of the trailing DROP.
    if not _exists([chain, "-j", "DROP"]):
        _run(["-A", chain, "-j", "DROP"])

    # Hook into WGFLOW_FORWARD via a source-IP jump, just like client peers.
    # Insert at position 2 (after the conntrack ESTABLISHED rule). We
    # intentionally place fed jumps at the same position as client peers —
    # ordering between fed jumps and client jumps doesn't matter because
    # they have disjoint source-IP matches.
    _purge_jump(["WGFLOW_FORWARD", "-s", src, "-j", chain])
    _run(["-I", "WGFLOW_FORWARD", "2", "-s", src, "-j", chain])


def destroy_federation_chain(link_id: int, remote_fed_addr: str) -> None:
    """Tear down a federation chain. Idempotent."""
    chain = _fed_chain_name(link_id)
    src = _strip_mask(remote_fed_addr)

    _purge_jump(["WGFLOW_FORWARD", "-s", src, "-j", chain])

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

    # Mirror ensure_base_chain's gate: the LOG rules only get installed
    # when the operator has opted in via WGFLOW_IPTABLES_LOG. Without
    # this, every box's kernel log would get noise from default behavior.
    log_enabled = os.environ.get("WGFLOW_IPTABLES_LOG", "").lower() in (
        "1", "true", "yes",
    )

    for e in ordered:
        # FORWARD chain rule (unchanged behaviour).
        args = ["-A", chain, "-d", e.cidr]
        if e.proto is not None:
            args += ["-p", e.proto]
            if e.port is not None:
                args += ["--dport", str(e.port)]
        args += ["-j", "DROP" if e.is_deny else "ACCEPT"]

        # For deny entries with logging on, install the LOG rule first
        # (so it appears earlier in the chain than the DROP that follows).
        # Append-order matters: LOG is non-terminal, DROP is terminal,
        # so the kernel walks LOG → log line → next rule → DROP → drop.
        if e.is_deny and log_enabled:
            _run(_forward_log_args(chain, e))
        _run(args)

        # INPUT chain rule — only for deny entries and only when we have
        # the peer's source IP. Order is reversed here vs FORWARD because
        # we use -I (insert at position 1): install DROP first, then LOG,
        # so LOG ends up at position 1 (matched first → logs), DROP at
        # position 2 (matched second → drops).
        if e.is_deny and src:
            _run(["-I"] + _input_deny_args(src, e))
            if log_enabled:
                _run(["-I"] + _input_log_args(src, e))

    # Catch-all ACCEPT for full-tunnel mode.
    #
    # When the operator has any deny entry, we want the chain to end
    # with an ACCEPT so that anything not explicitly denied falls
    # through to "allowed" (full-tunnel semantics: deny-list, not
    # allow-list).
    #
    # BUT — if the operator's ACL already includes an allow rule for
    # 0.0.0.0/0 (with no port/proto restriction), that rule already IS
    # the catch-all. Adding our own catch-all on top produces a dead
    # duplicate ACCEPT at the chain tail. We saw this in v3.6: peers
    # with ACL "!host:22/tcp, 0.0.0.0/0" ended up with chains like
    # [LOG, DROP, ACCEPT 0/0, ACCEPT 0/0] — second ACCEPT unreachable.
    #
    # Detect by checking if any allow entry is unconditional 0.0.0.0/0
    # with no port/proto narrowing. Anything more restrictive (e.g.
    # "0.0.0.0/0:443/tcp") is NOT a catch-all — only port-443 traffic
    # would match — so the trailing ACCEPT is still needed for everything
    # else.
    if denies:
        already_has_catchall = any(
            e.cidr == "0.0.0.0/0" and e.port is None and e.proto is None
            for e in allows
        )
        if not already_has_catchall:
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


# ---------------------------------------------------------------------------
# ACL stats — replaces the failed iptables-LOG-streaming UI
# ---------------------------------------------------------------------------
# Reading per-rule packet/byte counters is environment-agnostic: works the
# same on bare-metal, Docker, anywhere. It's what the operator actually
# wants ("did my deny fire and how many times") without the kernel-log
# delivery problems that plague iptables LOG inside containers.
#
# We use `iptables-save -c` because it emits machine-readable rule specs
# WITH counters inline ([packets:bytes] prefix on each rule), much easier
# to parse than `iptables -L -n -v -x` (which is fixed-column display
# format and needs careful regex handling).


def read_acl_stats() -> dict:
    """Snapshot per-peer ACL counter state via iptables-save -c.

    Returns a dict shape:
        {
          "peers": {
            <peer_id>: {
              "chain": "WGFLOW_PEER_<id>",
              "rules": [
                {"direction": "forward", "kind": "deny" | "allow",
                 "match": "<rule spec for display>",
                 "packets": int, "bytes": int},
                ...
              ]
            }, ...
          },
          "input_denies": {  # peer_id → list of input-chain deny rules
            <peer_id>: [
              {"match": "...", "packets": int, "bytes": int},
              ...
            ]
          },
          "snapshot_ts": float,    # time.time() — consumer computes deltas
        }

    The shape is denormalised for the UI: each peer has both its
    forward-chain rules (matched by destination CIDR) and its input-chain
    deny rules (which guard the wg server itself). The UI presents them
    grouped per peer with a small label per group.

    We don't deduplicate the LOG variants from this readout — they're
    rendered as separate rows in the UI. That's actually useful: the LOG
    counter and the DROP counter for the same deny should match exactly,
    and any divergence (LOG count > DROP count, or vice versa) would be
    a sign the rate-limit threshold was hit on the LOG. In practice the
    counts are identical for normal traffic volumes.
    """
    out = subprocess.run(
        ["iptables-save", "-c", "-t", "filter"],
        capture_output=True, text=True, check=False,
    ).stdout

    peers: Dict[int, Dict[str, Any]] = {}
    input_denies: Dict[int, List[Dict[str, Any]]] = {}

    # We need the peer-id-to-source-IP mapping to attribute INPUT chain
    # rules (which are scoped by `-s <peer_ip>` rather than by chain
    # name). Read from the DB so the mapping is authoritative.
    #
    # We also pull each ACL row's comment so we can display it next to
    # the matching iptables rule. Lookup key is (peer_id, cidr, port,
    # proto, action) — the unique constraint on peer_acls. The lookup
    # is best-effort: if a rule shows up in iptables-save that doesn't
    # match any ACL row (LOG variants, the catch-all ACCEPT, the trailing
    # DROP), it just doesn't get a comment.
    from .config import SETTINGS
    import sqlite3
    db_conn = sqlite3.connect(SETTINGS.db_path)
    db_conn.row_factory = sqlite3.Row
    src_to_peer: Dict[str, int] = {}
    comment_lookup: Dict[tuple, str] = {}
    try:
        for row in db_conn.execute(
            "SELECT id, address FROM peers WHERE enabled = 1"
        ):
            src_to_peer[_strip_mask(row["address"])] = row["id"]
        for row in db_conn.execute(
            "SELECT peer_id, cidr, port, proto, action, comment FROM peer_acls"
        ):
            if row["comment"]:
                key = (row["peer_id"], row["cidr"],
                       row["port"], row["proto"], row["action"])
                comment_lookup[key] = row["comment"]
    finally:
        db_conn.close()

    for raw in out.splitlines():
        line = raw.strip()
        # Counter-bearing rules look like:
        #   [packets:bytes] -A CHAIN -d ... -j TARGET ...
        # (the `-c` flag adds the prefix). Lines without [...] are header
        # comments or table boundaries — skip.
        if not line.startswith("["):
            continue
        try:
            counter_end = line.index("]")
        except ValueError:
            continue
        counters = line[1:counter_end]
        try:
            pkts_str, bytes_str = counters.split(":", 1)
            pkts = int(pkts_str)
            byts = int(bytes_str)
        except ValueError:
            continue
        rest = line[counter_end + 1:].strip()
        # Now `rest` is "-A CHAIN -d X -j Y ..." or similar.
        if not rest.startswith("-A "):
            continue

        # Extract chain name (first token after -A).
        parts = rest.split()
        if len(parts) < 2:
            continue
        chain = parts[1]

        # WGFLOW_PEER_<id> chain → forward direction
        if chain.startswith("WGFLOW_PEER_"):
            try:
                peer_id = int(chain.split("_")[-1])
            except ValueError:
                continue
            if peer_id not in peers:
                peers[peer_id] = {"chain": chain, "rules": []}
            target = _extract_target(parts)
            kind = (
                "log" if target == "LOG"
                else "deny" if target == "DROP"
                else "allow" if target == "ACCEPT"
                else "other"
            )
            # Look up the human comment for this rule. The comment_lookup
            # is keyed by the persisted ACL row's (cidr, port, proto, action)
            # tuple. LOG rules don't have a stored peer_acls row (LOG is a
            # synthesised rule paired with each deny), so we fall back to
            # the matching deny row's comment for them — same logical entry.
            cidr = _extract_arg(parts, "-d") or ""
            port_s = _extract_arg(parts, "--dport")
            proto_s = _extract_arg(parts, "-p") or None
            port = int(port_s) if port_s else None
            # For lookup, normalise: action is "deny" for both LOG and
            # DROP variants of a deny rule. ACCEPT → action "allow".
            lookup_action = "allow" if kind == "allow" else "deny"
            comment = comment_lookup.get(
                (peer_id, cidr, port, proto_s, lookup_action), ""
            )
            peers[peer_id]["rules"].append({
                "direction": "forward",
                "kind": kind,
                "match": _format_match_summary(rest),
                "comment": comment,
                "packets": pkts,
                "bytes": byts,
            })
            continue

        # INPUT chain — only entries we care about have `-s <peer_ip>`
        # AND target is DROP or our LOG. Other operator-added rules
        # are ignored.
        if chain == "INPUT":
            target = _extract_target(parts)
            if target not in ("DROP", "LOG"):
                continue
            # Find the source IP.
            src = _extract_arg(parts, "-s")
            if not src:
                continue
            # Source might be in CIDR form (e.g. 10.13.13.5/32); strip.
            src_ip = src.split("/")[0]
            peer_id = src_to_peer.get(src_ip)
            if peer_id is None:
                continue
            # Also confirm it's our rule by checking either DROP target
            # or LOG with our WGFLOW-DROP prefix. Defensive: an operator
            # who hand-adds an INPUT DROP for `-s 10.13.13.5` would
            # otherwise show up here.
            if target == "LOG" and "WGFLOW-DROP" not in rest:
                continue
            cidr = _extract_arg(parts, "-d") or ""
            port_s = _extract_arg(parts, "--dport")
            proto_s = _extract_arg(parts, "-p") or None
            port = int(port_s) if port_s else None
            comment = comment_lookup.get(
                (peer_id, cidr, port, proto_s, "deny"), ""
            )
            input_denies.setdefault(peer_id, []).append({
                "match": _format_match_summary(rest),
                "comment": comment,
                "kind": "log" if target == "LOG" else "deny",
                "packets": pkts,
                "bytes": byts,
            })

    return {
        "peers": peers,
        "input_denies": input_denies,
        "snapshot_ts": time.time(),
    }


def reset_acl_stats() -> None:
    """Zero per-peer chain counters. Used by the UI's reset button.

    Implementation scope: we zero the per-peer FORWARD chains
    (`WGFLOW_PEER_<id>`) which handle traffic between peers and the
    LAN. This covers the main case operators ask about ("did my deny
    fire since I made it?").

    INPUT-chain explicit-deny counters are NOT reset by this function.
    The reason: `iptables -Z INPUT` zeros every INPUT rule including
    operator-managed ones we don't own (SSH allow-lists, container
    networking, etc.) — too dangerous. Per-rule zeroing requires a
    line-number lookup that's brittle under concurrent changes.

    Operators who want truly clean INPUT counters can:
      - re-save the affected peer's ACL (apply_peer_acls flushes both
        chain and INPUT rules and reinstalls fresh, resetting counts
        as a side effect), OR
      - restart wgflow (`_replay_state_to_kernel` re-applies all ACLs
        across all peers).

    This tradeoff is documented in the UI banner so the reset button's
    scope is honest.
    """
    out = subprocess.run(
        ["iptables-save", "-t", "filter"],
        capture_output=True, text=True, check=False,
    ).stdout
    for line in out.splitlines():
        line = line.strip()
        # Chain declaration lines: `:WGFLOW_PEER_<id> POLICY [pkts:bytes]`.
        if line.startswith(":WGFLOW_PEER_"):
            chain = line.split()[0][1:]   # strip leading ':'
            subprocess.run(
                ["iptables", "-Z", chain],
                capture_output=True, check=False,
            )


def _extract_target(parts: List[str]) -> str:
    """Pull the value after -j from a tokenised iptables rule."""
    try:
        idx = parts.index("-j")
        return parts[idx + 1] if idx + 1 < len(parts) else ""
    except ValueError:
        return ""


def _extract_arg(parts: List[str], flag: str) -> str:
    """Pull the value after a given flag, or empty string."""
    try:
        idx = parts.index(flag)
        return parts[idx + 1] if idx + 1 < len(parts) else ""
    except ValueError:
        return ""


def _format_match_summary(rule: str) -> str:
    """Compact human display string for a rule.

    Pulls out destination, protocol, port — the bits the operator cares
    about — and returns something like "tcp 22 → 192.168.111.2/32" or
    "→ 10.0.0.0/8". Skips internal flags (-A, -i, -j, --log-*, etc).
    """
    parts = rule.split()
    dst = _extract_arg(parts, "-d")
    proto = _extract_arg(parts, "-p")
    port = _extract_arg(parts, "--dport")

    # Build a compact summary. The leading arrow visually emphasizes
    # "this is what gets blocked / allowed" without redundant labels.
    bits = []
    if proto:
        bits.append(proto)
    if port:
        bits.append(port)
    bits.append("→")
    bits.append(dst or "anywhere")
    return " ".join(bits)
