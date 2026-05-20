#!/usr/bin/env bash
# wgflow — host-tune.sh
#
# HOST-side network performance tuning for WireGuard. This script does
# NOT touch the wgflow container — it tunes the Linux HOST the container
# runs on. Run it once on the host; the changes persist across reboots.
#
# It applies up to three independent optimizations:
#
#   1. sysctl   — larger socket buffers + netdev backlog for high-rate
#                 UDP (WireGuard is UDP-heavy). Written to
#                 /etc/sysctl.d/99-wireguard.conf — systemd re-applies
#                 it every boot natively.
#
#   2. governor — pins the CPU frequency scaling governor to
#                 'performance' (max clock, no ramp-up latency).
#                 Installed as a systemd unit so it survives reboot.
#                 OPT-IN: raises power draw and heat. Off unless you
#                 pass --governor.
#
#   3. offload  — enables NIC hardware offloads (tso/gso/gro and, on
#                 recent kernels, rx-udp-gro-forwarding which notably
#                 helps WireGuard throughput). ethtool -K is volatile,
#                 so this is installed as a systemd unit that re-runs
#                 it after the network comes up.
#
# Why a separate script and not part of setup-one-time.sh: these write
# files under /etc and install systemd units — they modify the HOST,
# not wgflow's own directory. That's more invasive than anything the
# normal installer does, so it's deliberately explicit, opt-in, and
# fully reversible (--revert).
#
# Usage:
#   sudo ./host-tune.sh                  # sysctl + offload (NOT governor)
#   sudo ./host-tune.sh --governor       # also pin CPU governor
#   sudo ./host-tune.sh --dry-run        # show what it would do, change nothing
#   sudo ./host-tune.sh --nic eth0       # override NIC autodetection
#   sudo ./host-tune.sh --no-sysctl      # skip the sysctl part
#   sudo ./host-tune.sh --no-offload     # skip the NIC offload part
#   sudo ./host-tune.sh --rmem 33554432  # custom socket buffer cap (bytes)
#   sudo ./host-tune.sh --revert         # remove everything this script installed
#
# Re-runnable. Each apply is idempotent.

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SYSCTL_FILE="/etc/sysctl.d/99-wireguard.conf"
GOVERNOR_UNIT="/etc/systemd/system/wgflow-cpu-governor.service"
OFFLOAD_UNIT="/etc/systemd/system/wgflow-nic-offload.service"

# Default socket buffer cap: 32 MiB. Generous for WireGuard without
# being wasteful on low-RAM hosts (a Raspberry Pi shouldn't reserve
# 128 MiB of buffer headroom). Override with --rmem / --wmem.
DEFAULT_BUF=33554432           # 32 MiB
DEFAULT_BACKLOG=250000

# NIC hardware offloads to try. Each is applied independently — if the
# kernel/NIC doesn't support one, that single feature is skipped and
# the rest still apply. rx-udp-gro-forwarding is the one that helps
# WireGuard most, and the one most likely to be missing (needs a
# recent kernel).
OFFLOAD_FEATURES=(tx sg tso gso gro rx-udp-gro-forwarding)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
    C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'; C_CYAN=$'\033[36m'
else
    C_RESET= C_BOLD= C_DIM= C_GREEN= C_YELLOW= C_RED= C_CYAN=
fi

say()  { printf "${C_DIM}[host-tune]${C_RESET} %s\n" "$*"; }
ok()   { printf "${C_DIM}[host-tune]${C_RESET} ${C_GREEN}✓${C_RESET} %s\n" "$*"; }
warn() { printf "${C_DIM}[host-tune]${C_RESET} ${C_YELLOW}!${C_RESET} %s\n" "$*" >&2; }
fail() { printf "${C_DIM}[host-tune]${C_RESET} ${C_RED}✗${C_RESET} %s\n" "$*" >&2; exit 1; }
hdr()  { printf "\n${C_BOLD}== %s ==${C_RESET}\n" "$*"; }

run() {
    if [[ $DRY_RUN -eq 1 ]]; then
        printf "${C_CYAN}[dry-run]${C_RESET} %s\n" "$*"
    else
        "$@"
    fi
}

# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------

DRY_RUN=0
DO_SYSCTL=1
DO_OFFLOAD=1
DO_GOVERNOR=0          # opt-in
REVERT=0
NIC_OVERRIDE=""
BUF="$DEFAULT_BUF"
BUF_SET=0
BACKLOG="$DEFAULT_BACKLOG"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)     DRY_RUN=1 ;;
        --governor)    DO_GOVERNOR=1 ;;
        --no-sysctl)   DO_SYSCTL=0 ;;
        --no-offload)  DO_OFFLOAD=0 ;;
        --revert)      REVERT=1 ;;
        --nic)         NIC_OVERRIDE="${2:?--nic needs an interface name}"; shift ;;
        --rmem|--wmem) BUF="${2:?$1 needs a byte value}"; BUF_SET=1; shift ;;
        --backlog)     BACKLOG="${2:?--backlog needs a value}"; shift ;;
        -h|--help)     sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) fail "unknown flag: $1 (try --help)" ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

hdr "Preflight"

[[ $EUID -eq 0 ]] || fail "must run as root (sudo $0 ...)"

# systemd is required — the governor and offload persistence both use
# systemd units.
command -v systemctl >/dev/null 2>&1 || fail "systemd not found — this script needs systemd for persistence"
ok "running as root, systemd present"

# ethtool is needed for the offload part only.
HAVE_ETHTOOL=1
if ! command -v ethtool >/dev/null 2>&1; then
    HAVE_ETHTOOL=0
    if [[ $DO_OFFLOAD -eq 1 && $REVERT -eq 0 ]]; then
        warn "ethtool not installed — the NIC offload step needs it."
        warn "install it:  apt install ethtool   (Debian/Ubuntu)"
        warn "             dnf install ethtool   (RHEL/Fedora)"
        warn "continuing without the offload step; re-run after installing."
        DO_OFFLOAD=0
    fi
fi

# ---------------------------------------------------------------------------
# Revert mode — undo everything, exit
# ---------------------------------------------------------------------------

if [[ $REVERT -eq 1 ]]; then
    hdr "Revert"
    # sysctl file
    if [[ -f "$SYSCTL_FILE" ]]; then
        run rm -f "$SYSCTL_FILE"
        ok "removed $SYSCTL_FILE"
        # Note: kernel keeps the runtime values until next boot. A
        # reboot (or manual sysctl reset) restores defaults.
        say "  (current runtime values stay until reboot)"
    else
        say "no sysctl file to remove"
    fi
    # units
    for unit in "$GOVERNOR_UNIT" "$OFFLOAD_UNIT"; do
        name="$(basename "$unit")"
        if [[ -f "$unit" ]]; then
            run systemctl disable --now "$name" 2>/dev/null || true
            run rm -f "$unit"
            ok "removed $name"
        fi
    done
    run systemctl daemon-reload
    hdr "Reverted"
    say "sysctl runtime values and CPU governor revert fully on next reboot."
    exit 0
fi

# ---------------------------------------------------------------------------
# NIC detection
# ---------------------------------------------------------------------------

detect_nic() {
    # Ask the kernel which interface it would use to reach the public
    # internet. The `dev X` field in `ip route get` output is the
    # default-route interface.
    local nic
    nic=$(ip route get 8.8.8.8 2>/dev/null | grep -oP '(?<=dev )\S+' | head -1)
    printf '%s' "${nic:-}"
}

NIC=""
if [[ $DO_OFFLOAD -eq 1 ]]; then
    hdr "NIC detection"
    if [[ -n "$NIC_OVERRIDE" ]]; then
        NIC="$NIC_OVERRIDE"
        say "using NIC from --nic: ${C_BOLD}${NIC}${C_RESET}"
    else
        NIC="$(detect_nic)"
        [[ -n "$NIC" ]] || fail "could not autodetect the NIC — pass it explicitly with --nic <name>"
        say "autodetected default-route NIC: ${C_BOLD}${NIC}${C_RESET}"
    fi

    # Sanity: does the interface exist?
    if ! ip link show "$NIC" >/dev/null 2>&1; then
        fail "interface '$NIC' does not exist on this host"
    fi

    # Warn on bridge / bond — ethtool offloads set on a bridge/bond
    # do not always propagate to the underlying physical NICs.
    if [[ -d "/sys/class/net/${NIC}/bridge" ]]; then
        warn "'$NIC' is a BRIDGE — offloads may not reach the physical"
        warn "NICs underneath. Consider re-running with --nic <physical-nic>."
    fi
    if [[ -d "/sys/class/net/${NIC}/bonding" ]]; then
        warn "'$NIC' is a BOND — offloads may need to be set on the"
        warn "slave interfaces instead. Verify after applying."
    fi
    # Warn if it looks virtual (veth/docker) — almost certainly wrong.
    case "$NIC" in
        veth*|docker*|br-*|wg*)
            warn "'$NIC' looks like a virtual interface — that's probably"
            warn "not the physical NIC carrying your traffic. Double-check,"
            warn "or pass the right one with --nic."
            ;;
    esac
    ok "NIC to tune: $NIC"
fi

# ---------------------------------------------------------------------------
# Confirmation
# ---------------------------------------------------------------------------

hdr "Plan"
say "This will apply, persistently across reboots:"
[[ $DO_SYSCTL -eq 1 ]]   && say "  • sysctl   → $SYSCTL_FILE (buffers ${BUF}B, backlog ${BACKLOG})"
[[ $DO_OFFLOAD -eq 1 ]]  && say "  • offload  → ${OFFLOAD_FEATURES[*]} on ${NIC}"
[[ $DO_GOVERNOR -eq 1 ]] && say "  • governor → CPU pinned to 'performance'"
[[ $DO_SYSCTL -eq 0 && $DO_OFFLOAD -eq 0 && $DO_GOVERNOR -eq 0 ]] && fail "nothing to do (all parts disabled)"

if [[ $DO_GOVERNOR -eq 1 ]]; then
    echo
    warn "CPU governor 'performance' keeps every core at max frequency"
    warn "at all times. This increases power draw and heat — on a"
    warn "Raspberry Pi or fanless mini-PC, make sure cooling is adequate."
fi

if [[ $DRY_RUN -eq 0 && -t 0 ]]; then
    echo
    read -r -p "proceed? [y/N]: " reply
    case "$reply" in
        y|Y|yes|YES) ;;
        *) say "aborted by user"; exit 0 ;;
    esac
fi

# ---------------------------------------------------------------------------
# 1. sysctl
# ---------------------------------------------------------------------------

if [[ $DO_SYSCTL -eq 1 ]]; then
    hdr "sysctl"
    if [[ $DRY_RUN -eq 1 ]]; then
        printf "${C_CYAN}[dry-run]${C_RESET} write %s\n" "$SYSCTL_FILE"
    else
        cat > "$SYSCTL_FILE" <<EOF
# wgflow host tuning — WireGuard / high-rate UDP
# Generated by host-tune.sh on $(date -Is)
#
# Larger socket buffer ceilings + a deeper netdev backlog so the host
# can absorb bursts of UDP without dropping. These are HOST-GLOBAL
# settings (net.core.*) — they cannot be set from inside a container.
#
# Remove this file (or run host-tune.sh --revert) to undo.

# Max socket receive/send buffer the kernel will grant (bytes).
# This is a ceiling — actual buffers are sized by autotuning or by
# the app via SO_RCVBUF/SO_SNDBUF.
net.core.rmem_max = ${BUF}
net.core.wmem_max = ${BUF}

# How many packets the per-CPU input queue holds before drops, when
# the NIC delivers faster than the stack drains. Higher = more burst
# tolerance at the cost of a little latency/memory.
net.core.netdev_max_backlog = ${BACKLOG}
EOF
        # Apply now (also re-applied every boot by systemd-sysctl).
        sysctl --system >/dev/null 2>&1 || warn "sysctl --system reported an issue; values may apply on next boot"
        ok "wrote $SYSCTL_FILE and applied"
        # Echo back the live values as proof.
        for k in net.core.rmem_max net.core.wmem_max net.core.netdev_max_backlog; do
            v=$(sysctl -n "$k" 2>/dev/null || echo "?")
            say "  $k = $v"
        done
    fi
fi

# ---------------------------------------------------------------------------
# 2. CPU governor (opt-in)
# ---------------------------------------------------------------------------

if [[ $DO_GOVERNOR -eq 1 ]]; then
    hdr "CPU governor"
    # Check the host actually has cpufreq governors. VMs and some
    # cloud instances don't expose them.
    if ! ls /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor >/dev/null 2>&1; then
        warn "no cpufreq governor on this host (common in VMs / cloud)"
        warn "skipping the governor step"
    else
        avail=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors 2>/dev/null || echo "")
        if [[ "$avail" != *performance* ]]; then
            warn "'performance' governor not available (have: $avail)"
            warn "skipping the governor step"
        elif [[ $DRY_RUN -eq 1 ]]; then
            printf "${C_CYAN}[dry-run]${C_RESET} install %s\n" "$GOVERNOR_UNIT"
        else
            cat > "$GOVERNOR_UNIT" <<'EOF'
[Unit]
Description=wgflow — pin CPU scaling governor to performance
Documentation=https://github.com/gcblauth/wgflow
After=multi-user.target

[Service]
Type=oneshot
# Write 'performance' to every CPU's governor. The shell glob runs
# inside sh -c so it expands at execution time across all cores.
ExecStart=/bin/sh -c 'for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > "$g"; done'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
            systemctl enable --now wgflow-cpu-governor.service >/dev/null 2>&1 \
                || warn "could not enable governor unit — check 'systemctl status wgflow-cpu-governor'"
            gov=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "?")
            ok "installed wgflow-cpu-governor.service · cpu0 governor now: $gov"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# 3. NIC offload
# ---------------------------------------------------------------------------

if [[ $DO_OFFLOAD -eq 1 ]]; then
    hdr "NIC offload"
    if [[ $DRY_RUN -eq 1 ]]; then
        printf "${C_CYAN}[dry-run]${C_RESET} install %s for NIC %s\n" "$OFFLOAD_UNIT" "$NIC"
        printf "${C_CYAN}[dry-run]${C_RESET} features: %s\n" "${OFFLOAD_FEATURES[*]}"
    else
        # Resolve ethtool's real path — it lives in /sbin, /usr/sbin,
        # or /usr/bin depending on distro. systemd units need an
        # absolute path in ExecStart.
        ETHTOOL_BIN="$(command -v ethtool)"
        [[ -n "$ETHTOOL_BIN" ]] || fail "ethtool vanished between preflight and now"

        # Build the ExecStart lines. One `ethtool -K` per feature, each
        # with a leading '-' so an unsupported feature on an old kernel
        # (rx-udp-gro-forwarding especially) doesn't fail the unit and
        # block the rest.
        exec_lines=""
        for feat in "${OFFLOAD_FEATURES[@]}"; do
            exec_lines+="ExecStart=-${ETHTOOL_BIN} -K ${NIC} ${feat} on"$'\n'
        done

        cat > "$OFFLOAD_UNIT" <<EOF
[Unit]
Description=wgflow — enable NIC hardware offloads on ${NIC}
Documentation=https://github.com/gcblauth/wgflow
# Run after the network is up so the interface exists. We don't bind
# to a specific network unit name (varies: NetworkManager / networkd /
# ifupdown) — multi-user.target plus a feature-by-feature best-effort
# apply is portable enough.
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
# Each feature applied separately. The leading '-' on ExecStart makes
# systemd ignore a non-zero exit, so an unsupported offload (e.g.
# rx-udp-gro-forwarding on an older kernel) is skipped, not fatal.
${exec_lines}RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable --now wgflow-nic-offload.service >/dev/null 2>&1 \
            || warn "could not enable offload unit — check 'systemctl status wgflow-nic-offload'"
        ok "installed wgflow-nic-offload.service for $NIC"

        # Report what actually stuck. ethtool -k (lowercase) shows
        # current feature state.
        say "current offload state on $NIC:"
        for feat in "${OFFLOAD_FEATURES[@]}"; do
            # ethtool feature names in -k output sometimes differ
            # slightly; grep loosely.
            state=$(ethtool -k "$NIC" 2>/dev/null | grep -i "${feat}:" | head -1 | awk '{print $2}')
            printf "         %-26s %s\n" "$feat" "${state:-not reported}"
        done
        say "(features showing 'fixed'/'not reported' aren't supported by this NIC/kernel — that's fine)"
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

hdr "Done"
if [[ $DRY_RUN -eq 1 ]]; then
    say "dry-run only — nothing was changed."
    say "re-run without --dry-run to apply."
    exit 0
fi
say "Host tuning applied. Persists across reboots."
say ""
say "Verify after a reboot:"
[[ $DO_SYSCTL -eq 1 ]]   && say "  sysctl net.core.rmem_max net.core.wmem_max net.core.netdev_max_backlog"
[[ $DO_GOVERNOR -eq 1 ]] && say "  cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
[[ $DO_OFFLOAD -eq 1 ]]  && say "  ethtool -k ${NIC} | grep -E 'udp-gro|generic-receive|tcp-segmentation'"
say ""
say "Undo everything:"
say "  sudo $0 --revert"
