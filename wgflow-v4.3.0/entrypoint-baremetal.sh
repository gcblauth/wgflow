#!/bin/bash
# wgflow bare-metal entrypoint.
#
# STATUS: EXPERIMENTAL. Docker is the recommended deployment path and is what
# we test against each release. Bare-metal still works (it's used in production
# on at least one instance), but new features may have docker-only paths and
# bare-metal-specific bugs are addressed only on request. If you want a
# reliable single-host VPN gateway, use the docker-compose.yml flow instead.
#
# This is what `entrypoint.sh` does in the container, minus the bits that
# only make sense in Docker (no /srv, no WGFLOW_BIND parsing — uvicorn is
# launched separately by the systemd unit, not from this script).
#
# Runs as root via the systemd unit's ExecStartPre. Idempotent: every
# wgflow restart re-renders wg0.conf from the stored key, brings the
# interface back up, replays iptables scaffolding, and (re)starts
# dnsmasq if WG_LOCAL_DNS=1.
#
# Order of operations matches the container's entrypoint so the running
# behavior is identical between deployments.

set -euo pipefail

# Source the operator's env file so this script behaves identically
# whether invoked manually or by systemd. systemd's EnvironmentFile sets
# these for the uvicorn process; we read them ourselves so the bring-up
# sequence sees the same values.
if [[ -f /etc/wgflow/.env ]]; then
    set -a
    # shellcheck disable=SC1091
    source /etc/wgflow/.env
    set +a
fi

DATA_DIR="${WGFLOW_DATA_DIR:-/var/lib/wgflow/data}"
WG_IF="${WG_INTERFACE:-wg0}"
WG_PORT="${WG_LISTEN_PORT:-51820}"
WG_ADDR="${WG_SERVER_ADDRESS:-10.13.13.1/24}"
WG_SUBNET="${WG_SUBNET:-10.13.13.0/24}"

mkdir -p "${DATA_DIR}/keys" "${DATA_DIR}/peers"
chmod 700 "${DATA_DIR}/keys"

PRIV="${DATA_DIR}/keys/server_private.key"
PUB="${DATA_DIR}/keys/server_public.key"

if [[ ! -f "${PRIV}" ]]; then
    echo "[wgflow] no server key found, generating new keypair"
    umask 077
    wg genkey | tee "${PRIV}" | wg pubkey > "${PUB}"
fi
chmod 600 "${PRIV}"
chmod 644 "${PUB}"

# Render wg0.conf from the stored key on every boot. Peer sections are
# managed by the python app via `wg syncconf`, so we only write the
# [Interface] section here.
CONF="/etc/wireguard/${WG_IF}.conf"
mkdir -p /etc/wireguard
{
    echo "[Interface]"
    echo "Address = ${WG_ADDR}"
    echo "ListenPort = ${WG_PORT}"
    echo "PrivateKey = $(cat "${PRIV}")"
    echo "# Peer sections are managed by wgflow via 'wg syncconf'."
} > "${CONF}"
chmod 600 "${CONF}"

# Take the interface down if it's somehow already up. Could happen if the
# previous wgflow exited uncleanly, or if someone ran wg-quick manually.
if ip link show "${WG_IF}" >/dev/null 2>&1; then
    echo "[wgflow] ${WG_IF} already exists, tearing down"
    wg-quick down "${WG_IF}" 2>/dev/null || ip link del "${WG_IF}" || true
fi

echo "[wgflow] bringing up ${WG_IF}"
wg-quick up "${WG_IF}"

# Baseline firewall scaffolding. Same architecture as the container:
#   FORWARD jumps wg0-sourced packets into WGFLOW_FORWARD
#   WGFLOW_FORWARD dispatches to per-peer chains; default-deny if no match
#   WGFLOW_PEER_<id> chains are populated by the app from sqlite ACLs
echo "[wgflow] installing iptables scaffolding"

iptables -N WGFLOW_FORWARD 2>/dev/null || iptables -F WGFLOW_FORWARD

# Remove any stale jump from a previous run, then install a fresh one.
while iptables -C FORWARD -i "${WG_IF}" -j WGFLOW_FORWARD 2>/dev/null; do
    iptables -D FORWARD -i "${WG_IF}" -j WGFLOW_FORWARD
done
iptables -I FORWARD 1 -i "${WG_IF}" -j WGFLOW_FORWARD

iptables -A WGFLOW_FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Optional: log packets that fall through every per-peer chain (i.e. weren't
# matched by any allow rule). Implemented by iptables_manager.ensure_base_chain
# when WGFLOW_IPTABLES_LOG=1 — it inserts a rate-limited LOG rule just before
# the trailing DROP. The actual rule installation happens in the Python app
# at startup via ensure_base_chain(), reading the same env var. We just print
# a confirmation here so the operator sees in journalctl that the toggle
# was picked up.
if [ "${WGFLOW_IPTABLES_LOG:-0}" = "1" ] || [ "${WGFLOW_IPTABLES_LOG:-}" = "true" ]; then
    echo "[wgflow] iptables drop logging ENABLED (WGFLOW-DROP: prefix, rate-limited)"
fi

# MASQUERADE outbound. Without this, peers can't reach the internet —
# return packets would be addressed to 10.13.13.x and have nowhere to go.
if ! iptables -t nat -C POSTROUTING -s "${WG_SUBNET}" ! -o "${WG_IF}" -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -s "${WG_SUBNET}" ! -o "${WG_IF}" -j MASQUERADE
fi

# IP forwarding. The Docker container has this set in compose; on the
# host it has to be set in sysctl.conf. Set it at runtime too in case
# something flipped it back.
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# DNS toggle. Mirrors the container behavior.
LOCAL_DNS_RAW="${WG_LOCAL_DNS:-1}"
case "${LOCAL_DNS_RAW,,}" in
    1|true|yes|on)  LOCAL_DNS=1 ;;
    *)              LOCAL_DNS=0 ;;
esac

if [ "${LOCAL_DNS}" = "1" ]; then
    WG_SERVER_IP="${WG_SERVER_ADDRESS%%/*}"
    for proto in udp tcp; do
        if ! iptables -C INPUT -i "${WG_IF}" -p "${proto}" --dport 53 -d "${WG_SERVER_IP}" -j ACCEPT 2>/dev/null; then
            iptables -I INPUT 1 -i "${WG_IF}" -p "${proto}" --dport 53 -d "${WG_SERVER_IP}" -j ACCEPT
        fi
    done

    # Render dnsmasq.conf. Template lives at /opt/wgflow/dnsmasq.conf.template
    # (copied there by the install script).
    touch /var/log/dnsmasq.log
    chmod 644 /var/log/dnsmasq.log

    DNSMASQ_CONF="/etc/dnsmasq.conf"
    UPSTREAMS_RAW="${WG_DNS_UPSTREAMS:-8.8.8.8,8.8.4.4,1.1.1.1}"
    SERVER_LINES=""
    IFS=',' read -ra UPS <<< "${UPSTREAMS_RAW}"
    for u in "${UPS[@]}"; do
        u="$(echo "${u}" | tr -d '[:space:]')"
        [[ -z "${u}" ]] && continue
        if [[ ! "${u}" =~ ^(\[[0-9a-fA-F:]+\]|[0-9.]+)(#[0-9]+)?$ ]]; then
            echo "[wgflow] WARNING: skipping invalid WG_DNS_UPSTREAMS entry: ${u}"
            continue
        fi
        SERVER_LINES+="server=${u}"$'\n'
    done
    if [[ -z "${SERVER_LINES}" ]]; then
        echo "[wgflow] WARNING: no valid upstreams in WG_DNS_UPSTREAMS, falling back to 8.8.8.8"
        SERVER_LINES="server=8.8.8.8"$'\n'
    fi
    awk -v repl="${SERVER_LINES}" '
        /^# __WGFLOW_UPSTREAMS__/ { printf "%s", repl; next }
        { print }
    ' /opt/wgflow/dnsmasq.conf.template > "${DNSMASQ_CONF}"
    chmod 644 "${DNSMASQ_CONF}"

    # Stop any stale dnsmasq from a previous boot. We use --conf-file so
    # multiple dnsmasq instances are technically possible, but only one
    # can hold port 53 on the wg interface — kill any prior one cleanly.
    pkill -f "dnsmasq --conf-file=${DNSMASQ_CONF}" 2>/dev/null || true
    sleep 0.2

    echo "[wgflow] starting dnsmasq"
    dnsmasq --conf-file="${DNSMASQ_CONF}"
    # No '&' and no foreground hold here: the install script renders a
    # copy of dnsmasq.conf.template into /opt/wgflow/ with the
    # `keep-in-foreground` line stripped, so dnsmasq daemonizes itself
    # and this entrypoint exits cleanly. systemd's ExecStartPre needs
    # this — if dnsmasq stayed foreground, ExecStartPre would block and
    # the uvicorn ExecStart would never fire.
else
    echo "[wgflow] WG_LOCAL_DNS=0 — skipping dnsmasq"
fi

echo "[wgflow] entrypoint complete"
