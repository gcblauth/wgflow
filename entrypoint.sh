#!/bin/bash
# Entry point for the wgflow container.
#
# Order of operations:
#   1. Ensure /data layout exists and server private key is present (generate
#      once, never regenerate unless the file is manually removed).
#   2. Write the minimal wg0.conf that has the [Interface] section. Peer
#      sections are appended by the python app via `wg syncconf`.
#   3. Bring up wg0 with wg-quick.
#   4. Install the baseline iptables scaffolding (per-peer chain architecture).
#   5. Hand off to uvicorn, which will replay peers + ACLs from sqlite.
set -euo pipefail

DATA_DIR="${WGFLOW_DATA_DIR:-/data}"
WG_IF="${WG_INTERFACE:-wg0}"
WG_PORT="${WG_LISTEN_PORT:-51820}"
WG_ADDR="${WG_SERVER_ADDRESS:-10.13.13.1/24}"

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

# Write wg0.conf from scratch on every boot. Peers will be added via syncconf
# by the python app after it starts. This file is the source of truth for the
# [Interface] section only; peer sections live in sqlite.
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

# Take the interface down if it is somehow already up from a prior run.
if ip link show "${WG_IF}" >/dev/null 2>&1; then
    echo "[wgflow] ${WG_IF} already exists, tearing down"
    wg-quick down "${WG_IF}" || ip link del "${WG_IF}" || true
fi

echo "[wgflow] bringing up ${WG_IF}"
wg-quick up "${WG_IF}"

# Baseline firewall. The architecture:
#   FORWARD chain: default policy stays ACCEPT (docker relies on this) but we
#       add an early jump that sends wg0-sourced packets into WGFLOW_FORWARD.
#   WGFLOW_FORWARD: dispatches to per-peer chains by source IP. If no peer
#       chain matches, the packet is dropped. This is the default-deny.
#   WGFLOW_PEER_<id>: one chain per peer, populated from the sqlite ACL table.
echo "[wgflow] installing iptables scaffolding"

# Idempotent: flush if they exist, create if they do not.
iptables -N WGFLOW_FORWARD 2>/dev/null || iptables -F WGFLOW_FORWARD

# Remove any stale jump from a previous run, then install a fresh one.
while iptables -C FORWARD -i "${WG_IF}" -j WGFLOW_FORWARD 2>/dev/null; do
    iptables -D FORWARD -i "${WG_IF}" -j WGFLOW_FORWARD
done
iptables -I FORWARD 1 -i "${WG_IF}" -j WGFLOW_FORWARD

# Allow return traffic for established flows. Without this, TCP replies from
# the whitelisted destination back to the peer would be dropped.
iptables -A WGFLOW_FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Optional: log packets that fall through every per-peer chain (i.e. weren't
# matched by any allow rule). Implemented by iptables_manager.ensure_base_chain
# when WGFLOW_IPTABLES_LOG=1 — it inserts a rate-limited LOG rule just before
# the trailing DROP. Documented here for operator awareness.
if [ "${WGFLOW_IPTABLES_LOG:-0}" = "1" ] || [ "${WGFLOW_IPTABLES_LOG:-}" = "true" ]; then
    echo "[wgflow] iptables drop logging ENABLED (WGFLOW-DROP: prefix, rate-limited)"
fi

# MASQUERADE outbound so destination servers see the container IP (they do
# not need routes back to the wg subnet). Only applied to traffic leaving the
# wg interface toward the outside world.
if ! iptables -t nat -C POSTROUTING -s "${WG_SUBNET:-10.13.13.0/24}" ! -o "${WG_IF}" -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -s "${WG_SUBNET:-10.13.13.0/24}" ! -o "${WG_IF}" -j MASQUERADE
fi

# Local DNS toggle. When disabled, the entire dnsmasq stack is skipped:
# no INPUT exception for :53, no conf rendering, no process started. Peers
# get whatever WG_PEER_DNS is set to (defaulted upstream by the app).
LOCAL_DNS_RAW="${WG_LOCAL_DNS:-1}"
case "${LOCAL_DNS_RAW,,}" in
    1|true|yes|on)  LOCAL_DNS=1 ;;
    *)              LOCAL_DNS=0 ;;
esac

if [ "${LOCAL_DNS}" = "1" ]; then
    # DNS exception: peers send DNS queries to the WG server's address (e.g.
    # 10.13.13.1:53). These packets arrive on wg0 destined for the host
    # (the container) — they are NOT forwarded, so they hit the INPUT chain,
    # not FORWARD. We need to make sure INPUT accepts them so dnsmasq can answer.
    WG_SERVER_IP="${WG_SERVER_ADDRESS%%/*}"   # strip /24 → bare IP
    for proto in udp tcp; do
        if ! iptables -C INPUT -i "${WG_IF}" -p "${proto}" --dport 53 -d "${WG_SERVER_IP}" -j ACCEPT 2>/dev/null; then
            iptables -I INPUT 1 -i "${WG_IF}" -p "${proto}" --dport 53 -d "${WG_SERVER_IP}" -j ACCEPT
        fi
    done

    # Make sure the dnsmasq log file exists and is writable. dnsmasq won't
    # create it; if it's missing, dnsmasq starts but logs nothing.
    touch /var/log/dnsmasq.log
    chmod 644 /var/log/dnsmasq.log

    # Render dnsmasq.conf from the template, substituting in the configured
    # upstream resolvers. We validate each entry is a plausible IP (or IP#port)
    # before writing — a typo here would otherwise just make dnsmasq fail
    # silently with no upstreams.
    DNSMASQ_CONF="/etc/dnsmasq.conf"
    UPSTREAMS_RAW="${WG_DNS_UPSTREAMS:-8.8.8.8,8.8.4.4,1.1.1.1}"
    SERVER_LINES=""
    IFS=',' read -ra UPS <<< "${UPSTREAMS_RAW}"
    for u in "${UPS[@]}"; do
        u="$(echo "${u}" | tr -d '[:space:]')"   # strip whitespace
        [[ -z "${u}" ]] && continue
        # Accept "1.2.3.4", "1.2.3.4#5353", and bracketed IPv6 like "[2001:db8::1]"
        # Reject anything with characters outside the allowed set.
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
    # Substitute. We use awk rather than sed so server-list contents (which
    # may contain '/') don't need escaping.
    awk -v repl="${SERVER_LINES}" '
        /^# __WGFLOW_UPSTREAMS__/ { printf "%s", repl; next }
        { print }
    ' /etc/dnsmasq.conf.template > "${DNSMASQ_CONF}"
    chmod 644 "${DNSMASQ_CONF}"
    echo "[wgflow] dnsmasq upstreams: $(grep ^server= "${DNSMASQ_CONF}" | tr '\n' ' ')"

    # Start dnsmasq in the background. It runs in the foreground (per its
    # config) so this stays alive until killed; tini will reap it on shutdown.
    echo "[wgflow] starting dnsmasq"
    dnsmasq --conf-file="${DNSMASQ_CONF}" &
    DNSMASQ_PID=$!

    # Quick sanity check — give dnsmasq a moment, then verify it actually
    # bound to the port. Failure here usually means another resolver (systemd-
    # resolved, or a stale dnsmasq from a previous run) is holding port 53.
    sleep 0.5
    if ! kill -0 "${DNSMASQ_PID}" 2>/dev/null; then
        echo "[wgflow] WARNING: dnsmasq exited immediately. Check /var/log/dnsmasq.log"
    fi
else
    echo "[wgflow] WG_LOCAL_DNS=0 — skipping dnsmasq; peers will use WG_PEER_DNS"
fi

echo "[wgflow] handoff to uvicorn"
BIND="${WGFLOW_BIND:-0.0.0.0:8080}"
HOST="${BIND%:*}"
PORT="${BIND##*:}"
cd /srv
exec uvicorn app.main:app --host "${HOST}" --port "${PORT}" --no-access-log
