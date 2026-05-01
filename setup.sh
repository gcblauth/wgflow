#!/bin/bash
# Interactive .env generator for wgflow.
# Run once before `docker compose up`. Re-run to change settings.

# --- Helpers ---
prompt_user() {
    local var_name=$1
    local prompt_text=$2
    local default_val=$3
    read -p "$prompt_text [$default_val]: " input
    eval "$var_name=\"${input:-$default_val}\""
}

# Silent password prompt — does NOT echo to terminal. Empty value is valid
# (operator may run behind a reverse-proxy auth layer).
prompt_password_silent() {
    local var_name=$1
    local prompt_text=$2
    read -rsp "$prompt_text: " input
    echo
    eval "$var_name=\"$input\""
}

echo "==============================================="
echo "     WGFLOW v3.2 INTERACTIVE CONFIGURATION"
echo "==============================================="

# 1. Network & WireGuard Core
prompt_user "WG_INTERFACE" "WireGuard interface name" "wg0"
prompt_user "WG_LISTEN_PORT" "WireGuard UDP port" "51820"
prompt_user "WG_SUBNET" "Internal VPN Subnet" "10.13.13.0/24"
prompt_user "WG_SERVER_ADDRESS" "Internal Server IP" "10.13.13.1/24"
prompt_user "WG_ENDPOINT" "Public Endpoint (DNS:Port or IP:Port)" "vpn.example.com:51820"

# 2. DNS Configuration
prompt_user "WG_LOCAL_DNS" "Run local dnsmasq? (1=Yes, 0=No)" "1"
if [ "$WG_LOCAL_DNS" == "1" ]; then
    prompt_user "WG_DNS_UPSTREAMS" "Upstream DNS (comma-separated)" "8.8.8.8,8.8.4.4,1.1.1.1"
    prompt_user "WG_PEER_DNS" "DNS IP pushed to peers (usually server IP)" "$WG_SERVER_ADDRESS"
    # Clean up CIDR suffix if user kept it in peer DNS
    WG_PEER_DNS=$(echo $WG_PEER_DNS | cut -d'/' -f1)
else
    prompt_user "WG_PEER_DNS" "External DNS for peers" "1.1.1.1"
fi

# 3. Bind addresses
echo ""
echo "--- Network bindings ---"
echo "WGFLOW_BIND is what the wgflow process listens on INSIDE the container."
echo "  Keep this at 0.0.0.0:8080 — the container has its own network stack."
prompt_user "WGFLOW_BIND" "Container-side bind" "0.0.0.0:8080"
echo ""
echo "HOSTBIND_WG_PANEL is what the HOST publishes the panel on. Defaults to"
echo "loopback only — the panel can read peer private keys and rewrite iptables,"
echo "so do NOT bind it to 0.0.0.0 unless you have a reverse proxy with auth in"
echo "front (and you've read README → 'Exposing the admin UI safely')."
prompt_user "HOSTBIND_WG_PANEL" "Host-side bind" "127.0.0.1:8080"

# 4. Authentication
echo ""
echo "--- Admin password ---"
echo "Leave empty to disable in-app auth (useful when an upstream proxy handles"
echo "authentication). When set, can be plaintext (will be hashed at startup)"
echo "or a pre-computed bcrypt hash starting with \$2a\$ / \$2b\$ / \$2y\$."
prompt_password_silent "PANEL_PASSWORD" "Admin Password (input hidden, empty = disable)"

# 5. ACL defaults
echo ""
echo "========================================================================="
echo "Note on ACLs — these are defaults applied to new peers; per-peer overrides"
echo "are available in the UI at create time and via the ACL editor afterwards."
echo "Syntax: comma-separated entries of CIDR or ip:port/proto. Prefix with '!'"
echo "for DENY (any deny entry switches the peer to full-tunnel mode and a"
echo "catch-all ACCEPT is appended to the chain — you do NOT need to add"
echo "0.0.0.0/0 yourself). Examples:"
echo "  10.10.10.50:3389/tcp,10.10.10.1:22/tcp"
echo "      → allow only RDP to .50 and SSH to .1; everything else dropped"
echo "  192.168.1.0/24,192.168.2.50/32"
echo "      → allow whole /24 plus one extra host"
echo "  !${WG_SERVER_ADDRESS%/*}:${WGFLOW_BIND#*:}/tcp"
echo "      → full-tunnel, but DENY this peer access to the wgflow admin panel"
echo "========================================================================="
prompt_user "WG_DEFAULT_ACL" "Default ACL for new peers" "10.0.0.0/8"
prompt_user "WGFLOW_IPTABLES_LOG" "Enable drop logging? (1=Yes, 0=No)" "0"

# 6. Telemetry
echo ""
echo "--- Anonymous telemetry ---"
echo "wgflow can send anonymous usage stats every 30 minutes:"
echo "  - per-instance UUID (generated on first DB init)"
echo "  - peer count"
echo "  - cumulative rx/tx bytes"
echo "  - process uptime + wgflow version"
echo "Aggregated stats are visible on the project's GitHub page. The README's"
echo "Telemetry section documents exactly what's collected and how the HMAC"
echo "signing works."
prompt_user "WGFLOW_TELEMETRY_ENABLED" "Enable telemetry? (1=Yes, 0=No)" "1"

# 7. Host Log Path
echo ""
echo "Select host kernel log path (needed for the wireguard / iptables UI tabs):"
echo "1) /var/log/kern.log  (Ubuntu/Debian with rsyslog)"
echo "2) /var/log/messages  (Alpine)"
echo "3) None/Other         (those log tabs will show 'unavailable')"
read -p "Selection [1]: " log_choice
case ${log_choice:-1} in
    1) KERNEL_LOG="/var/log/kern.log" ;;
    2) KERNEL_LOG="/var/log/messages" ;;
    *) KERNEL_LOG="" ;;
esac

# Create .env file. We deliberately don't write WGFLOW_TELEMETRY_SECRET — leave
# it empty so the per-instance derived secret is used. Operators running their
# own collector can add it manually later.
cat <<EOF > .env
WG_INTERFACE=$WG_INTERFACE
WG_LISTEN_PORT=$WG_LISTEN_PORT
WG_SUBNET=$WG_SUBNET
WG_SERVER_ADDRESS=$WG_SERVER_ADDRESS
WG_ENDPOINT=$WG_ENDPOINT
WG_LOCAL_DNS=$WG_LOCAL_DNS
WG_DNS_UPSTREAMS=$WG_DNS_UPSTREAMS
WG_PEER_DNS=$WG_PEER_DNS
WG_DEFAULT_ACL=$WG_DEFAULT_ACL
HOSTBIND_WG_PANEL=$HOSTBIND_WG_PANEL
PANEL_PASSWORD=$PANEL_PASSWORD
WGFLOW_BIND=$WGFLOW_BIND
WGFLOW_IPTABLES_LOG=$WGFLOW_IPTABLES_LOG
KERNEL_LOG_PATH=$KERNEL_LOG
WGFLOW_TELEMETRY_ENABLED=$WGFLOW_TELEMETRY_ENABLED
EOF

# Tighten permissions — .env contains the admin password.
chmod 600 .env

echo "-------------------------------------------"
echo "SUCCESS: .env file generated (chmod 600)."
echo "Run: docker compose up -d --build"
echo "-------------------------------------------"
