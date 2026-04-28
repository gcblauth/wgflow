#!/bin/bash

# --- Helper Function for Input ---
prompt_user() {
    local var_name=$1
    local prompt_text=$2
    local default_val=$3
    read -p "$prompt_text [$default_val]: " input
    eval "$var_name=\"${input:-$default_val}\""
}

echo "==============================================="
echo "     WGFLOW v3.1 INTERACTIVE CONFIGURATION"
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

# 3. Access Control & Admin
prompt_user "WG_DEFAULT_ACL" "Default ACL for new peers" "10.0.0.0/8"
prompt_user "PANEL_PASSWORD" "Admin Password (leave empty for proxy-auth)" ""
prompt_user "WGFLOW_IPTABLES_LOG" "Enable drop logging? (1=Yes, 0=No)" "0"

# 4. Host Log Path
echo ""
echo "Select host kernel log path (needed for UI logs):"
echo "1) /var/log/kern.log (Ubuntu/Debian)"
echo "2) /var/log/messages (Alpine)"
echo "3) None/Other"
read -p "Selection [1]: " log_choice
case ${log_choice:-1} in
    1) KERNEL_LOG="/var/log/kern.log" ;;
    2) KERNEL_LOG="/var/log/messages" ;;
    *) KERNEL_LOG="" ;;
esac

# Create .env file
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
PANEL_PASSWORD=$PANEL_PASSWORD
WGFLOW_IPTABLES_LOG=$WGFLOW_IPTABLES_LOG
KERNEL_LOG_PATH=$KERNEL_LOG
EOF

echo "-------------------------------------------"
echo "SUCCESS: .env file generated."
echo "You can now run: docker-compose up -d --build"
echo "-------------------------------------------"
