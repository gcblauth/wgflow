#!/bin/bash
# wgflow bare-metal install script (Ubuntu).
#
# STATUS: EXPERIMENTAL. Docker is the recommended deployment path. This
# install script still works on Ubuntu 22.04+ and is used in at least one
# production instance, but it's not actively tested against each release;
# new features may have Docker-only paths. If you want a tested single-host
# VPN gateway, prefer:
#     docker compose up -d
# from the wgflow source. Use this script if you specifically want to avoid
# Docker and accept the maintenance tradeoff.
#
# Run as root, once. Sets up wgflow as a systemd service on the host
# without Docker. Assumes you've already decided to stop your existing
# wireguard service and let wgflow take over wg0.
#
# Layout this script creates:
#   /opt/wgflow/                  code (app/, venv/, dnsmasq.conf.template, entrypoint)
#   /var/lib/wgflow/data/         sqlite DB, server keypair, generated peer configs
#   /etc/wgflow/.env              environment file (edit after install)
#   /etc/systemd/system/wgflow.service
#
# Idempotent in the sense that re-running it won't destroy existing data
# (the DB and keypair under /var/lib/wgflow/ are preserved), but it WILL
# overwrite /opt/wgflow/* with the current source tree, which is what
# you usually want when re-running after a code update.
#
# What it touches outside its own dirs:
#   - apt installs: wireguard-tools, iptables, dnsmasq, python3-venv, python3-pip
#   - stops + disables wg-quick@wg0.service
#   - rewrites /etc/systemd/resolved.conf to set DNSStubListener=no (backed up first)
#   - sets net.ipv4.ip_forward=1 in /etc/sysctl.d/99-wgflow.conf
#   - installs /etc/systemd/system/wgflow.service
#
# Recovery: each modified system file is backed up to <path>.pre-wgflow.bak
# the first time we touch it. To revert, restore those, run
# `systemctl disable --now wgflow`, and remove /opt/wgflow + /etc/wgflow.
# /var/lib/wgflow contains your data so we leave it alone.

set -euo pipefail

# ---------------------------------------------------------------------------
# Pretty output
# ---------------------------------------------------------------------------
c_dim="\033[2m"
c_ok="\033[1;32m"
c_warn="\033[1;33m"
c_err="\033[1;31m"
c_off="\033[0m"

step() { printf "${c_ok}==>${c_off} %s\n" "$*"; }
warn() { printf "${c_warn}!!${c_off} %s\n"  "$*" >&2; }
die()  { printf "${c_err}xx${c_off} %s\n"   "$*" >&2; exit 1; }
note() { printf "${c_dim}   %s${c_off}\n"   "$*"; }

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
[[ $EUID -eq 0 ]] || die "must run as root (try: sudo bash $0)"

# Check we're on a Debian-family box. We only TEST for Ubuntu by name in
# the user-facing message; the actual deps work on Debian too. If you
# happen to run this on Debian it'll work fine.
if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}" in
        ubuntu|debian) ;;
        *) warn "this script targets Ubuntu/Debian; detected ID=${ID:-unknown} — proceeding anyway" ;;
    esac
fi

command -v systemctl >/dev/null || die "systemd is required (no systemctl found)"

# Find the source tree. The script expects to be run from the repo root,
# i.e. the directory containing the `app/` tree. Resolve it via the
# script's own location so `sudo bash install-baremetal.sh` works
# regardless of cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -d "${SCRIPT_DIR}/app" ]] || die "no app/ directory next to this script (expected at ${SCRIPT_DIR}/app)"
[[ -f "${SCRIPT_DIR}/dnsmasq.conf.template" ]] || die "no dnsmasq.conf.template next to this script"
[[ -f "${SCRIPT_DIR}/entrypoint-baremetal.sh" ]] || die "no entrypoint-baremetal.sh next to this script"
[[ -f "${SCRIPT_DIR}/app/requirements.txt" ]] || die "no app/requirements.txt — corrupt source tree?"

# ---------------------------------------------------------------------------
# Confirm with the user
# ---------------------------------------------------------------------------
echo
echo "wgflow bare-metal install"
echo "-------------------------"
echo "This will:"
echo "  - apt install wireguard-tools iptables dnsmasq python3-venv python3-pip"
echo "  - stop + disable wg-quick@wg0 (your existing wireguard service)"
echo "  - configure systemd-resolved to not bind :53 (so dnsmasq can)"
echo "  - install wgflow under /opt/wgflow + /var/lib/wgflow + /etc/wgflow"
echo "  - install + enable a systemd unit"
echo
read -r -p "Proceed? [y/N] " ans
[[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]] || die "aborted"

# ---------------------------------------------------------------------------
# Step 1: apt
# ---------------------------------------------------------------------------
step "installing apt packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    wireguard-tools \
    iproute2 \
    iptables \
    iputils-ping \
    conntrack \
    dnsmasq \
    procps \
    ca-certificates \
    curl \
    python3 \
    python3-pip \
    python3-venv \
    qrencode \
    mtr-tiny \
    traceroute \
    dnsutils \
    iperf3 \
    openssl
note "done"

# build-essential is only needed if pip can't find a wheel for one of
# the requirements (uvloop, pydantic-core, bcrypt). All current pins
# ship wheels for cpython 3.10+ on x86_64/aarch64 Linux, so this is
# defense-in-depth. Skip if already present to avoid noise.
if ! dpkg -s build-essential >/dev/null 2>&1; then
    note "installing build-essential as a fallback for pip wheel-misses"
    apt-get install -y -qq build-essential python3-dev
fi

# Some Ubuntu installs auto-start dnsmasq.service after apt install. We
# manage dnsmasq ourselves via the entrypoint, so disable the system unit
# to prevent two dnsmasq processes fighting over port 53.
if systemctl list-unit-files | grep -q '^dnsmasq\.service'; then
    step "disabling system dnsmasq.service (we manage dnsmasq ourselves)"
    systemctl disable --now dnsmasq.service 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Step 2: stop existing wireguard
# ---------------------------------------------------------------------------
WG_IF="wg0"

if systemctl is-active --quiet "wg-quick@${WG_IF}.service" 2>/dev/null; then
    step "stopping wg-quick@${WG_IF}.service"
    systemctl stop "wg-quick@${WG_IF}.service" || warn "stop failed; continuing"
else
    note "wg-quick@${WG_IF}.service not running"
fi

if systemctl is-enabled --quiet "wg-quick@${WG_IF}.service" 2>/dev/null; then
    step "disabling wg-quick@${WG_IF}.service (so it doesn't fight wgflow on boot)"
    systemctl disable "wg-quick@${WG_IF}.service" || warn "disable failed; continuing"
else
    note "wg-quick@${WG_IF}.service not enabled"
fi

# Take the interface down if it's still up after stopping the unit
# (covers the case where it was brought up manually with `wg-quick up`
# rather than via the unit).
if ip link show "${WG_IF}" >/dev/null 2>&1; then
    step "tearing down stale ${WG_IF} interface"
    wg-quick down "${WG_IF}" 2>/dev/null || ip link del "${WG_IF}" 2>/dev/null || true
fi

# Back up the existing wg0.conf so the operator can read peer info from it
# during migration. Don't *delete* it — wgflow's entrypoint will overwrite
# it with its own config anyway, but the backup is what the migrate UI
# will read (the operator points the migrate tab at the .bak file).
if [[ -f "/etc/wireguard/${WG_IF}.conf" ]]; then
    BACKUP_PATH="/etc/wireguard/${WG_IF}.conf.pre-wgflow.bak"
    if [[ ! -f "${BACKUP_PATH}" ]]; then
        step "backing up existing /etc/wireguard/${WG_IF}.conf → ${BACKUP_PATH}"
        cp -a "/etc/wireguard/${WG_IF}.conf" "${BACKUP_PATH}"
        note "use this file as your migration source in the wgflow UI"
    else
        note "backup already exists at ${BACKUP_PATH} — leaving it alone"
    fi
fi

# ---------------------------------------------------------------------------
# Step 3: systemd-resolved
# ---------------------------------------------------------------------------
# Ubuntu's systemd-resolved listens on 127.0.0.53:53 by default, which
# is fine — dnsmasq binds to 10.13.13.1:53 (different IP, no conflict)
# IF resolved's stub listener is restricted to 127.0.0.53. But on some
# configs the stub listener binds 0.0.0.0:53 effectively, which collides.
# Setting DNSStubListener=no makes resolved a non-listening backend used
# only via /etc/resolv.conf forwarding — exactly what we want.
RESOLVED_CONF="/etc/systemd/resolved.conf"
if [[ -f "${RESOLVED_CONF}" ]]; then
    if ! grep -qE '^DNSStubListener=no' "${RESOLVED_CONF}"; then
        step "configuring systemd-resolved (DNSStubListener=no)"
        BACKUP="${RESOLVED_CONF}.pre-wgflow.bak"
        [[ -f "${BACKUP}" ]] || cp -a "${RESOLVED_CONF}" "${BACKUP}"

        # Idempotent edit: if the line is commented out or set to yes,
        # replace it. Otherwise append. We only touch the [Resolve]
        # section's DNSStubListener key.
        if grep -qE '^[#[:space:]]*DNSStubListener=' "${RESOLVED_CONF}"; then
            sed -i -E 's|^[#[:space:]]*DNSStubListener=.*|DNSStubListener=no|' "${RESOLVED_CONF}"
        else
            # Append under [Resolve] section, or at file end if no section header.
            if grep -q '^\[Resolve\]' "${RESOLVED_CONF}"; then
                sed -i '/^\[Resolve\]/a DNSStubListener=no' "${RESOLVED_CONF}"
            else
                printf '\n[Resolve]\nDNSStubListener=no\n' >> "${RESOLVED_CONF}"
            fi
        fi
        systemctl restart systemd-resolved || warn "systemd-resolved restart failed; check 'systemctl status systemd-resolved'"
        note "backup at ${BACKUP}"
    else
        note "DNSStubListener=no already set, leaving alone"
    fi
else
    note "no systemd-resolved on this box, skipping"
fi

# ---------------------------------------------------------------------------
# Step 4: ip_forward
# ---------------------------------------------------------------------------
# Persist net.ipv4.ip_forward=1. The entrypoint also sets it at runtime
# so this is belt-and-braces.
SYSCTL_FILE="/etc/sysctl.d/99-wgflow.conf"
if [[ ! -f "${SYSCTL_FILE}" ]]; then
    step "enabling net.ipv4.ip_forward=1 (${SYSCTL_FILE})"
    cat > "${SYSCTL_FILE}" <<EOF
# wgflow needs IPv4 forwarding to route peer traffic out to the internet.
net.ipv4.ip_forward = 1
EOF
    sysctl -p "${SYSCTL_FILE}" >/dev/null
else
    note "${SYSCTL_FILE} already present"
fi

# ---------------------------------------------------------------------------
# Step 5: directories
# ---------------------------------------------------------------------------
step "creating directories"
mkdir -p /opt/wgflow
mkdir -p /var/lib/wgflow/data/keys
mkdir -p /var/lib/wgflow/data/peers
mkdir -p /etc/wgflow
chmod 700 /var/lib/wgflow/data/keys
chmod 700 /etc/wgflow

# ---------------------------------------------------------------------------
# Step 6: copy code
# ---------------------------------------------------------------------------
step "copying app/ → /opt/wgflow/app/"
# Use rsync if available for cleaner output; fall back to cp. Either way
# we wipe the destination first so removed files don't linger across
# upgrades.
rm -rf /opt/wgflow/app
if command -v rsync >/dev/null; then
    rsync -a --delete "${SCRIPT_DIR}/app/" /opt/wgflow/app/
else
    cp -a "${SCRIPT_DIR}/app" /opt/wgflow/app
fi

# Strip pyc caches just in case the source tree has them from a dev run.
find /opt/wgflow/app -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true

# Render the dnsmasq template stripped of the keep-in-foreground line.
# The container variant uses tini as PID 1 and wants dnsmasq foreground;
# bare-metal wants dnsmasq daemonized so the entrypoint exits cleanly
# (otherwise systemd's ExecStartPre would block forever).
step "rendering /opt/wgflow/dnsmasq.conf.template (bare-metal variant)"
grep -v '^keep-in-foreground' "${SCRIPT_DIR}/dnsmasq.conf.template" \
    > /opt/wgflow/dnsmasq.conf.template

# Copy the entrypoint and make it executable.
cp "${SCRIPT_DIR}/entrypoint-baremetal.sh" /opt/wgflow/entrypoint-baremetal.sh
chmod +x /opt/wgflow/entrypoint-baremetal.sh

# ---------------------------------------------------------------------------
# Step 7: venv + pip
# ---------------------------------------------------------------------------
step "creating Python venv at /opt/wgflow/venv"
python3 -m venv /opt/wgflow/venv

step "installing Python dependencies (this takes ~30s)"
/opt/wgflow/venv/bin/pip install --quiet --upgrade pip
/opt/wgflow/venv/bin/pip install --quiet -r /opt/wgflow/app/requirements.txt
note "done"

# ---------------------------------------------------------------------------
# Step 8: .env
# ---------------------------------------------------------------------------
ENV_FILE="/etc/wgflow/.env"
if [[ -f "${ENV_FILE}" ]]; then
    step ".env already exists at ${ENV_FILE}, leaving it alone"
    GENERATED_PASSWORD=""
else
    step "writing default ${ENV_FILE}"
    # Generate a random password. The app will bcrypt-hash it at startup
    # when it sees plaintext — so we can drop it in unhashed.
    GENERATED_PASSWORD="$(openssl rand -base64 18 | tr -d '/+=' | head -c 24)"

    cat > "${ENV_FILE}" <<EOF
# wgflow bare-metal config. Edit and run: systemctl restart wgflow

# --- WireGuard ---
WG_INTERFACE=wg0
WG_LISTEN_PORT=51820
WG_SUBNET=10.13.13.0/24
WG_SERVER_ADDRESS=10.13.13.1/24
# IMPORTANT: change this to your public hostname or IP.
WG_ENDPOINT=vpn.example.com:51820

# Default ACL applied to new peers (comma-separated CIDRs).
# 10.0.0.0/8 = let peers reach RFC1918 only. Use 0.0.0.0/0 for full-tunnel.
WG_DEFAULT_ACL=10.0.0.0/8

# --- DNS ---
# Set WG_LOCAL_DNS=0 to disable wgflow's dnsmasq entirely (peers will
# use WG_PEER_DNS directly). Leave =1 to use wgflow's bundled resolver.
WG_LOCAL_DNS=1
WG_DNS_UPSTREAMS=8.8.8.8,8.8.4.4,1.1.1.1
# WG_PEER_DNS auto-derives sensibly; uncomment to override:
# WG_PEER_DNS=10.13.13.1

# --- Panel auth ---
# Plaintext password OK — the app will bcrypt-hash it at startup.
# Empty value = auth DISABLED (panel reachable without login). Don't.
PANEL_PASSWORD=${GENERATED_PASSWORD}

# --- Storage ---
WGFLOW_DATA_DIR=/var/lib/wgflow/data

# --- Telemetry ---
# Set to 0 to opt out of anonymous usage stats (peer count + total rx/tx).
WGFLOW_TELEMETRY_ENABLED=1
EOF
    chmod 600 "${ENV_FILE}"
fi

# ---------------------------------------------------------------------------
# Step 9: systemd unit
# ---------------------------------------------------------------------------
UNIT_FILE="/etc/systemd/system/wgflow.service"
step "writing systemd unit ${UNIT_FILE}"
cat > "${UNIT_FILE}" <<'EOF'
[Unit]
Description=wgflow — WireGuard control panel (bare-metal)
After=network-online.target
Wants=network-online.target
# We deliberately don't set Conflicts=wg-quick@wg0.service. The install
# script disabled that unit; this dependency is enforced once at
# install-time, not at every boot, so an operator who manually starts
# wg-quick@wg0 later will see "interface already exists" in our logs
# (entrypoint handles that case by tearing it down).

[Service]
Type=exec
EnvironmentFile=/etc/wgflow/.env
WorkingDirectory=/opt/wgflow
ExecStartPre=/opt/wgflow/entrypoint-baremetal.sh
ExecStart=/opt/wgflow/venv/bin/uvicorn app.main:app \
    --app-dir /opt/wgflow \
    --host 127.0.0.1 \
    --port 8080 \
    --no-access-log
# Use the default KillMode (control-group) so `systemctl stop wgflow`
# also kills dnsmasq. The entrypoint's `pkill -f` and clean restart
# handle the case where a stale dnsmasq from a crashed prior run is
# still bound to :53.
Restart=on-failure
RestartSec=3

# Run as root: wgflow needs to manipulate iptables, wg, wg-quick, and
# (when LOCAL_DNS=1) bind low ports for dnsmasq. CAP_NET_ADMIN +
# CAP_NET_BIND_SERVICE would be enough for most paths, but wg-quick
# also wants to load the kernel module on cold start. Root is the
# pragmatic choice; capabilities are a future hardening project.
User=root
Group=root

# Be loud in journalctl, quiet on stdout. wgflow's logs already go via
# Python's logging machinery; stderr captures uncaught exceptions.
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

step "enabling + starting wgflow.service"
systemctl enable --now wgflow.service

# Give it a couple seconds to either bind or fail.
sleep 3

if systemctl is-active --quiet wgflow.service; then
    note "wgflow is running"
else
    warn "wgflow failed to start. Check: journalctl -u wgflow -n 80 --no-pager"
    exit 1
fi

# ---------------------------------------------------------------------------
# Done — print next steps
# ---------------------------------------------------------------------------
SERVER_PUB=""
if [[ -f /var/lib/wgflow/data/keys/server_public.key ]]; then
    SERVER_PUB="$(cat /var/lib/wgflow/data/keys/server_public.key)"
fi

cat <<EOF

${c_ok}===============================================================${c_off}
 wgflow installed.

 Panel:    http://127.0.0.1:8080  (loopback only by default)
EOF

if [[ -n "${GENERATED_PASSWORD}" ]]; then
    cat <<EOF
 Password: ${GENERATED_PASSWORD}
           (this is the only time it's printed — it's stored as
           plaintext in /etc/wgflow/.env until first app start, when
           wgflow rewrites it as a bcrypt hash. Change anytime by
           editing /etc/wgflow/.env and running 'systemctl restart wgflow'.)
EOF
fi

cat <<EOF

 Server pubkey: ${SERVER_PUB:-(not generated yet — check journalctl)}

 Next steps:
   1. Edit /etc/wgflow/.env — set WG_ENDPOINT to your real hostname/IP
      (the default 'vpn.example.com:51820' will not work for clients).
      Then: systemctl restart wgflow

   2. Reach the panel:
        - Local:  http://127.0.0.1:8080
        - SSH tunnel: ssh -L 8080:127.0.0.1:8080 you@this-host
                      then open http://127.0.0.1:8080 on your laptop

   3. Migrate your existing peers:
        - Open the panel, log in, go to peer-management → migrate
        - Upload /etc/wireguard/wg0.conf.pre-wgflow.bak (your old config)
        - Tick "adopt source's server keypair" so existing clients
          can connect without reconfiguration
        - Type IMPORT, commit

 Logs:    journalctl -u wgflow -f
 Status:  systemctl status wgflow
${c_ok}===============================================================${c_off}
EOF
