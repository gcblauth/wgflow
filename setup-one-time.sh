#!/usr/bin/env bash
# wgflow — setup-one-time.sh
#
# One-shot installer. Run once per host. Idempotent for "already
# installed" detection (refuses to clobber existing .env without
# --force). After this completes, ongoing operations go through
# `docker compose` or `systemctl`, NOT through this script.
#
# Usage:
#   sudo ./setup-one-time.sh                            # Docker, interactive
#   sudo ./setup-one-time.sh --bare-metal               # systemd + venv
#   sudo ./setup-one-time.sh --force                    # reconfigure existing
#   sudo ./setup-one-time.sh --noninteractive           # defaults + env-var overrides
#   sudo WG_ENDPOINT=vpn.example.com:51820 \
#        WG_LOCAL_DNS=1 \
#        ./setup-one-time.sh --noninteractive          # fully scripted
#
# Design:
#   - Detects prior install. If found and not --force, exits 0 with a
#     pointer to docker compose / systemctl for ongoing ops.
#   - Prompts only for values that have no sane default. Everything
#     else gets a default; operator can edit .env after.
#   - Writes a single .env at the repo root. Both Docker and bare-
#     metal modes read from this same file (bare-metal via systemd
#     EnvironmentFile=).
#   - Generates a random admin password, writes to a chmod-600 file,
#     prints the FILE PATH (not the password) to stdout.
#   - Verifies the install by hitting /healthz post-start. Failure
#     is a warning, not a fatal error — panel may need a few seconds.
#
# Safe to re-run with --force. Backs up the existing .env to
# .env.backup-<timestamp> before overwriting.

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants + helpers
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"
PASSWORD_FILE="/root/.wgflow-initial-password"
LOG_PREFIX="[setup]"

# ANSI colors (only if stdout is a tty — pipe-safe).
if [[ -t 1 ]]; then
    C_RESET='\033[0m'
    C_BOLD='\033[1m'
    C_DIM='\033[2m'
    C_GREEN='\033[32m'
    C_YELLOW='\033[33m'
    C_RED='\033[31m'
    C_CYAN='\033[36m'
else
    C_RESET= C_BOLD= C_DIM= C_GREEN= C_YELLOW= C_RED= C_CYAN=
fi

say()  { printf "${C_DIM}%s${C_RESET} %s\n" "$LOG_PREFIX" "$*"; }
ok()   { printf "${C_DIM}%s${C_RESET} ${C_GREEN}✓${C_RESET} %s\n" "$LOG_PREFIX" "$*"; }
warn() { printf "${C_DIM}%s${C_RESET} ${C_YELLOW}!${C_RESET} %s\n" "$LOG_PREFIX" "$*" >&2; }
fail() { printf "${C_DIM}%s${C_RESET} ${C_RED}✗${C_RESET} %s\n" "$LOG_PREFIX" "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Flag parsing
# ---------------------------------------------------------------------------

MODE_DOCKER=1
FORCE=0
INTERACTIVE=1
SHOW_HELP=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bare-metal|--no-docker) MODE_DOCKER=0 ;;
        --force)                  FORCE=1 ;;
        --noninteractive|-y)      INTERACTIVE=0 ;;
        --help|-h)                SHOW_HELP=1 ;;
        *) fail "unknown flag: $1 (try --help)" ;;
    esac
    shift
done

if [[ $SHOW_HELP -eq 1 ]]; then
    sed -n '2,35p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    fail "must run as root (sudo $0 ...)"
fi

if [[ ! -f "${SCRIPT_DIR}/docker-compose.yml" ]] && [[ ! -d "${SCRIPT_DIR}/app" ]]; then
    fail "no docker-compose.yml or app/ in ${SCRIPT_DIR} — run from the wgflow repo root"
fi

# ---------------------------------------------------------------------------
# Prior-install detection
# ---------------------------------------------------------------------------

detect_prior_install() {
    local found=()
    [[ -f "$ENV_FILE" ]] && found+=(".env at ${ENV_FILE}")
    if command -v docker >/dev/null 2>&1; then
        if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx wgflow; then
            found+=("running wgflow container")
        fi
    fi
    [[ -f /etc/systemd/system/wgflow.service ]] && found+=("wgflow.service in systemd")
    [[ -f /data/wgflow.sqlite ]] && found+=("/data/wgflow.sqlite")

    if [[ ${#found[@]} -gt 0 ]]; then
        printf "%s\n" "${found[@]}"
        return 0
    fi
    return 1
}

if PRIOR=$(detect_prior_install); then
    say "Detected prior wgflow install:"
    while IFS= read -r line; do printf "       ${C_DIM}• %s${C_RESET}\n" "$line"; done <<< "$PRIOR"
    if [[ $FORCE -ne 1 ]]; then
        cat <<EOF

${C_YELLOW}wgflow is already configured on this host.${C_RESET} setup-one-time.sh
will not overwrite an existing install without --force.

Ongoing operations:
  ${C_BOLD}Docker:${C_RESET}      docker compose up -d   (apply config changes)
                docker compose logs -f
                docker compose restart
  ${C_BOLD}Bare-metal:${C_RESET}  systemctl restart wgflow
                journalctl -u wgflow -f

To reconfigure from scratch (the existing .env will be backed up):
  sudo $0 --force ${MODE_DOCKER:+}

EOF
        exit 0
    fi
    if [[ -f "$ENV_FILE" ]]; then
        BACKUP="${ENV_FILE}.backup-$(date +%Y%m%d-%H%M%S)"
        cp -p "$ENV_FILE" "$BACKUP"
        ok "backed up existing .env → $BACKUP"
    fi
    warn "--force: reconfiguring existing install"
fi

# ---------------------------------------------------------------------------
# Interactive prompt helpers
# ---------------------------------------------------------------------------
#
# Each prompt reads from env first (so noninteractive mode + scripted
# overrides work), then from stdin if interactive, then falls back to
# the default. Validation happens inline.

prompt_string() {
    # Args: var_name, label, default, [validator-fn]
    local var="$1" label="$2" default="$3" validator="${4:-}"
    local current="${!var:-}"
    local val=""

    if [[ -n "$current" ]]; then
        # Operator pre-set the env var. Trust it (validate if asked).
        val="$current"
    elif [[ $INTERACTIVE -eq 0 ]]; then
        val="$default"
    else
        local prompt="$label"
        [[ -n "$default" ]] && prompt+=" [${C_DIM}${default}${C_RESET}]"
        prompt+=": "
        while true; do
            printf "%b" "$prompt" >&2
            read -r val
            [[ -z "$val" ]] && val="$default"
            if [[ -z "$val" && -z "$default" ]]; then
                warn "value required, please retry"
                continue
            fi
            if [[ -n "$validator" ]]; then
                if ! $validator "$val"; then
                    continue
                fi
            fi
            break
        done
    fi
    printf -v "$var" '%s' "$val"
}

prompt_yesno() {
    # Args: var_name, label, default_yes_or_no
    local var="$1" label="$2" default="$3"
    local current="${!var:-}"
    local val=""

    if [[ -n "$current" ]]; then
        case "$current" in
            1|yes|true|on|YES|Yes) val=1 ;;
            *)                     val=0 ;;
        esac
    elif [[ $INTERACTIVE -eq 0 ]]; then
        [[ "$default" == "yes" ]] && val=1 || val=0
    else
        local hint
        [[ "$default" == "yes" ]] && hint="[Y/n]" || hint="[y/N]"
        printf "%b %s: " "$label" "$hint" >&2
        read -r reply
        if [[ -z "$reply" ]]; then
            [[ "$default" == "yes" ]] && val=1 || val=0
        else
            case "$reply" in
                y|Y|yes|YES) val=1 ;;
                *)           val=0 ;;
            esac
        fi
    fi
    printf -v "$var" '%s' "$val"
}

validate_endpoint() {
    local v="$1"
    if [[ ! "$v" =~ ^[a-zA-Z0-9.-]+:[0-9]+$ ]]; then
        warn "expected host:port (e.g. vpn.example.com:51820), got: $v"
        return 1
    fi
    local port="${v##*:}"
    if (( port < 1 || port > 65535 )); then
        warn "port out of range (1-65535)"
        return 1
    fi
    return 0
}

validate_cidr() {
    local v="$1"
    if [[ ! "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
        warn "expected CIDR (e.g. 10.13.13.0/24), got: $v"
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

cat <<EOF

${C_BOLD}wgflow${C_RESET} — one-time setup
${C_DIM}$(date -Is)${C_RESET}

Mode: $([[ $MODE_DOCKER -eq 1 ]] && echo "Docker" || echo "bare-metal (systemd + venv)")
Interactive: $([[ $INTERACTIVE -eq 1 ]] && echo "yes" || echo "no")
$([[ $FORCE -eq 1 ]] && echo "Forced reconfiguration: yes")

This script:
  1. Asks a few questions about what features you want
  2. Generates a random admin password (saved to a file, chmod 600)
  3. Writes .env with all config values
  4. Starts the service
  5. Verifies the panel is reachable

After it completes, ongoing operations are run with
$([[ $MODE_DOCKER -eq 1 ]] && echo "  docker compose" || echo "  systemctl") — NOT this script.

EOF

# ---------------------------------------------------------------------------
# Mode-specific preflight (Docker availability, bare-metal install path)
# ---------------------------------------------------------------------------

if [[ $MODE_DOCKER -eq 1 ]]; then
    if ! command -v docker >/dev/null 2>&1; then
        cat <<EOF
${C_RED}Docker is not installed.${C_RESET}

Install it before continuing:
  Debian/Ubuntu:  https://docs.docker.com/engine/install/
  RHEL/Rocky:     https://docs.docker.com/engine/install/centos/
  Or run with    --bare-metal   to install without Docker.

EOF
        exit 1
    fi
    if ! docker compose version >/dev/null 2>&1; then
        fail "docker compose plugin missing (try 'apt install docker-compose-plugin' or upgrade Docker)"
    fi
    ok "docker + compose available"
else
    if [[ ! -x "${SCRIPT_DIR}/install-baremetal.sh" ]]; then
        fail "bare-metal mode requested but install-baremetal.sh not found or not executable"
    fi
    ok "bare-metal install script found"
fi

# ---------------------------------------------------------------------------
# Configuration prompts
# ---------------------------------------------------------------------------

say "Gathering configuration..."
echo

# (1) WG_ENDPOINT — required, no default
echo "  ${C_BOLD}1. Public endpoint${C_RESET}"
echo "     The host:port where peers connect to this wgflow over WireGuard."
echo "     Examples: vpn.example.com:51820, 203.0.113.10:51820"
prompt_string WG_ENDPOINT "     endpoint" "" validate_endpoint
echo

# (2) DNS — default off
echo "  ${C_BOLD}2. Local DNS server${C_RESET}"
echo "     Enable wgflow's built-in dnsmasq for DNS-level ad/tracker"
echo "     blocking via blocklists. Adds DNS Queries, Blocklists, and"
echo "     DNS Overrides panels to the UI. Default off."
prompt_yesno WG_LOCAL_DNS "     enable local DNS?" "no"
WG_DNS_UPSTREAMS_VAL=""
if [[ "$WG_LOCAL_DNS" == "1" ]]; then
    echo
    echo "     Upstream resolvers (comma-separated; queries that don't hit a"
    echo "     blocklist are forwarded here)."
    prompt_string WG_DNS_UPSTREAMS "     upstreams" "8.8.8.8,8.8.4.4,1.1.1.1"
    WG_DNS_UPSTREAMS_VAL="$WG_DNS_UPSTREAMS"
fi
echo

# (3) Migration / import panel
echo "  ${C_BOLD}3. Import from another VPN${C_RESET}"
echo "     If you're migrating from wg-easy, PiVPN, or a bare WireGuard"
echo "     setup, the Import panel can read those configs and create"
echo "     peers in wgflow. You can disable this later from Settings."
prompt_yesno WGFLOW_MIGRATION_DEFAULT_ENABLED "     show Import panel?" "no"
echo

# (4) Telemetry
echo "  ${C_BOLD}4. Anonymous telemetry${C_RESET}"
echo "     wgflow sends a small payload every ~30 min: version, peer"
echo "     count, total RX/TX bytes, uptime, instance ID (a random"
echo "     string we generate). No peer identifiers, no IPs, no names."
echo "     See README §Telemetry for what's sent and how to opt out."
prompt_yesno WGFLOW_TELEMETRY "     send anonymous stats?" "yes"
echo

# (5) Subnet (rarely changed but useful for LAN-conflict cases)
echo "  ${C_BOLD}5. WireGuard subnet${C_RESET} ${C_DIM}(advanced, defaults usually fine)${C_RESET}"
echo "     The /24 from which peer addresses are allocated. Change only"
echo "     if it conflicts with networks you already use."
prompt_string WG_SUBNET "     subnet" "10.13.13.0/24" validate_cidr
echo

# ---------------------------------------------------------------------------
# Password generation
# ---------------------------------------------------------------------------

say "Generating initial admin password..."

# 32 bytes of urandom → 64 hex chars. Use /dev/urandom (universally
# available) rather than openssl rand (may not be installed on
# minimal containers we'll build inside).
WGFLOW_AUTH_PASSWORD="$(head -c 32 /dev/urandom | xxd -p | tr -d '\n')"

# Write to a root-owned, chmod-600 file. We print the file PATH
# (not the password) so it doesn't end up in journalctl, ssh
# scrollback, terminal multiplexer buffers, etc.
mkdir -p "$(dirname "$PASSWORD_FILE")"
umask 077
printf '%s\n' "$WGFLOW_AUTH_PASSWORD" > "$PASSWORD_FILE"
chmod 600 "$PASSWORD_FILE"
ok "admin password written → ${PASSWORD_FILE}"

# ---------------------------------------------------------------------------
# Write .env
# ---------------------------------------------------------------------------

say "Writing .env → $ENV_FILE"

# Derive WG_SERVER_ADDRESS from WG_SUBNET (first usable address + /24).
# subnet is e.g. 10.13.13.0/24 → server is 10.13.13.1/24.
SUBNET_NET="${WG_SUBNET%/*}"
SUBNET_MASK="${WG_SUBNET#*/}"
SUBNET_PREFIX="${SUBNET_NET%.*}"
WG_SERVER_ADDRESS="${SUBNET_PREFIX}.1/${SUBNET_MASK}"

cat > "$ENV_FILE" <<EOF
# wgflow configuration
# Generated by setup-one-time.sh on $(date -Is)
#
# Edit any value, then:
#   Docker:      docker compose up -d
#   Bare-metal:  systemctl restart wgflow
#
# Variables you DIDN'T set during setup get the defaults below;
# they're written explicitly so you can find and edit them.

# ---- Public endpoint -------------------------------------------------------
# The host:port peers connect to over WireGuard. Must be reachable
# from the public internet (or your peers' networks).
WG_ENDPOINT=${WG_ENDPOINT}

# ---- WireGuard interface ---------------------------------------------------
WG_INTERFACE=wg0
WG_LISTEN_PORT=51820
WG_SUBNET=${WG_SUBNET}
WG_SERVER_ADDRESS=${WG_SERVER_ADDRESS}

# ---- Local DNS -------------------------------------------------------------
# 1 = run dnsmasq inside wgflow with blocklist support, DNS Queries +
# Blocklists + DNS Overrides panels visible.
# 0 = no DNS server, those panels hidden.
WG_LOCAL_DNS=${WG_LOCAL_DNS}
$(if [[ "$WG_LOCAL_DNS" == "1" ]]; then echo "WG_DNS_UPSTREAMS=${WG_DNS_UPSTREAMS_VAL}"; else echo "# WG_DNS_UPSTREAMS=8.8.8.8,8.8.4.4,1.1.1.1   (uncomment if you turn DNS on)"; fi)

# Peer-side DNS field in generated client configs. Usually the wgflow
# server itself (so peers use the local DNS); change to a public
# resolver if you don't want peers using your local DNS.
$(if [[ "$WG_LOCAL_DNS" == "1" ]]; then echo "WG_PEER_DNS=${SUBNET_PREFIX}.1"; else echo "WG_PEER_DNS=1.1.1.1"; fi)

# ---- Authentication --------------------------------------------------------
# 1 = require password to access the admin panel (recommended).
# Password is the SHA256 of the value in WGFLOW_AUTH_PASSWORD_FILE,
# which is read at startup. We write a random initial password to
# ${PASSWORD_FILE}; you can change it from the panel after first
# login.
WGFLOW_AUTH=1
WGFLOW_AUTH_PASSWORD_FILE=${PASSWORD_FILE}

# ---- Migration importer ----------------------------------------------------
# 1 = show the Import panel for migrating from wg-easy / PiVPN / bare WG.
# 0 = hide. Can be toggled in Settings after install.
WGFLOW_MIGRATION_DEFAULT_ENABLED=${WGFLOW_MIGRATION_DEFAULT_ENABLED}

# ---- Telemetry -------------------------------------------------------------
# 1 = send anonymous stats to wgflow.2ps.in every 30 min.
# See README §Telemetry for what's sent. Opt out by setting to 0.
WGFLOW_TELEMETRY=${WGFLOW_TELEMETRY}

# ---- Multisite federation --------------------------------------------------
# 1 = enable the Multisite panel for pairing this wgflow with another
# wgflow over WireGuard. Each pairing produces a federation_links row;
# overlay traffic uses the 10.99.0.0/24 subnet.
WGFLOW_MULTISITE_ENABLED=1

# ---- Panel bind ------------------------------------------------------------
# Where the FastAPI/uvicorn admin panel listens. Default binds to
# all interfaces on port 8080. Change to 127.0.0.1:8080 if you're
# fronting with a reverse proxy.
WGFLOW_BIND=0.0.0.0:8080

# ---- Advanced --------------------------------------------------------------
# Iptables drop logging: 0 = quiet, 1 = log rejected packets (rate-
# limited) with WGFLOW-DROP: prefix. Useful for debugging ACLs;
# noisy on busy installs.
WGFLOW_DROP_LOGGING=0
EOF

chmod 600 "$ENV_FILE"
ok ".env written ($(wc -l < "$ENV_FILE") lines)"

# ---------------------------------------------------------------------------
# Adapt docker-compose.yml if needed (Docker mode)
# ---------------------------------------------------------------------------
#
# The shipped docker-compose.yml may have env values hardcoded inline
# (legacy layout). For setup-one-time.sh to drive everything via .env,
# the compose file must use ${VAR} interpolation. If it doesn't yet,
# leave a note for the operator — we don't rewrite their compose file
# automatically because we don't know what custom changes they may
# have made.

if [[ $MODE_DOCKER -eq 1 ]]; then
    COMPOSE="${SCRIPT_DIR}/docker-compose.yml"
    if [[ -f "$COMPOSE" ]] && ! grep -q '\${WG_ENDPOINT' "$COMPOSE"; then
        warn "docker-compose.yml has inline values, not \${VAR} references."
        warn "Your .env values will be used when docker compose reads them,"
        warn "but the compose file may have stale defaults that shadow .env."
        warn "Consider editing docker-compose.yml to use \${WG_ENDPOINT} etc."
    fi
fi

# ---------------------------------------------------------------------------
# Start the service
# ---------------------------------------------------------------------------

say "Starting wgflow..."

if [[ $MODE_DOCKER -eq 1 ]]; then
    cd "$SCRIPT_DIR"
    if ! docker compose up -d 2>&1; then
        fail "docker compose up failed — check 'docker compose logs' for details"
    fi
    ok "docker compose started"
else
    # Bare-metal: delegate to install-baremetal.sh, which knows how
    # to set up the venv, write the systemd unit, and start the
    # service. We pass an env var hint so it can short-circuit its
    # own interactive prompts (.env we just wrote is the source of
    # truth now).
    say "Delegating to install-baremetal.sh..."
    if ! WGFLOW_ENV_FILE="$ENV_FILE" "${SCRIPT_DIR}/install-baremetal.sh"; then
        fail "bare-metal install failed — check the output above"
    fi
    ok "bare-metal install complete"
fi

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------

say "Verifying..."

# Wait up to 20s for /healthz to respond. The panel takes a couple
# seconds to come up cold (Python import, sqlite open, wg syncconf).
VERIFY_HOST="${WGFLOW_BIND%:*}"
[[ "$VERIFY_HOST" == "0.0.0.0" ]] && VERIFY_HOST="127.0.0.1"
VERIFY_PORT="${WGFLOW_BIND##*:}"
VERIFY_PORT="${VERIFY_PORT:-8080}"
VERIFY_URL="http://${VERIFY_HOST}:${VERIFY_PORT}/healthz"

VERIFY_OK=0
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if curl -fsS --max-time 2 "$VERIFY_URL" >/dev/null 2>&1; then
        VERIFY_OK=1
        break
    fi
    sleep 2
done

if [[ $VERIFY_OK -eq 1 ]]; then
    HEALTH_JSON="$(curl -fsS --max-time 2 "$VERIFY_URL" 2>/dev/null || echo '{}')"
    ok "panel responding at $VERIFY_URL"
    ok "$HEALTH_JSON"
else
    warn "panel not responding at $VERIFY_URL after 20s"
    warn "this may be transient — check logs in 30s:"
    if [[ $MODE_DOCKER -eq 1 ]]; then
        warn "  docker compose logs --tail=50 wgflow"
    else
        warn "  journalctl -u wgflow -n 50 --no-pager"
    fi
fi

# Quick check: wg show wg0 is up
if command -v wg >/dev/null 2>&1; then
    if [[ $MODE_DOCKER -eq 1 ]]; then
        if docker exec wgflow wg show wg0 >/dev/null 2>&1; then
            ok "wg0 interface up inside container"
        else
            warn "wg show wg0 inside container failed — interface may still be coming up"
        fi
    else
        if wg show wg0 >/dev/null 2>&1; then
            ok "wg0 interface up on host"
        else
            warn "wg show wg0 on host failed — interface may still be coming up"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

cat <<EOF

${C_GREEN}${C_BOLD}wgflow setup complete.${C_RESET}

  ${C_BOLD}Panel:${C_RESET}    http://${VERIFY_HOST}:${VERIFY_PORT}/
  ${C_BOLD}Login:${C_RESET}    admin / (password in ${PASSWORD_FILE})

  ${C_BOLD}Read the password:${C_RESET}
    sudo cat ${PASSWORD_FILE}

  ${C_BOLD}First steps:${C_RESET}
    1. Log in to the panel.
    2. ${C_BOLD}Change the admin password${C_RESET} (Settings → Account).
    3. Set up your first peer.

  ${C_BOLD}Day-2 operations:${C_RESET}
$(if [[ $MODE_DOCKER -eq 1 ]]; then cat <<DOC
    Edit .env, then:                docker compose up -d
    View logs:                      docker compose logs -f
    Restart:                        docker compose restart
    Stop:                           docker compose down
DOC
else cat <<BARE
    Edit .env, then:                systemctl restart wgflow
    View logs:                      journalctl -u wgflow -f
    Restart:                        systemctl restart wgflow
    Stop:                           systemctl stop wgflow
BARE
fi)

  ${C_BOLD}Reconfigure:${C_RESET}
    sudo $0 --force

EOF
