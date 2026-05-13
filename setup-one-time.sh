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
# Initial admin password is written to the repo root alongside .env
# (chmod 600). Lives with the deployment files rather than /root so
# that removing the deployment dir removes the password file too.
PASSWORD_FILE="${SCRIPT_DIR}/.wgflow-initial-password"
LOG_PREFIX="[setup]"

# ANSI colors (only if stdout is a tty — pipe-safe). Use $'...'
# (ANSI-C quoting) so bash interprets the \033 escape at assignment
# time. Without this the constants hold the literal six-character
# string "\033[1m" which gets emitted verbatim by printf/heredocs
# (the bug from v4.3.0 — operator saw codes in the terminal).
if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'
    C_BOLD=$'\033[1m'
    C_DIM=$'\033[2m'
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
    C_RED=$'\033[31m'
    C_CYAN=$'\033[36m'
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

validate_port() {
    local v="$1"
    if [[ ! "$v" =~ ^[0-9]+$ ]]; then
        warn "expected a number (1-65535), got: $v"
        return 1
    fi
    if (( v < 1 || v > 65535 )); then
        warn "port out of range (1-65535)"
        return 1
    fi
    return 0
}

validate_bind_iface() {
    local v="$1"
    if [[ "$v" != "0.0.0.0" && "$v" != "127.0.0.1" && ! "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        warn "expected 0.0.0.0, 127.0.0.1, or another IPv4 (got: $v)"
        return 1
    fi
    return 0
}

validate_acl() {
    # Coarse ACL syntax check. The app does the authoritative parse via
    # acl.parse_entry; we just refuse obvious garbage here so the operator
    # gets immediate feedback instead of discovering the typo after the
    # service starts. Format per entry (comma-separated):
    #   [!]IP-or-CIDR[:port[/proto]]
    # plus optional `# comment` at end of any entry. We tolerate
    # whitespace around commas.
    local v="$1"
    [[ -z "$v" ]] && { warn "ACL cannot be empty (use 10.0.0.0/8 for permissive default)"; return 1; }
    local IFS=','
    local entry
    for entry in $v; do
        # Trim whitespace.
        entry="${entry#"${entry%%[![:space:]]*}"}"
        entry="${entry%"${entry##*[![:space:]]}"}"
        [[ -z "$entry" ]] && continue
        # Strip optional bang prefix.
        entry="${entry#!}"
        # Strip optional comment.
        entry="${entry%%#*}"
        entry="${entry%"${entry##*[![:space:]]}"}"
        # Now expect IP, IP/cidr, IP:port, or IP:port/proto.
        if [[ ! "$entry" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?(:[0-9]+(/[a-zA-Z]+)?)?$ ]]; then
            warn "invalid ACL entry: '${entry}' (expected IP[/cidr][:port[/proto]])"
            return 1
        fi
    done
    return 0
}

# Returns 0 if the given port is currently bound by any listener on
# the host. iface is informational — for the host network namespace
# any specific-IP listener will conflict with our 0.0.0.0 bind, and
# any 0.0.0.0 listener will conflict with our specific-IP bind, so
# we just ask "is anything listening on this port".
port_in_use() {
    local port="$1"
    command -v ss >/dev/null 2>&1 || return 2   # can't check
    # `ss -tlnH "sport = :PORT"` filters to listening TCP sockets
    # bound to PORT. Any output means something is listening.
    local lines
    lines=$(ss -tlnH "sport = :${port}" 2>/dev/null)
    [[ -n "$lines" ]]
}

# Best-effort: tell the operator which process owns a port.
port_owner_hint() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -tlnpH "sport = :${port}" 2>/dev/null | head -3 | sed 's/^/         /'
    fi
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

# (3) Client subnet — moved EARLIER than in the v4.3.0 initial layout
#     because question 5 (multisite) needs to validate the federation
#     subnet doesn't overlap with this one. Asked before the multisite
#     toggle.
echo "  ${C_BOLD}3. WireGuard client subnet${C_RESET} ${C_DIM}(advanced, defaults usually fine)${C_RESET}"
echo "     The /24 from which peer addresses are allocated. Change only"
echo "     if it conflicts with networks you already use."
prompt_string WG_SUBNET "     subnet" "10.13.13.0/24" validate_cidr
echo

# (4) Migration / import panel
echo "  ${C_BOLD}4. Import from another VPN${C_RESET}"
echo "     If you're migrating from wg-easy, PiVPN, or a bare WireGuard"
echo "     setup, the Import panel can read those configs and create"
echo "     peers in wgflow. You can disable this later from Settings."
prompt_yesno WGFLOW_MIGRATION_DEFAULT_ENABLED "     show Import panel?" "no"
echo

# (5) Telemetry
echo "  ${C_BOLD}5. Anonymous telemetry${C_RESET}"
echo "     wgflow sends a small payload every ~30 min: version, peer"
echo "     count, total RX/TX bytes, uptime, instance ID (a random"
echo "     string we generate). No peer identifiers, no IPs, no names."
echo "     See README §Telemetry for what's sent and how to opt out."
prompt_yesno WGFLOW_TELEMETRY_ENABLED "     send anonymous stats?" "yes"
echo

# (6) Multisite federation
echo "  ${C_BOLD}6. Multisite federation${C_RESET}"
echo "     Pair this wgflow with other wgflows over WireGuard, so"
echo "     advertised LANs on each side can reach the other. Adds a"
echo "     Multisite panel; uses a separate /24 overlay subnet for"
echo "     federation traffic (default 10.99.0.0/24, must NOT overlap"
echo "     with your client subnet)."
prompt_yesno WG_MULTISITE "     enable multisite federation?" "yes"
WG_FEDERATION_SUBNET_VAL="10.99.0.0/24"
if [[ "$WG_MULTISITE" == "1" ]]; then
    echo
    echo "     Federation overlay subnet (advanced, default is fine in"
    echo "     most cases — change only if it conflicts with networks"
    echo "     you already use)."
    prompt_string WG_FEDERATION_SUBNET "     federation subnet" "10.99.0.0/24" validate_cidr
    WG_FEDERATION_SUBNET_VAL="$WG_FEDERATION_SUBNET"
    # Sanity: federation subnet must not overlap with client subnet.
    # Cheap check: must not be the exact same /24.
    if [[ "$WG_FEDERATION_SUBNET_VAL" == "$WG_SUBNET" ]]; then
        fail "federation subnet ${WG_FEDERATION_SUBNET_VAL} overlaps with client subnet ${WG_SUBNET}. they must be different."
    fi
fi
echo

# (7) Default ACL for new peers
echo "  ${C_BOLD}7. Default ACL for new peers${C_RESET}"
echo "     What destinations can a NEW peer reach when first created."
echo "     (Per-peer ACLs can be edited later from the panel.)"
echo
echo "     Format: comma-separated entries. Each entry is one of:"
echo "       ${C_DIM}10.0.0.0/8${C_RESET}                  CIDR block (any port, any proto)"
echo "       ${C_DIM}192.168.1.7${C_RESET}                 single host (bare IP = /32)"
echo "       ${C_DIM}192.168.1.7:3389/tcp${C_RESET}        single host + port + proto"
echo "       ${C_DIM}!10.0.0.5/32${C_RESET}                deny rule (! prefix)"
echo
echo "     ${C_DIM}10.0.0.0/8${C_RESET}        broad — peers reach anything in private LANs (default)"
echo "     ${C_DIM}narrow example${C_RESET}    192.168.99.7:3389/tcp,192.168.99.133/32,192.168.99.132/32"
echo "                       (only RDP on .7, and full access to .133 / .132)"
prompt_string WG_DEFAULT_ACL "     default ACL" "10.0.0.0/8" validate_acl
echo

# (8) iptables drop logging
echo "  ${C_BOLD}8. iptables drop logging${C_RESET}"
echo "     When ON: rejected packets are logged with WGFLOW-DROP: prefix"
echo "     (rate-limited). Useful for debugging ACLs and tracking attack"
echo "     surface. Noisy on busy installs; off by default."
prompt_yesno WGFLOW_IPTABLES_LOG "     enable drop logging?" "no"
echo

# (9) Admin panel bind + port
echo "  ${C_BOLD}9. Admin panel binding${C_RESET}"
echo "     Where the wgflow admin panel is reachable on this host."
echo "     ${C_DIM}0.0.0.0${C_RESET}    — listen on all interfaces (any IP)"
echo "     ${C_DIM}127.0.0.1${C_RESET}  — loopback only (use when fronting with a"
echo "                  reverse proxy that provides TLS / extra auth)"
prompt_string HOSTBIND_WG_PANEL "     bind interface" "0.0.0.0" validate_bind_iface
echo
# Pick a default port. If 8080 is already in use on this host,
# warn now and suggest 8081 — but still let the operator pick
# anything.
DEFAULT_PORT=8080
if port_in_use "$DEFAULT_PORT"; then
    warn "port ${DEFAULT_PORT} is already in use on this host:"
    port_owner_hint "$DEFAULT_PORT" >&2
    DEFAULT_PORT=8081
    warn "suggesting ${DEFAULT_PORT} instead — pick any free port below"
fi
echo "     Host-side port for the admin panel (the container always"
echo "     listens on 8080 internally; this is just what the HOST"
echo "     publishes it as)."
while true; do
    prompt_string HOSTBIND_WG_PANEL_PORT "     host port" "${DEFAULT_PORT}" validate_port
    if port_in_use "$HOSTBIND_WG_PANEL_PORT"; then
        warn "port ${HOSTBIND_WG_PANEL_PORT} is in use:"
        port_owner_hint "$HOSTBIND_WG_PANEL_PORT" >&2
        if [[ $INTERACTIVE -eq 0 ]]; then
            fail "port ${HOSTBIND_WG_PANEL_PORT} is in use and we can't prompt for another (--noninteractive)"
        fi
        unset HOSTBIND_WG_PANEL_PORT
        continue
    fi
    break
done
echo

# ---------------------------------------------------------------------------
# Password generation
# ---------------------------------------------------------------------------

say "Initial admin password..."

# Generate a 16-byte random hex string as the proposed default
# (32 chars, 128 bits of entropy — under bcrypt's 72-byte input
# limit and short enough that copy-pasting between terminals is
# painless). Use od (always available on Linux) rather than xxd
# (not on minimal Ubuntu/Debian).
RANDOM_PASSWORD="$(od -A n -t x1 -N 16 < /dev/urandom | tr -d ' \n')"

# In interactive mode, show the random default and let the operator
# accept it (Enter) or type their own. In --noninteractive mode,
# use the random default unless PANEL_PASSWORD is preset in the
# environment.
if [[ -n "${PANEL_PASSWORD:-}" ]]; then
    say "  using PANEL_PASSWORD from environment"
elif [[ $INTERACTIVE -eq 0 ]]; then
    PANEL_PASSWORD="$RANDOM_PASSWORD"
    say "  generated random password (will be saved to ${PASSWORD_FILE})"
else
    echo
    echo "     A random password has been generated for the admin user."
    echo "     Press Enter to use it, or type your own password."
    echo "     ${C_DIM}generated: ${RANDOM_PASSWORD}${C_RESET}"
    echo
    printf "     password [random]: "
    read -r typed_password
    if [[ -z "$typed_password" ]]; then
        PANEL_PASSWORD="$RANDOM_PASSWORD"
        echo "     ${C_GREEN}using generated password${C_RESET}"
    else
        # Sanity: bcrypt rejects inputs over 72 bytes. Warn early.
        if [[ ${#typed_password} -gt 72 ]]; then
            warn "your password is ${#typed_password} chars (>72); bcrypt will reject it"
            warn "either pick something shorter or press Ctrl-C and re-run"
        fi
        PANEL_PASSWORD="$typed_password"
        echo "     ${C_GREEN}using your password${C_RESET}"
    fi
    echo
fi

# Write to a root-owned, chmod-600 file. We print the file PATH
# (not the password) so it doesn't end up in journalctl, ssh
# scrollback, terminal multiplexer buffers, etc.
mkdir -p "$(dirname "$PASSWORD_FILE")"
umask 077
printf '%s\n' "$PANEL_PASSWORD" > "$PASSWORD_FILE"
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

# Defaults for variables we don't prompt for but which docker-compose
# references. Setting them here (rather than relying on shell-side
# `${VAR:-default}` in compose) keeps the .env self-documenting and
# means operators editing values can see all the knobs in one place.
HOSTBIND_WG_PANEL_VAL="${HOSTBIND_WG_PANEL:-0.0.0.0}"
HOSTBIND_WG_PANEL_PORT_VAL="${HOSTBIND_WG_PANEL_PORT:-8080}"
# Backwards-compat: previous setup.sh wrote HOSTBIND_WG_PANEL as
# `host:port` (e.g. 127.0.0.1:8080), assuming the compose file's
# 2-part form `${HOSTBIND_WG_PANEL}:8080/tcp`. We've switched the
# compose file to the unambiguous 3-part form
# `${HOSTBIND_WG_PANEL}:${HOSTBIND_WG_PANEL_PORT}:8080/tcp`, so
# HOSTBIND_WG_PANEL is now interface-only. If the operator's env
# still has the legacy host:port form, split it: the IP becomes
# HOSTBIND_WG_PANEL, the port becomes HOSTBIND_WG_PANEL_PORT.
if [[ "$HOSTBIND_WG_PANEL_VAL" == *:* ]]; then
    legacy="$HOSTBIND_WG_PANEL_VAL"
    legacy_port="${HOSTBIND_WG_PANEL_VAL##*:}"
    HOSTBIND_WG_PANEL_VAL="${HOSTBIND_WG_PANEL_VAL%:*}"
    # If the operator already set HOSTBIND_WG_PANEL_PORT explicitly,
    # respect that — otherwise lift the legacy port out.
    if [[ -z "${HOSTBIND_WG_PANEL_PORT:-}" ]] && [[ "$legacy_port" =~ ^[0-9]+$ ]]; then
        HOSTBIND_WG_PANEL_PORT_VAL="$legacy_port"
    fi
    warn "HOSTBIND_WG_PANEL was '${legacy}' (host:port). v4.3.0 expects"
    warn "interface only — normalized to '${HOSTBIND_WG_PANEL_VAL}' (port"
    warn "${HOSTBIND_WG_PANEL_PORT_VAL} kept as HOSTBIND_WG_PANEL_PORT)."
fi
WGFLOW_BIND_VAL="${WGFLOW_BIND:-0.0.0.0:8080}"
WGFLOW_IPTABLES_LOG_VAL="${WGFLOW_IPTABLES_LOG:-0}"
WG_DEFAULT_ACL_VAL="${WG_DEFAULT_ACL:-10.0.0.0/8}"
KERNEL_LOG_PATH_VAL="${KERNEL_LOG_PATH:-/dev/null}"

# Default WG_DNS_UPSTREAMS even when DNS is off — docker-compose
# references this variable unconditionally and will warn about
# unbound vars. The container-side code reads WG_LOCAL_DNS=0 and
# ignores the upstream list, so writing the default is harmless.
if [[ "$WG_LOCAL_DNS" != "1" ]]; then
    WG_DNS_UPSTREAMS_VAL="8.8.8.8,8.8.4.4,1.1.1.1"
fi

# Peer-side DNS — when local DNS is on, peers resolve via the
# wgflow server itself (so blocklists apply); when off, peers
# get a public resolver in their generated config.
if [[ "$WG_LOCAL_DNS" == "1" ]]; then
    WG_PEER_DNS_VAL="${SUBNET_PREFIX}.1"
else
    WG_PEER_DNS_VAL="1.1.1.1"
fi

cat > "$ENV_FILE" <<EOF
# wgflow configuration
# Generated by setup-one-time.sh on $(date -Is)
#
# Edit any value, then:
#   Docker:      docker compose up -d
#   Bare-metal:  systemctl restart wgflow
#
# Every variable docker-compose references is set explicitly here
# so you can find and tune any knob without hunting through docs.

# ---- Public endpoint -------------------------------------------------------
# The host:port peers connect to over WireGuard. Must be reachable
# from the public internet (or your peers' networks).
WG_ENDPOINT=${WG_ENDPOINT}

# ---- WireGuard interface ---------------------------------------------------
WG_INTERFACE=wg0
WG_LISTEN_PORT=51820
WG_SUBNET=${WG_SUBNET}
WG_SERVER_ADDRESS=${WG_SERVER_ADDRESS}

# Default ACL applied to new client peers — controls which destinations
# they can reach by default. 10.0.0.0/8 covers most private LANs;
# tighten if you want more restrictive defaults.
WG_DEFAULT_ACL=${WG_DEFAULT_ACL_VAL}

# ---- Local DNS -------------------------------------------------------------
# 1 = run dnsmasq inside wgflow with blocklist support; DNS Queries +
# Blocklists + DNS Overrides panels visible.
# 0 = no DNS server, those panels hidden.
WG_LOCAL_DNS=${WG_LOCAL_DNS}
WG_DNS_UPSTREAMS=${WG_DNS_UPSTREAMS_VAL}

# Peer-side DNS field in generated client configs. When WG_LOCAL_DNS=1
# this is the wgflow itself (so peers use the local DNS); otherwise
# a public resolver.
WG_PEER_DNS=${WG_PEER_DNS_VAL}

# ---- Authentication --------------------------------------------------------
# The plaintext password is bcrypt-hashed at startup. We also save the
# value in ${PASSWORD_FILE} (chmod 600) for your records — you can
# change it from the panel (Settings → Account) after first login.
# Leave empty to DISABLE the panel password entirely (not recommended).
PANEL_PASSWORD=${PANEL_PASSWORD}

# ---- Migration importer ----------------------------------------------------
# 1 = show the Import panel for migrating from wg-easy / PiVPN /
# bare WG. 0 = hide. This seeds the initial state; once you toggle
# it in the panel (Settings → Features), the DB row wins and this
# variable is no longer consulted.
WGFLOW_MIGRATION_DEFAULT_ENABLED=${WGFLOW_MIGRATION_DEFAULT_ENABLED}

# ---- Telemetry -------------------------------------------------------------
# 1 = send anonymous stats to wgflow.2ps.in every 30 min.
# See README §Telemetry for what's sent. Opt out by setting to 0.
WGFLOW_TELEMETRY_ENABLED=${WGFLOW_TELEMETRY_ENABLED}
# Community-shared HMAC key for telemetry payload signing. The public
# collector at wgflow.2ps.in accepts payloads signed with this key.
# It's intentionally a known constant — the signature is an integrity
# check, not authentication of origin (the collector enforces its own
# per-IP rate limits and per-instance approval). Change ONLY if you
# run your own collector with a private signing arrangement.
WGFLOW_TELEMETRY_SECRET=wgflow-community-default

# ---- Multisite federation --------------------------------------------------
# 1 = enable the Multisite panel for pairing this wgflow with other
# wgflows over WireGuard. Each pairing produces a federation_links
# row; overlay traffic uses the federation subnet below.
WG_MULTISITE=${WG_MULTISITE}
# Subnet used for the federation overlay (NOT for client peers).
# Each paired wgflow gets one /32 from this range. Must NOT overlap
# with WG_SUBNET.
WG_FEDERATION_SUBNET=${WG_FEDERATION_SUBNET_VAL}
# Optional: override the public host:port other wgflows should send
# WG traffic to. Defaults to WG_ENDPOINT when unset (most operators
# want this default — only override if your federation listener is
# on a different UDP port from your client listener).
WG_FEDERATION_ENDPOINT=

# ---- Panel bind / port mapping ---------------------------------------------
# HOSTBIND_WG_PANEL is the host-side interface to bind for the admin
# panel. 0.0.0.0 = all interfaces; 127.0.0.1 = loopback only (when
# fronting with a reverse proxy).
HOSTBIND_WG_PANEL=${HOSTBIND_WG_PANEL_VAL}
# HOSTBIND_WG_PANEL_PORT is the host-side port. The container always
# listens on 8080 internally; this is what the host publishes it as.
# Change if 8080 is already taken by another service on this host.
HOSTBIND_WG_PANEL_PORT=${HOSTBIND_WG_PANEL_PORT_VAL}
# WGFLOW_BIND is what uvicorn binds INSIDE the container. The two
# must agree on the container-side port (8080 by default); the
# host-side is set by HOSTBIND_WG_PANEL_PORT above.
WGFLOW_BIND=${WGFLOW_BIND_VAL}

# ---- Advanced --------------------------------------------------------------
# Iptables drop logging: 0 = quiet, 1 = log rejected packets (rate-
# limited, prefix WGFLOW-DROP:). Useful for debugging ACLs; noisy
# on busy installs.
WGFLOW_IPTABLES_LOG=${WGFLOW_IPTABLES_LOG_VAL}

# Path to mount for kernel log streaming (the panel's Logs tab can
# tail this). Default /dev/null disables the feature.
KERNEL_LOG_PATH=${KERNEL_LOG_PATH_VAL}
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

# Operator may want to inspect the .env before anything starts.
# Prompt unless --noninteractive.
START_NOW="1"
if [[ $INTERACTIVE -eq 1 ]]; then
    echo
    if [[ $MODE_DOCKER -eq 1 ]]; then
        echo "Ready to build and start wgflow. This runs:"
        echo "  ${C_DIM}docker compose up -d --build${C_RESET}"
    else
        echo "Ready to install and start wgflow. This runs:"
        echo "  ${C_DIM}install-baremetal.sh${C_RESET}"
    fi
    echo "You can also stop here and run it yourself later."
    prompt_yesno _START_NOW "build and start now?" "yes"
    START_NOW="$_START_NOW"
    echo
fi

if [[ "$START_NOW" != "1" ]]; then
    cat <<EOF

${C_YELLOW}Skipped service start.${C_RESET} Your .env is at ${ENV_FILE}.

When you're ready:
$(if [[ $MODE_DOCKER -eq 1 ]]; then
    echo "  cd ${SCRIPT_DIR}"
    echo "  sudo docker compose up -d --build"
else
    echo "  sudo ${SCRIPT_DIR}/install-baremetal.sh"
fi)

EOF
    exit 0
fi

say "Starting wgflow..."

if [[ $MODE_DOCKER -eq 1 ]]; then
    cd "$SCRIPT_DIR"
    # --build forces a build on first install and is a no-op on
    # re-runs where the image is already current. Cheaper than
    # branching on "is this the first time?".
    if ! docker compose up -d --build 2>&1; then
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

# .env was just written; we set the script's variables to compute it,
# but for the verify path we want to be robust to whatever the .env
# actually contains (in case the operator edited it between write
# and start). Source it. `set -u` is on, so any unset reference
# below would abort — that's why we explicitly set fallback vars
# right after.
set +u
# shellcheck disable=SC1090
source "$ENV_FILE"
set -u

# Resolve which host:port to curl. In Docker mode, the panel is
# exposed on the host via HOSTBIND_WG_PANEL:HOSTBIND_WG_PANEL_PORT.
# In bare-metal, uvicorn binds directly per WGFLOW_BIND
# (default 0.0.0.0:8080).
if [[ $MODE_DOCKER -eq 1 ]]; then
    VERIFY_HOST="${HOSTBIND_WG_PANEL:-0.0.0.0}"
    VERIFY_PORT="${HOSTBIND_WG_PANEL_PORT:-8080}"
else
    # Bare-metal: parse WGFLOW_BIND (e.g. "0.0.0.0:8080").
    VERIFY_HOST="${WGFLOW_BIND%:*}"
    VERIFY_PORT="${WGFLOW_BIND##*:}"
fi
# 0.0.0.0 isn't curl-able; rewrite to loopback for the probe.
[[ "$VERIFY_HOST" == "0.0.0.0" ]] && VERIFY_HOST="127.0.0.1"
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
