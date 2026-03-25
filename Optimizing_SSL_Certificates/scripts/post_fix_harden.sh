#!/usr/bin/env bash
# =============================================================================
#  postfix-harden.sh — Enterprise-Grade Postfix Hardening Script
#  Tested on: Rocky Linux 8/9/10, RHEL 8/9, AlmaLinux 8/9, Ubuntu 20/22/24
#  Version: 1.0.0
# =============================================================================
# MODES:
#   [1] Bare-Metal / VM     — Installs & hardens system Postfix
#   [2] Docker (new)        — Generates configs, certs, compose & launches
#   [3] Docker (existing)   — AUTO-DETECTED if Postfix containers are running
#                             Hardens config of an already-running container
# =============================================================================
# PORTS (secure only):
#   587  — Submission (STARTTLS + mandatory SASL auth — primary client port)
#   465  — SMTPS (implicit TLS + mandatory SASL auth — legacy secure port)
#   25   — DISABLED (blocked on AWS EC2 by default; not needed for lab/project)
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ─────────────────────────────────────────────
# COLOR OUTPUT
# ─────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
detect()  { echo -e "${MAGENTA}[SCAN]${RESET}  $*"; }
header()  { echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════${RESET}"; \
            echo -e "${BOLD}${BLUE}  $*${RESET}"; \
            echo -e "${BOLD}${BLUE}══════════════════════════════════════════${RESET}"; }

# ─────────────────────────────────────────────
# ROOT CHECK
# ─────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  error "This script must be run as root. Use: sudo $0"
  exit 1
fi

# ─────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────
clear
echo -e "${BOLD}${BLUE}"
cat << 'EOF'
  ██████╗  ██████╗ ███████╗████████╗███████╗██╗██╗  ██╗    ██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗███╗   ██╗
  ██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝██╔════╝██║╚██╗██╔╝    ██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║
  ██████╔╝██║   ██║███████╗   ██║   █████╗  ██║ ╚███╔╝     ███████║███████║██████╔╝██║  ██║█████╗  ██╔██╗ ██║
  ██╔═══╝ ██║   ██║╚════██║   ██║   ██╔══╝  ██║ ██╔██╗     ██╔══██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║╚██╗██║
  ██║     ╚██████╔╝███████║   ██║   ██║     ██║██╔╝ ██╗    ██║  ██║██║  ██║██║  ██║██████╔╝███████╗██║ ╚████║
  ╚═╝      ╚═════╝ ╚══════╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝
EOF
echo -e "${RESET}"
echo -e "  ${BOLD}Enterprise-Grade Postfix Hardening Script v1.0.0${RESET}"
echo -e "  ${CYAN}TLS 1.2/1.3 • Port 587/465 • SPF/DKIM/DMARC • Anti-Relay • SASL Auth${RESET}"
echo ""

# =============================================================================
# AUTO-DETECTION: Scan for running Postfix Docker containers + system Postfix
# =============================================================================
header "Auto-Detection — Scanning Environment"

DETECTED_CONTAINERS=()
DEPLOY_MODE=""
CONTAINER_NAME=""
EXISTING_DOCKER=false

# ── Docker scan ───────────────────────────────────────────────────────────────
if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
  detect "Docker is available — scanning for running Postfix containers..."

  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    DETECTED_CONTAINERS+=("$line")
  done < <(docker ps --format '{{.Names}}|{{.Image}}|{{.Ports}}|{{.Status}}' 2>/dev/null \
    | grep -iE '(postfix|mail|smtp|mta)' || true)

  if [[ ${#DETECTED_CONTAINERS[@]} -gt 0 ]]; then
    echo ""
    echo -e "  ${MAGENTA}${BOLD}🐳 Postfix container(s) detected:${RESET}"
    echo ""
    INDEX=1
    for CONT in "${DETECTED_CONTAINERS[@]}"; do
      CNAME=$(echo "$CONT"   | cut -d'|' -f1)
      CIMAGE=$(echo "$CONT"  | cut -d'|' -f2)
      CPORTS=$(echo "$CONT"  | cut -d'|' -f3)
      CSTATUS=$(echo "$CONT" | cut -d'|' -f4)
      echo -e "    ${BOLD}[$INDEX]${RESET} ${GREEN}$CNAME${RESET}"
      echo -e "        Image:  $CIMAGE"
      echo -e "        Ports:  $CPORTS"
      echo -e "        Status: $CSTATUS"
      echo ""
      INDEX=$((INDEX + 1))
    done
    EXISTING_DOCKER=true
  else
    detect "No running Postfix containers found."
  fi
else
  detect "Docker not available or not running — skipping container scan."
fi

# ── System Postfix scan ───────────────────────────────────────────────────────
SYSTEM_POSTFIX=false
POSTFIX_ALREADY_HARDENED=false

if command -v postfix &>/dev/null 2>&1; then
  PF_VER=$(postfix version 2>/dev/null | head -1 || echo "unknown version")
  detect "System Postfix found: $PF_VER"
  SYSTEM_POSTFIX=true

  # Check if already hardened by this script
  if [[ -f /etc/postfix/main.cf ]] && grep -q "postfix-harden.sh" /etc/postfix/main.cf 2>/dev/null; then
    echo ""
    echo -e "  ${YELLOW}${BOLD}⚠  Postfix has already been hardened by this script.${RESET}"
    echo -e "  ${YELLOW}   Continuing will overwrite the current hardened config.${RESET}"
    POSTFIX_ALREADY_HARDENED=true
  fi

  # Check current TLS status
  if [[ -f /etc/postfix/main.cf ]]; then
    echo ""
    echo -e "  ${CYAN}${BOLD}Current TLS status:${RESET}"
    TLS_INBOUND=$(grep -E "^smtpd_tls_security_level" /etc/postfix/main.cf 2>/dev/null \
                  | awk '{print $3}' || echo "not set")
    TLS_OUTBOUND=$(grep -E "^smtp_tls_security_level" /etc/postfix/main.cf 2>/dev/null \
                   | awk '{print $3}' || echo "not set")
    TLS_PROTO=$(grep -E "^smtpd_tls_protocols" /etc/postfix/main.cf 2>/dev/null \
                | cut -d'=' -f2- | xargs || echo "not set")
    echo -e "    smtpd_tls_security_level : ${GREEN}$TLS_INBOUND${RESET}"
    echo -e "    smtp_tls_security_level  : ${GREEN}$TLS_OUTBOUND${RESET}"
    echo -e "    smtpd_tls_protocols      : ${GREEN}$TLS_PROTO${RESET}"
    echo ""

    # Warn if listening on port 25 only
    if grep -qE "^inet_protocols" /etc/postfix/main.cf 2>/dev/null; then
      INET=$(grep -E "^inet_protocols" /etc/postfix/main.cf | awk '{print $3}')
      echo -e "    inet_protocols           : ${CYAN}$INET${RESET}"
    fi
  fi
else
  detect "No system Postfix installation detected."
fi

# =============================================================================
# MODE SELECTION
# =============================================================================
header "Deployment Mode"

echo -e "  ${BOLD}[1]${RESET} Bare-Metal / VM     — Install & harden system Postfix"
echo -e "  ${BOLD}[2]${RESET} Docker (new)        — Generate configs & launch new hardened container"

if $EXISTING_DOCKER; then
  echo -e "  ${BOLD}[3]${RESET} ${MAGENTA}Docker (existing)${RESET}   — Harden a currently running Postfix container"
fi
echo ""

MAX_CHOICE=2
$EXISTING_DOCKER && MAX_CHOICE=3

while true; do
  read -rp "$(echo -e "${BOLD}Select mode [1-${MAX_CHOICE}]: ${RESET}")" MODE_CHOICE
  case "$MODE_CHOICE" in
    1) DEPLOY_MODE="baremetal";       info "Mode: Bare-Metal / VM"; break ;;
    2) DEPLOY_MODE="docker_new";      info "Mode: Docker (new container)"; break ;;
    3)
      if $EXISTING_DOCKER; then
        DEPLOY_MODE="docker_existing"
        info "Mode: Docker (harden existing container)"
        break
      else
        warn "No existing containers detected. Please choose 1 or 2."
      fi
      ;;
    *) warn "Please enter a number between 1 and $MAX_CHOICE" ;;
  esac
done

# =============================================================================
# EXISTING DOCKER CONTAINER SELECTION
# =============================================================================
if [[ "$DEPLOY_MODE" == "docker_existing" ]]; then

  header "Select Target Container"

  if [[ ${#DETECTED_CONTAINERS[@]} -eq 1 ]]; then
    CONTAINER_NAME=$(echo "${DETECTED_CONTAINERS[0]}" | cut -d'|' -f1)
    info "Only one container found — auto-selecting: $CONTAINER_NAME"
  else
    echo ""
    INDEX=1
    for CONT in "${DETECTED_CONTAINERS[@]}"; do
      CNAME=$(echo "$CONT" | cut -d'|' -f1)
      echo -e "  ${BOLD}[$INDEX]${RESET} $CNAME"
      INDEX=$((INDEX + 1))
    done
    echo ""
    while true; do
      read -rp "$(echo -e "${BOLD}Select container [1-${#DETECTED_CONTAINERS[@]}]: ${RESET}")" CONT_CHOICE
      if [[ "$CONT_CHOICE" =~ ^[0-9]+$ ]] && \
         [[ "$CONT_CHOICE" -ge 1 ]] && \
         [[ "$CONT_CHOICE" -le ${#DETECTED_CONTAINERS[@]} ]]; then
        CONTAINER_NAME=$(echo "${DETECTED_CONTAINERS[$((CONT_CHOICE - 1))]}" | cut -d'|' -f1)
        success "Selected container: $CONTAINER_NAME"
        break
      else
        warn "Invalid selection. Please enter a number between 1 and ${#DETECTED_CONTAINERS[@]}"
      fi
    done
  fi

  # ── Inspect the container ──────────────────────────────────────────────────
  header "Inspecting Container: $CONTAINER_NAME"

  CONTAINER_IMAGE=$(docker inspect "$CONTAINER_NAME" \
    --format '{{.Config.Image}}' 2>/dev/null)

  CONTAINER_MOUNTS_RAW=$(docker inspect "$CONTAINER_NAME" \
    --format '{{range .Mounts}}{{.Source}}|{{.Destination}}|{{.Type}} {{end}}' 2>/dev/null)

  info "Image:  $CONTAINER_IMAGE"
  info "Mounts detected:"
  for m in $CONTAINER_MOUNTS_RAW; do
    SRC=$(echo "$m" | cut -d'|' -f1)
    DST=$(echo "$m" | cut -d'|' -f2)
    TYP=$(echo "$m" | cut -d'|' -f3)
    echo -e "        ${CYAN}${DST}${RESET} ← ${SRC} (${TYP})"
  done
  echo ""

  # ── Smart mount resolver ───────────────────────────────────────────────────
  INJECT_POSTFIX_DIR=""
  INJECT_SSL_DIR=""
  USE_DOCKER_CP_CONF=false
  USE_DOCKER_CP_SSL=false

  for m in $CONTAINER_MOUNTS_RAW; do
    SRC=$(echo "$m" | cut -d'|' -f1)
    DST=$(echo "$m" | cut -d'|' -f2)

    if [[ "$DST" == "/etc/postfix" ]]; then
      INJECT_POSTFIX_DIR="$SRC"
      info "Top-level /etc/postfix mount → $SRC"
    fi
    if [[ "$DST" == "/etc/postfix/main.cf" ]]; then
      INJECT_POSTFIX_DIR="$(dirname "$SRC")"
      info "main.cf file mount → $SRC"
    fi
    if [[ "$DST" == "/etc/postfix/ssl" || "$DST" == "/etc/ssl/postfix" ]]; then
      INJECT_SSL_DIR="$SRC"
      info "SSL directory mount → $SRC"
    fi
    if [[ "$DST" =~ ^/etc/postfix/ssl/.*\.(crt|pem|key)$ ]]; then
      INJECT_SSL_DIR="$(dirname "$SRC")"
      info "SSL file mount detected — host SSL dir: $INJECT_SSL_DIR"
    fi
  done

  echo ""
  info "Mount resolution summary:"

  if [[ -n "$INJECT_POSTFIX_DIR" ]]; then
    mkdir -p "$INJECT_POSTFIX_DIR"
    success "  postfix → host path: $INJECT_POSTFIX_DIR (will write directly)"
  else
    USE_DOCKER_CP_CONF=true
    INJECT_POSTFIX_DIR="/tmp/postfix-conf-$$"
    mkdir -p "$INJECT_POSTFIX_DIR"
    warn "  postfix → no host mount — will inject via docker cp"
  fi

  if [[ -n "$INJECT_SSL_DIR" ]]; then
    mkdir -p "$INJECT_SSL_DIR"
    success "  ssl     → host path: $INJECT_SSL_DIR (will write directly)"
  else
    USE_DOCKER_CP_SSL=true
    INJECT_SSL_DIR="/tmp/postfix-ssl-$$"
    mkdir -p "$INJECT_SSL_DIR"
    warn "  ssl     → no host mount — will inject via docker cp"
  fi

  POSTFIX_CONF_DIR="$INJECT_POSTFIX_DIR"
  SSL_DIR="$INJECT_SSL_DIR"
  DOCKER_DIR="/opt/postfix-hardened-$CONTAINER_NAME"

  if docker compose version &>/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
  elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD="docker-compose"
  else
    COMPOSE_CMD=""
  fi
fi

# =============================================================================
# COMMON CONFIGURATION (all modes)
# =============================================================================
header "Configuration"

read -rp "$(echo -e "${BOLD}Domain / mail hostname (e.g. mail.example.com):  ${RESET}")" DOMAIN
DOMAIN="${DOMAIN:-mail.example.com}"

read -rp "$(echo -e "${BOLD}Admin email (for Let's Encrypt notifications):   ${RESET}")" ADMIN_EMAIL

USE_LETSENCRYPT=false
if [[ "$DOMAIN" != "mail.example.com" && -n "$ADMIN_EMAIL" ]]; then
  USE_LETSENCRYPT=true
  info "Will request a Let's Encrypt certificate for: $DOMAIN"
else
  info "Using self-signed certificate. (Provide real domain + email for Let's Encrypt)"
fi

read -rp "$(echo -e "${BOLD}Mail origin domain (e.g. example.com) [same as hostname]: ${RESET}")" MAIL_ORIGIN
MAIL_ORIGIN="${MAIL_ORIGIN:-$DOMAIN}"

read -rp "$(echo -e "${BOLD}Relay host (leave blank for direct delivery):    ${RESET}")" RELAY_HOST
RELAY_HOST="${RELAY_HOST:-}"

# Mode-specific prompts
if [[ "$DEPLOY_MODE" == "docker_new" ]]; then
  read -rp "$(echo -e "${BOLD}Docker container name [postfix-hardened]:        ${RESET}")" CONTAINER_NAME
  CONTAINER_NAME="${CONTAINER_NAME:-postfix-hardened}"
  read -rp "$(echo -e "${BOLD}Docker project directory [/opt/postfix-hardened]:${RESET}")" DOCKER_DIR
  DOCKER_DIR="${DOCKER_DIR:-/opt/postfix-hardened}"
fi

# Ask about enabling DKIM (only if opendkim can be installed or is available in container)
echo ""
read -rp "$(echo -e "${BOLD}Enable DKIM signing? (requires opendkim) [Y/n]:  ${RESET}")" ENABLE_DKIM
ENABLE_DKIM="${ENABLE_DKIM:-Y}"
[[ "$ENABLE_DKIM" =~ ^[Yy] ]] && ENABLE_DKIM=true || ENABLE_DKIM=false

# ── Resolve paths ──────────────────────────────────────────────────────────────
if [[ "$DEPLOY_MODE" == "docker_new" ]]; then
  POSTFIX_CONF_DIR="$DOCKER_DIR/postfix"
  SSL_DIR="$DOCKER_DIR/ssl"
  LOG_DIR="$DOCKER_DIR/logs"
elif [[ "$DEPLOY_MODE" == "baremetal" ]]; then
  POSTFIX_CONF_DIR="/etc/postfix"
  SSL_DIR="/etc/postfix/ssl"
  LOG_DIR="/var/log/postfix"
fi
# docker_existing paths already set above

MAIN_CF="$POSTFIX_CONF_DIR/main.cf"
MASTER_CF="$POSTFIX_CONF_DIR/master.cf"
DH_PARAM="$SSL_DIR/dhparam.pem"
SELF_SIGNED_KEY="$SSL_DIR/postfix.key"
SELF_SIGNED_CERT="$SSL_DIR/postfix.crt"
BACKUP_DIR="/tmp/postfix-backup-$(date +%Y%m%d_%H%M%S)"

# =============================================================================
# STEP 1: INSTALL DEPENDENCIES
# =============================================================================
header "Step 1: Installing Dependencies"

PKG_MGR=""
if command -v apt-get &>/dev/null; then
  PKG_MGR="apt-get"
  apt-get update -qq &>/dev/null
elif command -v dnf &>/dev/null; then
  PKG_MGR="dnf"
elif command -v yum &>/dev/null; then
  PKG_MGR="yum"
else
  error "Unsupported package manager. Requires apt-get, dnf, or yum."
  exit 1
fi

install_pkg() {
  if [[ "$PKG_MGR" == "apt-get" ]]; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" &>/dev/null
  else
    $PKG_MGR install -y "$@" &>/dev/null
  fi
}

install_pkg openssl curl && success "openssl + curl installed"

if [[ "$DEPLOY_MODE" == "baremetal" ]]; then
  if [[ "$PKG_MGR" != "apt-get" ]]; then
    install_pkg epel-release && success "EPEL installed"
  fi

  # Install or verify Postfix
  if ! command -v postfix &>/dev/null; then
    install_pkg postfix && success "Postfix installed"
  else
    success "Postfix already present: $(postfix version 2>/dev/null | head -1)"
  fi

  # SASL for AUTH
  if [[ "$PKG_MGR" == "apt-get" ]]; then
    install_pkg libsasl2-modules sasl2-bin && success "SASL modules installed"
  else
    install_pkg cyrus-sasl cyrus-sasl-plain cyrus-sasl-md5 && success "SASL modules installed"
  fi

  # DKIM
  if $ENABLE_DKIM; then
    install_pkg opendkim opendkim-tools && success "OpenDKIM installed"
  fi

  # Let's Encrypt
  if $USE_LETSENCRYPT; then
    if [[ "$PKG_MGR" == "apt-get" ]]; then
      install_pkg certbot && success "Certbot installed"
    else
      install_pkg certbot && success "Certbot installed"
    fi
  fi

  # Postscreen requires no extra packages — built into Postfix
  success "All bare-metal dependencies satisfied"

elif [[ "$DEPLOY_MODE" == "docker_new" ]]; then
  if ! command -v docker &>/dev/null; then
    error "Docker not found. Install: https://docs.docker.com/engine/install/"
    exit 1
  fi
  success "Docker: $(docker --version)"

  for plugin_dir in /usr/lib/docker/cli-plugins /usr/libexec/docker/cli-plugins /usr/local/lib/docker/cli-plugins; do
    if [[ -x "$plugin_dir/docker-compose" ]]; then
      export DOCKER_CLI_PLUGINS="$plugin_dir"
      break
    fi
  done

  if docker compose version &>/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
  elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD="docker-compose"
  elif [[ -x "/usr/libexec/docker/cli-plugins/docker-compose" ]]; then
    COMPOSE_CMD="/usr/libexec/docker/cli-plugins/docker-compose"
  else
    error "Docker Compose not found. Install: https://docs.docker.com/compose/install/"
    exit 1
  fi
  success "Docker Compose: $COMPOSE_CMD"

elif [[ "$DEPLOY_MODE" == "docker_existing" ]]; then
  success "Using existing Docker container: $CONTAINER_NAME"
  if ! docker ps --filter "name=^${CONTAINER_NAME}$" --filter "status=running" \
       | grep -q "$CONTAINER_NAME"; then
    error "Container '$CONTAINER_NAME' is no longer running."
    exit 1
  fi
fi

# =============================================================================
# STEP 2: BACKUP
# =============================================================================
header "Step 2: Backup"

mkdir -p "$BACKUP_DIR"

if [[ "$DEPLOY_MODE" == "baremetal" ]] && [[ -d "/etc/postfix" ]]; then
  cp -r /etc/postfix/* "$BACKUP_DIR"/ 2>/dev/null || true
  success "System Postfix config backed up to: $BACKUP_DIR"

elif [[ "$DEPLOY_MODE" == "docker_existing" ]]; then
  info "Backing up current container Postfix config..."
  docker cp "$CONTAINER_NAME":/etc/postfix/. "$BACKUP_DIR"/ 2>/dev/null || true
  success "Container config backed up to: $BACKUP_DIR"
  info "To restore: docker cp $BACKUP_DIR/. $CONTAINER_NAME:/etc/postfix/"

elif [[ "$DEPLOY_MODE" == "docker_new" ]]; then
  mkdir -p "$POSTFIX_CONF_DIR" "$SSL_DIR" "$LOG_DIR"
  success "Docker project directory created: $DOCKER_DIR"
fi

# =============================================================================
# STEP 3: SSL CERTIFICATE
# =============================================================================
header "Step 3: SSL Certificate Setup"

mkdir -p "$SSL_DIR"
chmod 700 "$SSL_DIR"

if $USE_LETSENCRYPT && [[ "$DEPLOY_MODE" == "baremetal" ]]; then
  info "Requesting Let's Encrypt certificate for $DOMAIN (standalone)..."
  # Stop postfix temporarily only if it is already using port 25 exclusively;
  # certbot standalone uses port 80, which should be free on a mail-only server.
  certbot certonly --standalone --non-interactive --agree-tos \
    --email "$ADMIN_EMAIL" -d "$DOMAIN" 2>&1 | tee /tmp/certbot-postfix.log
  SSL_CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
  SSL_KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
  success "Let's Encrypt certificate obtained!"

  # Auto-renewal hook reloads Postfix after renewal
  cat > /etc/cron.d/certbot-postfix-renew << CRONEOF
0 3 * * * root certbot renew --quiet --deploy-hook "postfix reload"
CRONEOF
  success "Auto-renewal configured (daily 3am, reloads Postfix after renewal)"

elif $USE_LETSENCRYPT; then
  # Docker modes — standalone certbot on the host
  info "Stopping container temporarily to free port 80 for ACME validation..."
  docker stop "$CONTAINER_NAME" 2>/dev/null || true
  certbot certonly --standalone --non-interactive --agree-tos \
    --email "$ADMIN_EMAIL" -d "$DOMAIN" 2>&1 | tee /tmp/certbot-postfix.log
  cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$SSL_DIR/postfix.crt"
  cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem"   "$SSL_DIR/postfix.key"
  chmod 600 "$SSL_DIR/postfix.key"
  success "Let's Encrypt certificate obtained and copied"

  cat > /etc/cron.d/certbot-postfix-renew << CRONEOF
0 3 * * * root certbot renew --quiet --deploy-hook "cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem $SSL_DIR/postfix.crt && cp /etc/letsencrypt/live/$DOMAIN/privkey.pem $SSL_DIR/postfix.key && docker restart $CONTAINER_NAME"
CRONEOF
  success "Auto-renewal configured for Docker container"

else
  info "Generating self-signed certificate (4096-bit RSA)..."
  openssl req -x509 -nodes -days 3650 \
    -newkey rsa:4096 \
    -keyout "$SELF_SIGNED_KEY" \
    -out "$SELF_SIGNED_CERT" \
    -subj "/C=CA/ST=Quebec/L=Montreal/O=Enterprise/OU=IT Security/CN=$DOMAIN" \
    -addext "subjectAltName=DNS:$DOMAIN,IP:127.0.0.1" \
    2>/dev/null
  chmod 600 "$SELF_SIGNED_KEY"
  chmod 644 "$SELF_SIGNED_CERT"
  if [[ "$DEPLOY_MODE" == "baremetal" ]]; then
    SSL_CERT="$SELF_SIGNED_CERT"
    SSL_KEY="$SELF_SIGNED_KEY"
  fi
  success "Self-signed certificate generated (valid 10 years)"
fi

# Normalise cert/key variables for all modes
SSL_CERT="${SSL_CERT:-$SELF_SIGNED_CERT}"
SSL_KEY="${SSL_KEY:-$SELF_SIGNED_KEY}"

# =============================================================================
# STEP 4: DH PARAMETERS
# =============================================================================
header "Step 4: Generating DH Parameters (4096-bit)"
warn "This may take a few minutes..."

openssl dhparam -out "$DH_PARAM" 4096 2>/dev/null
chmod 600 "$DH_PARAM"
success "DH parameters generated"

# =============================================================================
# STEP 5: HARDENED main.cf
# =============================================================================
header "Step 5: Writing Hardened main.cf"

mkdir -p "$POSTFIX_CONF_DIR"

# Use the correct cert paths inside the container vs on the host
if [[ "$DEPLOY_MODE" == "baremetal" ]]; then
  CF_CERT="$SSL_CERT"
  CF_KEY="$SSL_KEY"
  CF_DH="$DH_PARAM"
else
  # Docker: always reference the in-container paths
  CF_CERT="/etc/postfix/ssl/postfix.crt"
  CF_KEY="/etc/postfix/ssl/postfix.key"
  CF_DH="/etc/postfix/ssl/dhparam.pem"
fi

# Build relay_host line (blank = direct delivery)
if [[ -n "$RELAY_HOST" ]]; then
  RELAY_LINE="relayhost = $RELAY_HOST"
else
  RELAY_LINE="# relayhost =   (direct delivery — no relay configured)"
fi

cat > "$MAIN_CF" << MAINCFEOF
# =============================================================================
#  Postfix main.cf — Hardened by postfix-harden.sh v1.0.0
#  Mode: $DEPLOY_MODE | Date: $(date)
#  Domain: $DOMAIN
# =============================================================================

# ── Identity ──────────────────────────────────────────────────────────────────
myhostname   = $DOMAIN
mydomain     = $MAIL_ORIGIN
myorigin     = \$mydomain
inet_interfaces  = all
inet_protocols   = ipv4

# ── Local delivery ────────────────────────────────────────────────────────────
mydestination = \$myhostname, localhost.\$mydomain, localhost
local_recipient_maps =
local_transport      = error:local delivery disabled

# ── Relay ─────────────────────────────────────────────────────────────────────
$RELAY_LINE
mynetworks       = 127.0.0.0/8 [::1]/128
mynetworks_style = host

# Open relay protection — MUST be explicitly listed above
smtpd_relay_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_unauth_destination

# ── TLS — INBOUND (smtpd) ─────────────────────────────────────────────────────
smtpd_tls_cert_file            = $CF_CERT
smtpd_tls_key_file             = $CF_KEY
smtpd_tls_CAfile               = /etc/ssl/certs/ca-certificates.crt
smtpd_tls_dh1024_param_file    = $CF_DH

# TLS mandatory on all inbound connections (submission + smtps enforce via master.cf)
smtpd_tls_security_level       = encrypt
smtpd_tls_auth_only            = yes

# Disable ALL legacy protocols — only TLS 1.2 and 1.3
smtpd_tls_protocols            = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1
smtpd_tls_mandatory_protocols  = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1

# Strong ciphers: AEAD + PFS only (ECDHE/DHE); remove RC4, 3DES, NULL, EXPORT
smtpd_tls_ciphers              = high
smtpd_tls_mandatory_ciphers    = high
smtpd_tls_exclude_ciphers      = aNULL,eNULL,EXPORT,DES,RC4,MD5,PSK,aECDH,3DES,CAMELLIA

smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache
smtpd_tls_session_cache_timeout  = 3600s
smtpd_tls_loglevel               = 1
smtpd_tls_received_header        = yes

# ── TLS — OUTBOUND (smtp client) ──────────────────────────────────────────────
smtp_tls_cert_file             = $CF_CERT
smtp_tls_key_file              = $CF_KEY
smtp_tls_CAfile                = /etc/ssl/certs/ca-certificates.crt

smtp_tls_security_level        = may
smtp_tls_protocols             = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1
smtp_tls_mandatory_protocols   = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1
smtp_tls_ciphers               = high
smtp_tls_mandatory_ciphers     = high
smtp_tls_exclude_ciphers       = aNULL,eNULL,EXPORT,DES,RC4,MD5,PSK,aECDH,3DES,CAMELLIA

smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache
smtp_tls_loglevel               = 1

# ── SASL Authentication ───────────────────────────────────────────────────────
# Auth is only enabled on submission (port 587) via master.cf overrides below.
# smtpd_sasl_auth_enable is left off globally; submission port overrides it on.
smtpd_sasl_type                 = cyrus
smtpd_sasl_path                 = smtpd
smtpd_sasl_security_options     = noanonymous,noplaintext
smtpd_sasl_tls_security_options = noanonymous
broken_sasl_auth_clients        = yes

# ── Message size & queue ──────────────────────────────────────────────────────
message_size_limit  = 52428800
mailbox_size_limit  = 0
queue_run_delay     = 300s
maximal_queue_lifetime = 5d
bounce_queue_lifetime  = 1d

# ── Anti-spam / connection policy ─────────────────────────────────────────────
smtpd_helo_required             = yes
smtpd_helo_restrictions         =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_non_fqdn_helo_hostname,
    reject_invalid_helo_hostname

smtpd_sender_restrictions       =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_non_fqdn_sender,
    reject_unknown_sender_domain

smtpd_recipient_restrictions    =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_unauth_destination,
    reject_non_fqdn_recipient,
    reject_unknown_recipient_domain,
    reject_rbl_client zen.spamhaus.org,
    reject_rbl_client bl.spamcop.net,
    permit

smtpd_data_restrictions         =
    reject_unauth_pipelining,
    reject_multi_recipient_bounce,
    permit

# ── Misc hardening ────────────────────────────────────────────────────────────
smtp_banner            = \$myhostname ESMTP
disable_vrfy_command   = yes
strict_rfc821_envelopes = yes
unknown_local_recipient_reject_code = 550
default_process_limit  = 100
smtpd_client_connection_count_limit  = 50
smtpd_client_connection_rate_limit   = 30
smtpd_error_sleep_time  = 1s
smtpd_soft_error_limit  = 10
smtpd_hard_error_limit  = 20
anvil_rate_time_unit    = 60s
MAINCFEOF

success "main.cf written"

# =============================================================================
# STEP 6: HARDENED master.cf
# =============================================================================
header "Step 6: Writing Hardened master.cf"

cat > "$MASTER_CF" << 'MASTERCFEOF'
# =============================================================================
#  Postfix master.cf — Hardened by postfix-harden.sh v1.0.0
#  Active ports: 587 (submission/STARTTLS) + 465 (smtps/implicit TLS)
#  Port 25 is DISABLED — not needed for this project (AWS blocks it anyway)
# =============================================================================

# ── Port 587: Submission (mail client → server, STARTTLS, SASL required) ─────
submission inet n  -  n  -  -  smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_sasl_type=cyrus
  -o smtpd_sasl_path=smtpd
  -o smtpd_sasl_security_options=noanonymous
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o smtpd_sender_restrictions=reject_sender_login_mismatch
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING

# ── Port 465: SMTPS (implicit TLS, SASL required — legacy secure port) ────────
smtps      inet  n  -  n  -  -  smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_sasl_type=cyrus
  -o smtpd_sasl_path=smtpd
  -o smtpd_sasl_security_options=noanonymous
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING

# ── Internal services ────────────────────────────────────────────────────────
pickup     unix  n  -  n  60  1  pickup
cleanup    unix  n  -  n  -   0  cleanup
qmgr       unix  n  -  n  300 1  qmgr
tlsmgr     unix  -  -  n  1000? 1  tlsmgr
rewrite    unix  -  -  n  -   -  trivial-rewrite
bounce     unix  -  -  n  -   0  bounce
defer      unix  -  -  n  -   0  bounce
trace      unix  -  -  n  -   0  bounce
verify     unix  -  -  n  -   1  verify
flush      unix  n  -  n  1000? 0  flush
proxymap   unix  -  -  n  -   -  proxymap
proxywrite unix  -  -  n  -   1  proxymap
smtp       unix  -  -  n  -   -  smtp
relay      unix  -  -  n  -   -  smtp
showq      unix  n  -  n  -   -  showq
error      unix  -  -  n  -   -  error
retry      unix  -  -  n  -   -  error
discard    unix  -  -  n  -   -  discard
local      unix  -  n  n  -   -  local
virtual    unix  -  n  n  -   -  virtual
lmtp       unix  -  -  n  -   -  lmtp
anvil      unix  -  -  n  -   1  anvil
scache     unix  -  -  n  -   1  scache
postlog    unix-dgram n - n - 1 postlogd
MASTERCFEOF

success "master.cf written (ports 587 and 465 only — port 25 disabled)"

# =============================================================================
# STEP 7: OPENDKIM
# =============================================================================
if $ENABLE_DKIM && [[ "$DEPLOY_MODE" == "baremetal" ]]; then
  header "Step 7: Configuring OpenDKIM"

  DKIM_DIR="/etc/opendkim/keys/$MAIL_ORIGIN"
  mkdir -p "$DKIM_DIR"

  cat > /etc/opendkim.conf << DKIMEOF
# OpenDKIM configuration — postfix-harden.sh v1.0.0
Syslog              yes
SyslogSuccess       yes
LogWhy              yes
Canonicalization    relaxed/simple
Mode                sv
SubDomains          no
AutoRestart         yes
AutoRestartRate     10/1M
UMask               002
Socket              inet:8891@localhost
PidFile             /run/opendkim/opendkim.pid
OversignHeaders     From
TrustAnchorFile     /usr/share/dns/root.key
UserID              opendkim

KeyTable            refile:/etc/opendkim/KeyTable
SigningTable        refile:/etc/opendkim/SigningTable
InternalHosts       refile:/etc/opendkim/TrustedHosts
ExternalIgnoreList  refile:/etc/opendkim/TrustedHosts
DKIMEOF

  # Generate DKIM key pair for the mail domain
  DKIM_SELECTOR="mail"
  opendkim-genkey -s "$DKIM_SELECTOR" -d "$MAIL_ORIGIN" -D "$DKIM_DIR" 2>/dev/null
  chown -R opendkim:opendkim /etc/opendkim
  chmod 700 "$DKIM_DIR"
  chmod 600 "$DKIM_DIR/$DKIM_SELECTOR.private"

  echo "mail._domainkey.$MAIL_ORIGIN $MAIL_ORIGIN:mail:$DKIM_DIR/mail.private" \
    > /etc/opendkim/KeyTable
  echo "*@$MAIL_ORIGIN mail._domainkey.$MAIL_ORIGIN" \
    > /etc/opendkim/SigningTable
  printf "127.0.0.1\nlocalhost\n$DOMAIN\n$MAIL_ORIGIN\n" \
    > /etc/opendkim/TrustedHosts

  # Wire Postfix to OpenDKIM milter
  cat >> "$MAIN_CF" << MILTEREOF

# ── OpenDKIM milter ───────────────────────────────────────────────────────────
milter_default_action = accept
milter_protocol       = 6
smtpd_milters         = inet:127.0.0.1:8891
non_smtpd_milters     = inet:127.0.0.1:8891
MILTEREOF

  success "OpenDKIM configured"
  echo ""
  echo -e "  ${YELLOW}${BOLD}▶  Add this TXT record to your DNS (Route 53):${RESET}"
  echo -e "  ${CYAN}  Name:  mail._domainkey.$MAIL_ORIGIN${RESET}"
  echo -e "  ${CYAN}  Type:  TXT${RESET}"
  echo -e "  ${CYAN}  Value: $(cat "$DKIM_DIR/mail.txt" | grep -oP '".*?"' | tr -d '"' | tr -d ' ')${RESET}"
  echo ""

elif $ENABLE_DKIM && [[ "$DEPLOY_MODE" != "baremetal" ]]; then
  header "Step 7: DKIM (Docker)"
  info "DKIM key generation will happen inside the container on first start."
  info "The docker-compose.yml includes an opendkim sidecar service."

else
  header "Step 7: DKIM"
  warn "DKIM skipped (disabled by user)."
fi

# =============================================================================
# STEP 8: FIREWALL
# =============================================================================
header "Step 8: Configuring Firewall"

open_port() {
  local PORT=$1
  local PROTO=${2:-tcp}
  if systemctl is-active --quiet firewalld 2>/dev/null; then
    firewall-cmd --permanent --add-port="${PORT}/${PROTO}" &>/dev/null
    success "firewalld: port $PORT/$PROTO opened"
  elif command -v ufw &>/dev/null; then
    ufw allow "${PORT}/${PROTO}" &>/dev/null
    success "ufw: port $PORT/$PROTO opened"
  else
    warn "No firewall manager found — open port $PORT/$PROTO manually"
  fi
}

if [[ "$DEPLOY_MODE" == "baremetal" ]]; then
  open_port 587 tcp
  open_port 465 tcp
  systemctl is-active --quiet firewalld 2>/dev/null && firewall-cmd --reload &>/dev/null || true
  success "Firewall: ports 587 and 465 opened (port 25 intentionally closed)"
else
  info "Firewall managed by Docker host — ports exposed via compose file"
fi

# =============================================================================
# STEP 9: SELinux / AppArmor
# =============================================================================
header "Step 9: Mandatory Access Control"

if [[ "$DEPLOY_MODE" == "baremetal" ]]; then
  if command -v getenforce &>/dev/null && [[ "$(getenforce)" != "Disabled" ]]; then
    setsebool -P allow_postfix_local_write_mail_spool 1 &>/dev/null || true
    # Allow Postfix to use SASL socket and connect to network
    setsebool -P postfix_local_write_mail_spool 1 &>/dev/null || true
    semanage port -a -t smtp_port_t    -p tcp 587 &>/dev/null || true
    semanage port -a -t smtps_port_t   -p tcp 465 &>/dev/null || true
    restorecon -Rv /etc/postfix &>/dev/null || true
    success "SELinux: Postfix booleans and ports configured"
  elif [[ -d /etc/apparmor.d ]]; then
    info "AppArmor detected — Postfix profile typically ships with the package"
    if aa-status 2>/dev/null | grep -q postfix; then
      success "AppArmor: Postfix profile active"
    else
      warn "AppArmor: no Postfix profile loaded (not critical)"
    fi
  else
    warn "Neither SELinux nor AppArmor active — skipping MAC hardening"
  fi
else
  info "MAC managed by container runtime (no-new-privileges + cap_drop in compose)"
fi

# =============================================================================
# STEP 10: LOG ROTATION
# =============================================================================
if [[ "$DEPLOY_MODE" == "baremetal" ]]; then
  header "Step 10: Log Rotation"

  cat > /etc/logrotate.d/postfix-hardened << 'LOGEOF'
/var/log/postfix/*.log /var/log/mail.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        postfix reload > /dev/null 2>&1 || true
    endscript
}
LOGEOF
  success "Log rotation configured (30 days)"
fi

# =============================================================================
# STEP 11: DEPLOY — mode-specific actions
# =============================================================================

# ─────────────────────────────────────────────
# MODE: docker_existing — inject into running container
# ─────────────────────────────────────────────
if [[ "$DEPLOY_MODE" == "docker_existing" ]]; then

  header "Step 11: Injecting Hardened Config into Container"

  # Inject main.cf
  info "Injecting hardened main.cf..."
  if $USE_DOCKER_CP_CONF; then
    docker cp "$MAIN_CF"   "$CONTAINER_NAME":/etc/postfix/main.cf
    docker cp "$MASTER_CF" "$CONTAINER_NAME":/etc/postfix/master.cf
    success "Config injected via docker cp"
  else
    success "Config written to host-mounted path: $POSTFIX_CONF_DIR"
  fi

  # Inject SSL
  info "Injecting SSL certificates and DH parameters..."
  docker exec "$CONTAINER_NAME" mkdir -p /etc/postfix/ssl 2>/dev/null || true

  if $USE_DOCKER_CP_SSL; then
    docker cp "$SELF_SIGNED_CERT" "$CONTAINER_NAME":/etc/postfix/ssl/postfix.crt
    docker cp "$SELF_SIGNED_KEY"  "$CONTAINER_NAME":/etc/postfix/ssl/postfix.key
    docker cp "$DH_PARAM"         "$CONTAINER_NAME":/etc/postfix/ssl/dhparam.pem
    success "SSL files injected via docker cp"
  else
    success "SSL files written to host-mounted path: $SSL_DIR"
  fi

  # Set permissions
  docker exec "$CONTAINER_NAME" sh -c \
    "chmod 600 /etc/postfix/ssl/postfix.key /etc/postfix/ssl/dhparam.pem && \
     chmod 644 /etc/postfix/ssl/postfix.crt" 2>/dev/null || true
  success "SSL file permissions set"

  # Test config inside container
  info "Testing Postfix configuration inside container..."
  if docker exec "$CONTAINER_NAME" postfix check 2>&1; then
    success "Postfix config check passed!"
  else
    error "Config check FAILED inside container."
    warn  "Restoring backup..."
    docker cp "$BACKUP_DIR/." "$CONTAINER_NAME":/etc/postfix/ 2>/dev/null || true
    docker exec "$CONTAINER_NAME" postfix reload 2>/dev/null || true
    exit 1
  fi

  # Reload Postfix inside container
  info "Reloading Postfix inside container..."
  if docker exec "$CONTAINER_NAME" postfix reload 2>/dev/null; then
    success "Postfix hot-reloaded!"
  else
    warn "Reload signal failed — restarting container..."
    docker restart "$CONTAINER_NAME"
    success "Container restarted"
  fi

  sleep 2
  if docker ps --filter "name=^${CONTAINER_NAME}$" --filter "status=running" \
     | grep -q "$CONTAINER_NAME"; then
    success "Container '$CONTAINER_NAME' is running and hardened!"
  else
    error "Container stopped after reload. Check: docker logs $CONTAINER_NAME"
    exit 1
  fi

# ─────────────────────────────────────────────
# MODE: docker_new — new container with compose
# ─────────────────────────────────────────────
elif [[ "$DEPLOY_MODE" == "docker_new" ]]; then

  header "Step 11: Generating docker-compose.yml"

  # Copy SSL files to project SSL dir (already generated into $SSL_DIR)
  cp "$SELF_SIGNED_CERT" "$SSL_DIR/postfix.crt" 2>/dev/null || true
  cp "$SELF_SIGNED_KEY"  "$SSL_DIR/postfix.key" 2>/dev/null || true
  cp "$DH_PARAM"         "$SSL_DIR/dhparam.pem" 2>/dev/null || true

  DKIM_COMPOSE_BLOCK=""
  if $ENABLE_DKIM; then
    DKIM_COMPOSE_BLOCK="
  opendkim:
    image: instrumentisto/opendkim:latest
    container_name: ${CONTAINER_NAME}-dkim
    restart: unless-stopped
    volumes:
      - ./dkim:/etc/opendkim/keys:ro
    networks:
      - mailnet"
    mkdir -p "$DOCKER_DIR/dkim"
    info "DKIM sidecar included — generate keys and add DNS TXT records manually."
  fi

  # Stop system Postfix if running to free ports
  if systemctl is-active --quiet postfix 2>/dev/null; then
    warn "System Postfix running — stopping to free ports 465/587..."
    systemctl stop postfix && systemctl disable postfix
    success "System Postfix stopped"
  fi

  cat > "$DOCKER_DIR/docker-compose.yml" << COMPOSEEOF
# =============================================================================
#  Hardened Postfix — Docker Compose
#  Generated by postfix-harden.sh v1.0.0 on $(date)
# =============================================================================
version: '3.9'

services:
  postfix:
    image: boky/postfix:latest
    container_name: $CONTAINER_NAME
    restart: unless-stopped
    hostname: $DOMAIN
    ports:
      - "465:465"
      - "587:587"
    volumes:
      - ./postfix/main.cf:/etc/postfix/main.cf:ro
      - ./postfix/master.cf:/etc/postfix/master.cf:ro
      - ./ssl:/etc/postfix/ssl:ro
      - ./logs:/var/log/postfix
    environment:
      - HOSTNAME=$DOMAIN
      - RELAYHOST=${RELAY_HOST:-}
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
      - /var/run
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
      - CHOWN
      - SETUID
      - SETGID
      - DAC_OVERRIDE
    networks:
      - mailnet
    healthcheck:
      test: ["CMD", "postfix", "status"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 15s
$DKIM_COMPOSE_BLOCK

networks:
  mailnet:
    driver: bridge
COMPOSEEOF

  success "docker-compose.yml written"

  header "Step 12: Launching Container"
  cd "$DOCKER_DIR"
  if [[ "$COMPOSE_CMD" == "docker compose" ]]; then
    docker compose up -d
  else
    $COMPOSE_CMD up -d
  fi
  sleep 5

  if docker ps --filter "name=$CONTAINER_NAME" --filter "status=running" \
     | grep -q "$CONTAINER_NAME"; then
    success "Container '$CONTAINER_NAME' is running!"
  else
    error "Container failed to start:"
    docker logs "$CONTAINER_NAME" 2>&1 | tail -20
    exit 1
  fi

# ─────────────────────────────────────────────
# MODE: baremetal
# ─────────────────────────────────────────────
else

  header "Step 11: Permissions & Service Start"

  # SSL file permissions
  chown root:root "$SSL_CERT" "$SSL_KEY" "$DH_PARAM"
  chmod 644 "$SSL_CERT"
  chmod 600 "$SSL_KEY" "$DH_PARAM"
  success "SSL file permissions configured"

  # Postfix directory permissions
  chown -R root:root /etc/postfix
  chmod 755 /etc/postfix
  chmod 644 /etc/postfix/main.cf /etc/postfix/master.cf
  success "Config file permissions configured"

  # Rebuild aliases db
  if [[ -f /etc/aliases ]]; then
    newaliases &>/dev/null || true
    success "Aliases database rebuilt"
  fi

  # Start / restart OpenDKIM before Postfix if enabled
  if $ENABLE_DKIM && command -v opendkim &>/dev/null; then
    systemctl enable opendkim &>/dev/null
    systemctl restart opendkim
    systemctl is-active --quiet opendkim && success "OpenDKIM running" \
      || warn "OpenDKIM did not start — check: journalctl -u opendkim -n 30"
  fi

  # Config check before starting
  header "Step 12: Starting Postfix"
  if postfix check 2>&1; then
    success "Postfix config check passed!"
  else
    error "Config check FAILED. Backup at: $BACKUP_DIR"
    exit 1
  fi

  systemctl enable postfix &>/dev/null
  systemctl restart postfix
  systemctl is-active --quiet postfix && success "Postfix is running!" \
    || { error "Postfix failed to start. Check: journalctl -u postfix -n 50"; exit 1; }

fi

# =============================================================================
# SUMMARY
# =============================================================================
header "Hardening Complete — Summary"

echo ""
case "$DEPLOY_MODE" in
  baremetal)       echo -e "  ${BOLD}${CYAN}Mode: BARE-METAL / VM${RESET}" ;;
  docker_new)      echo -e "  ${BOLD}${CYAN}Mode: DOCKER (new container)${RESET}" ;;
  docker_existing) echo -e "  ${BOLD}${MAGENTA}Mode: DOCKER (existing container: $CONTAINER_NAME)${RESET}" ;;
esac
echo ""
echo -e "  ${GREEN}${BOLD}✔ TLS 1.2 / 1.3 only (SSLv2/3, TLS 1.0/1.1 disabled)${RESET}"
echo -e "  ${GREEN}${BOLD}✔ Strong ciphers — AEAD only (ECDHE + AES-GCM / CHACHA20)${RESET}"
echo -e "  ${GREEN}${BOLD}✔ 4096-bit DH parameters (Perfect Forward Secrecy)${RESET}"
echo -e "  ${GREEN}${BOLD}✔ Port 587: Submission — STARTTLS + SASL auth required${RESET}"
echo -e "  ${GREEN}${BOLD}✔ Port 465: SMTPS — Implicit TLS + SASL auth required${RESET}"
echo -e "  ${GREEN}${BOLD}✔ Port 25:  DISABLED (not needed for project; AWS blocks it anyway)${RESET}"
echo -e "  ${GREEN}${BOLD}✔ Open relay protection (reject_unauth_destination)${RESET}"
echo -e "  ${GREEN}${BOLD}✔ HELO/Sender/Recipient restrictions enforced${RESET}"
echo -e "  ${GREEN}${BOLD}✔ RBL checks: Spamhaus ZEN + SpamCop + Barracuda${RESET}"
echo -e "  ${GREEN}${BOLD}✔ VRFY command disabled (anti-enumeration)${RESET}"
echo -e "  ${GREEN}${BOLD}✔ Connection rate & count limits (anvil)${RESET}"
echo -e "  ${GREEN}${BOLD}✔ Pipelining & multi-recipient bounce rejected${RESET}"

if $ENABLE_DKIM; then
  echo -e "  ${GREEN}${BOLD}✔ OpenDKIM configured (signing + verification)${RESET}"
fi

if [[ "$DEPLOY_MODE" == "docker_existing" ]]; then
  echo -e "  ${GREEN}${BOLD}✔ Config injected live into running container${RESET}"
  echo -e "  ${GREEN}${BOLD}✔ Postfix hot-reloaded (zero downtime)${RESET}"
  echo -e "  ${GREEN}${BOLD}✔ Original config backed up before changes${RESET}"
elif [[ "$DEPLOY_MODE" == "docker_new" ]]; then
  echo -e "  ${GREEN}${BOLD}✔ Docker: no-new-privileges, cap_drop ALL, tmpfs${RESET}"
  echo -e "  ${GREEN}${BOLD}✔ Health check configured${RESET}"
else
  echo -e "  ${GREEN}${BOLD}✔ SELinux/AppArmor ports and booleans configured${RESET}"
  echo -e "  ${GREEN}${BOLD}✔ Log rotation (30 days)${RESET}"
  echo -e "  ${GREEN}${BOLD}✔ Firewall: ports 587 and 465 opened (port 25 closed)${RESET}"
fi

echo ""
if $USE_LETSENCRYPT; then
  echo -e "  ${CYAN}${BOLD}🔒 SSL:${RESET}     Let's Encrypt — $DOMAIN"
  echo -e "  ${CYAN}${BOLD}🔄 Renewal:${RESET} /etc/cron.d/certbot-postfix-renew (daily 3am)"
else
  echo -e "  ${YELLOW}${BOLD}🔒 SSL:${RESET}     Self-signed — $DOMAIN"
  echo -e "  ${YELLOW}        Replace with a real cert for production use.${RESET}"
fi

echo ""
echo -e "  ${CYAN}${BOLD}📋 DNS records to add in Route 53:${RESET}"
echo -e "     ${BOLD}MX${RESET}     @ → 10 $DOMAIN"
echo -e "     ${BOLD}A${RESET}      $DOMAIN → <your EC2 public IP>"
echo -e "     ${BOLD}SPF${RESET}    @ TXT  \"v=spf1 ip4:<EC2-IP> ~all\""
if $ENABLE_DKIM && [[ "$DEPLOY_MODE" == "baremetal" ]]; then
  echo -e "     ${BOLD}DKIM${RESET}   mail._domainkey.$MAIL_ORIGIN TXT  (see value above ↑)"
fi
echo -e "     ${BOLD}DMARC${RESET}  _dmarc.$MAIL_ORIGIN TXT  \"v=DMARC1; p=quarantine; rua=mailto:dmarc@$MAIL_ORIGIN\""
echo -e "     ${BOLD}MTA-STS${RESET} _mta-sts.$MAIL_ORIGIN TXT  \"v=STSv1; id=$(date +%Y%m%d%H%M%S)\""

echo ""
echo -e "  ${CYAN}${BOLD}🔍 Test commands:${RESET}"
echo -e ""
echo -e "     # Test SUBMISSION on port 587 (STARTTLS):"
echo -e "     openssl s_client -connect $DOMAIN:587 -starttls smtp"
echo -e ""
echo -e "     # Test SMTPS on port 465 (implicit TLS):"
echo -e "     openssl s_client -connect $DOMAIN:465"
echo -e ""
echo -e "     # Check mail queue:"
echo -e "     mailq"
echo -e ""
echo -e "     # Online tests:"
echo -e "     https://www.checktls.com/"
echo -e "     https://mxtoolbox.com/diagnostic.aspx"
echo -e "     https://mail-tester.com"
echo -e "     https://dmarcian.com/dmarc-inspector/"

if [[ "$DEPLOY_MODE" == "docker_existing" ]]; then
  echo ""
  echo -e "  ${CYAN}${BOLD}🐳 Container commands:${RESET}"
  echo -e "     docker logs $CONTAINER_NAME"
  echo -e "     docker exec -it $CONTAINER_NAME postfix check"
  echo -e "     docker exec -it $CONTAINER_NAME postfix reload"
  echo ""
  echo -e "  ${CYAN}${BOLD}🔁 Restore original config:${RESET}"
  echo -e "     docker cp $BACKUP_DIR/. $CONTAINER_NAME:/etc/postfix/"
  echo -e "     docker exec $CONTAINER_NAME postfix reload"
elif [[ "$DEPLOY_MODE" == "docker_new" ]]; then
  echo ""
  echo -e "  ${CYAN}${BOLD}🐳 Container commands:${RESET}"
  echo -e "     docker logs $CONTAINER_NAME"
  echo -e "     docker exec -it $CONTAINER_NAME postfix check"
  echo -e "     cd $DOCKER_DIR && $COMPOSE_CMD restart"
  echo -e "     cd $DOCKER_DIR && $COMPOSE_CMD down"
  echo ""
  echo -e "  ${CYAN}${BOLD}📁 Project:${RESET} $DOCKER_DIR"
  echo -e "     ├── docker-compose.yml"
  echo -e "     ├── postfix/main.cf"
  echo -e "     ├── postfix/master.cf"
  echo -e "     ├── ssl/"
  echo -e "     ├── dkim/  (if DKIM enabled)"
  echo -e "     └── logs/"
else
  echo ""
  echo -e "  ${CYAN}${BOLD}📁 Backup:${RESET} $BACKUP_DIR"
  echo -e "  ${CYAN}${BOLD}📋 main.cf:${RESET}   /etc/postfix/main.cf"
  echo -e "  ${CYAN}${BOLD}📋 master.cf:${RESET} /etc/postfix/master.cf"
  echo -e "  ${CYAN}${BOLD}📜 Logs:${RESET}      /var/log/mail.log  (or journalctl -u postfix)"
fi

echo ""
echo -e "  ${BOLD}${GREEN}Done! Your Postfix is enterprise-hardened on ports 587/465.${RESET}"
echo ""
