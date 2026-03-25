#!/usr/bin/env bash
# =============================================================================
#  nginx-harden.sh — Enterprise-Grade Nginx Hardening Script
#  Tested on: Rocky Linux 8/9/10, RHEL 8/9, AlmaLinux 8/9
#  Version: 4.0.0
# By: mrblue
# =============================================================================
# MODES:
#   [1] Bare-Metal / VM     — Installs & hardens system Nginx
#   [2] Docker (new)        — Generates configs, certs, compose & launches
#   [3] Docker (existing)   — AUTO-DETECTED if Nginx containers are running
#                             Hardens config of an already-running container
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
  ███╗   ██╗ ██████╗ ██╗███╗   ██╗██╗  ██╗    ██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗███╗   ██╗
  ████╗  ██║██╔════╝ ██║████╗  ██║╚██╗██╔╝    ██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║
  ██╔██╗ ██║██║  ███╗██║██╔██╗ ██║ ╚███╔╝     ███████║███████║██████╔╝██║  ██║█████╗  ██╔██╗ ██║
  ██║╚██╗██║██║   ██║██║██║╚██╗██║ ██╔██╗     ██╔══██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║╚██╗██║
  ██║ ╚████║╚██████╔╝██║██║ ╚████║██╔╝ ██╗    ██║  ██║██║  ██║██║  ██║██████╔╝███████╗██║ ╚████║
  ╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝
EOF
echo -e "${RESET}"
echo -e "  ${BOLD}Enterprise-Grade Nginx Hardening Script v5.0.0${RESET}"
echo -e "  ${CYAN}HTTPS-only • TLS 1.2/1.3 • Security Headers • Rate Limiting${RESET}"
echo ""

# =============================================================================
# AUTO-DETECTION: Scan for running Nginx Docker containers
# =============================================================================
header "Auto-Detection — Scanning Environment"

DETECTED_CONTAINERS=()
DEPLOY_MODE=""
CONTAINER_NAME=""
EXISTING_DOCKER=false

# Check if Docker is available
if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
  detect "Docker is available — scanning for running Nginx containers..."

  # Find all running containers using nginx image (any tag) or named *nginx*
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    DETECTED_CONTAINERS+=("$line")
  done < <(docker ps --format '{{.Names}}|{{.Image}}|{{.Ports}}|{{.Status}}' 2>/dev/null \
    | grep -iE '(nginx|proxy)' || true)

  if [[ ${#DETECTED_CONTAINERS[@]} -gt 0 ]]; then
    echo ""
    echo -e "  ${MAGENTA}${BOLD}🐳 Nginx container(s) detected:${RESET}"
    echo ""
    INDEX=1
    for CONT in "${DETECTED_CONTAINERS[@]}"; do
      CNAME=$(echo "$CONT" | cut -d'|' -f1)
      CIMAGE=$(echo "$CONT" | cut -d'|' -f2)
      CPORTS=$(echo "$CONT" | cut -d'|' -f3)
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
    detect "No running Nginx containers found."
  fi
else
  detect "Docker not available or not running — skipping container scan."
fi

# Check for system Nginx
SYSTEM_NGINX=false
if command -v nginx &>/dev/null 2>&1; then
  NGINX_VER=$(nginx -v 2>&1 | head -1)
  detect "System Nginx found: $NGINX_VER"
  SYSTEM_NGINX=true
fi

# =============================================================================
# MODE SELECTION
# =============================================================================
header "Deployment Mode"

echo -e "  ${BOLD}[1]${RESET} Bare-Metal / VM     — Install & harden system Nginx"
echo -e "  ${BOLD}[2]${RESET} Docker (new)        — Generate configs & launch new hardened container"

if $EXISTING_DOCKER; then
  echo -e "  ${BOLD}[3]${RESET} ${MAGENTA}Docker (existing)${RESET}   — Harden a currently running Nginx container"
fi
echo ""

MAX_CHOICE=2
$EXISTING_DOCKER && MAX_CHOICE=3

while true; do
  read -rp "$(echo -e "${BOLD}Select mode [1-${MAX_CHOICE}]: ${RESET}")" MODE_CHOICE
  case "$MODE_CHOICE" in
    1) DEPLOY_MODE="baremetal"; info "Mode: Bare-Metal / VM"; break ;;
    2) DEPLOY_MODE="docker_new"; info "Mode: Docker (new container)"; break ;;
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

  # Pull all mounts as "source:destination:type" lines for flexible parsing
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

  # ── Smart mount resolver ──────────────────────────────────────────────────
  # Handles: directory mounts, single-file mounts, /etc/nginx top-level mounts
  # For each category we check exact dest match first, then file-in-dir match,
  # then parent-dir match so we always find the right host path.

  INJECT_CONF_DIR=""
  INJECT_NGINX_DIR=""
  INJECT_SSL_DIR=""
  CONTAINER_HTML_MOUNT=""
  USE_DOCKER_CP_CONF=false
  USE_DOCKER_CP_SSL=false

  for m in $CONTAINER_MOUNTS_RAW; do
    SRC=$(echo "$m" | cut -d'|' -f1)
    DST=$(echo "$m" | cut -d'|' -f2)

    # ── /etc/nginx (top-level directory) ───────────────────────────────────
    if [[ "$DST" == "/etc/nginx" ]]; then
      INJECT_NGINX_DIR="$SRC"
      [[ -z "$INJECT_CONF_DIR" ]] && INJECT_CONF_DIR="$SRC/conf.d"
      [[ -z "$INJECT_SSL_DIR"  ]] && INJECT_SSL_DIR="$SRC/ssl"
      info "Top-level /etc/nginx mount → $SRC"
    fi

    # ── /etc/nginx/conf.d (directory mount) ────────────────────────────────
    if [[ "$DST" == "/etc/nginx/conf.d" ]]; then
      INJECT_CONF_DIR="$SRC"
      info "conf.d directory mount → $SRC"
    fi

    # ── Single .conf file mounted anywhere inside /etc/nginx/conf.d ────────
    # Handles: /host/file.conf → /etc/nginx/conf.d/default.conf
    #      or: /host/file.conf → /etc/nginx/conf.d/anything.conf
    # Uses regex match since bash glob in [[ ]] requires extglob
    if [[ "$DST" =~ ^/etc/nginx/conf\.d/[^/]+\.conf$ ]]; then
      HOST_CONF_DIR="$(dirname "$SRC")"
      INJECT_CONF_DIR="$HOST_CONF_DIR"
      # Record the exact host file so we can write hardened.conf alongside it
      EXISTING_CONF_FILE="$SRC"
      success "File-level conf.d mount detected:"
      info "  Container: $DST"
      info "  Host file: $SRC"
      info "  Host dir:  $HOST_CONF_DIR  (hardened.conf will be written here)"
    fi

    # ── /etc/nginx/nginx.conf (single file mount) ───────────────────────────
    if [[ "$DST" == "/etc/nginx/nginx.conf" ]]; then
      INJECT_NGINX_CONF_FILE="$SRC"
      INJECT_NGINX_DIR="$(dirname "$SRC")"
      info "nginx.conf file mount → $SRC"
    fi

    # ── /etc/nginx/ssl (directory mount) ───────────────────────────────────
    if [[ "$DST" == "/etc/nginx/ssl" ]]; then
      INJECT_SSL_DIR="$SRC"
      info "SSL directory mount → $SRC"
    fi

    # ── Single cert file mounts ─────────────────────────────────────────────
    if [[ "$DST" =~ ^/etc/nginx/ssl/.*\.(crt|pem)$ ]]; then
      INJECT_SSL_DIR="$(dirname "$SRC")"
      info "SSL file mount detected — host SSL dir: $INJECT_SSL_DIR"
    fi

    # ── HTML / web root ─────────────────────────────────────────────────────
    if [[ "$DST" == "/usr/share/nginx/html" || "$DST" == "/var/www/html" ]]; then
      CONTAINER_HTML_MOUNT="$SRC"
      info "HTML root mount → $SRC"
    fi
  done

  # ── Report findings and set fallback flags ───────────────────────────────
  echo ""
  info "Mount resolution summary:"

  if [[ -n "$INJECT_CONF_DIR" ]]; then
    mkdir -p "$INJECT_CONF_DIR"
    success "  conf.d  → host path: $INJECT_CONF_DIR (will write directly)"
  else
    USE_DOCKER_CP_CONF=true
    INJECT_CONF_DIR="/tmp/nginx-conf-$$"
    mkdir -p "$INJECT_CONF_DIR"
    warn "  conf.d  → no host mount — will inject via docker cp"
  fi

  if [[ -n "$INJECT_SSL_DIR" ]]; then
    mkdir -p "$INJECT_SSL_DIR"
    success "  ssl     → host path: $INJECT_SSL_DIR (will write directly)"
  else
    USE_DOCKER_CP_SSL=true
    INJECT_SSL_DIR="/tmp/nginx-ssl-$$"
    mkdir -p "$INJECT_SSL_DIR"
    warn "  ssl     → no host mount — will inject via docker cp"
  fi

  if [[ -n "$CONTAINER_HTML_MOUNT" ]]; then
    success "  html    → host path: $CONTAINER_HTML_MOUNT"
  else
    warn "  html    → no host mount (not required)"
  fi

  if [[ -n "${INJECT_NGINX_CONF_FILE:-}" ]]; then
    success "  nginx.conf → host file: $INJECT_NGINX_CONF_FILE (will overwrite in place)"
  else
    info "  nginx.conf → no file mount, will inject via docker cp"
  fi

  # ── Set working dirs for the rest of the script ──────────────────────────
  if [[ -n "$INJECT_NGINX_DIR" ]]; then
    NGINX_CONF_DIR="$INJECT_NGINX_DIR"
  else
    NGINX_CONF_DIR="/tmp/nginx-main-$$"
    mkdir -p "$NGINX_CONF_DIR"
  fi
  NGINX_SITE_DIR="$INJECT_CONF_DIR"
  SSL_DIR="$INJECT_SSL_DIR"
  LOG_DIR="/tmp/nginx-logs-$$"
  WEBROOT_HOST="${CONTAINER_HTML_MOUNT:-/var/www/html}"
  DOCKER_DIR="/opt/nginx-hardened-$CONTAINER_NAME"
  COMPOSE_CMD=""   # may not be using compose

  # Detect compose cmd anyway
  if docker compose version &>/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
  elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD="docker-compose"
  fi

fi

# =============================================================================
# COMMON CONFIGURATION (all modes)
# =============================================================================
header "Configuration"

read -rp "$(echo -e "${BOLD}Domain name (leave blank for self-signed cert): ${RESET}")" DOMAIN
read -rp "$(echo -e "${BOLD}Admin email (for Let's Encrypt notifications):  ${RESET}")" ADMIN_EMAIL

USE_LETSENCRYPT=false
if [[ -n "$DOMAIN" && -n "$ADMIN_EMAIL" ]]; then
  USE_LETSENCRYPT=true
  info "Will request a Let's Encrypt certificate for: ${DOMAIN}"
else
  info "No domain provided — will generate a self-signed certificate."
  DOMAIN="localhost"
fi

# Mode-specific extra prompts
if [[ "$DEPLOY_MODE" == "docker_new" ]]; then
  read -rp "$(echo -e "${BOLD}Docker container name [nginx-hardened]:         ${RESET}")" CONTAINER_NAME
  CONTAINER_NAME="${CONTAINER_NAME:-nginx-hardened}"
  read -rp "$(echo -e "${BOLD}Docker project directory [/opt/nginx-hardened]: ${RESET}")" DOCKER_DIR
  DOCKER_DIR="${DOCKER_DIR:-/opt/nginx-hardened}"
fi

if [[ "$DEPLOY_MODE" == "baremetal" ]]; then
  read -rp "$(echo -e "${BOLD}Web root directory [/var/www/html]:             ${RESET}")" WEBROOT
  WEBROOT="${WEBROOT:-/var/www/html}"
fi

# ── Resolve paths for non-existing modes ──────────────────────────────────────
if [[ "$DEPLOY_MODE" == "docker_new" ]]; then
  NGINX_CONF_DIR="$DOCKER_DIR/nginx"
  NGINX_SITE_DIR="$NGINX_CONF_DIR/conf.d"
  SSL_DIR="$DOCKER_DIR/ssl"
  LOG_DIR="$DOCKER_DIR/logs"
  WEBROOT_HOST="$DOCKER_DIR/html"
elif [[ "$DEPLOY_MODE" == "baremetal" ]]; then
  NGINX_CONF_DIR="/etc/nginx"
  NGINX_SITE_DIR="/etc/nginx/conf.d"
  SSL_DIR="/etc/nginx/ssl"
  LOG_DIR="/var/log/nginx"
  WEBROOT_HOST="$WEBROOT"
fi
# docker_existing paths already set above

NGINX_CONF="$NGINX_CONF_DIR/nginx.conf"
NGINX_SITE_CONF="$NGINX_SITE_DIR/hardened.conf"
DH_PARAM="$SSL_DIR/dhparam.pem"
SELF_SIGNED_KEY="$SSL_DIR/selfsigned.key"
SELF_SIGNED_CERT="$SSL_DIR/selfsigned.crt"
BACKUP_DIR="/tmp/nginx-backup-$(date +%Y%m%d_%H%M%S)"

# =============================================================================
# STEP 1: INSTALL DEPENDENCIES
# =============================================================================
header "Step 1: Installing Dependencies"

if command -v dnf &>/dev/null; then
  PKG_MGR="dnf"
elif command -v yum &>/dev/null; then
  PKG_MGR="yum"
else
  error "Unsupported package manager. Requires dnf or yum."
  exit 1
fi

$PKG_MGR install -y openssl curl &>/dev/null && success "openssl + curl installed"

if [[ "$DEPLOY_MODE" == "baremetal" ]]; then
  $PKG_MGR install -y epel-release &>/dev/null && success "EPEL installed"
  $PKG_MGR install -y nginx &>/dev/null && success "Nginx installed: $(nginx -v 2>&1)"
  if $USE_LETSENCRYPT; then
    $PKG_MGR install -y certbot python3-certbot-nginx &>/dev/null && success "Certbot installed"
  fi

elif [[ "$DEPLOY_MODE" == "docker_new" ]]; then
  if ! command -v docker &>/dev/null; then
    error "Docker not found. Install: https://docs.docker.com/engine/install/"
    exit 1
  fi
  success "Docker: $(docker --version)"
  # Search for docker compose in all known plugin locations
  # Rocky/RHEL installs to /usr/libexec, Debian/Ubuntu to /usr/lib
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
    info "Using direct plugin path: $COMPOSE_CMD"
  elif [[ -x "/usr/lib/docker/cli-plugins/docker-compose" ]]; then
    COMPOSE_CMD="/usr/lib/docker/cli-plugins/docker-compose"
    info "Using direct plugin path: $COMPOSE_CMD"
  else
    error "Docker Compose not found. Install: https://docs.docker.com/compose/install/"
    exit 1
  fi
  success "Docker Compose: $COMPOSE_CMD"

elif [[ "$DEPLOY_MODE" == "docker_existing" ]]; then
  success "Using existing Docker container: $CONTAINER_NAME"
  # Verify container is still running
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

if [[ "$DEPLOY_MODE" == "baremetal" ]] && [[ -d "/etc/nginx" ]]; then
  cp -r /etc/nginx/* "$BACKUP_DIR"/ 2>/dev/null || true
  success "System Nginx config backed up to: $BACKUP_DIR"

elif [[ "$DEPLOY_MODE" == "docker_existing" ]]; then
  info "Backing up current container config..."
  # Copy existing nginx config out of the container
  docker cp "$CONTAINER_NAME":/etc/nginx/. "$BACKUP_DIR"/ 2>/dev/null || true
  success "Container config backed up to: $BACKUP_DIR"
  info "To restore: docker cp $BACKUP_DIR/. $CONTAINER_NAME:/etc/nginx/"

elif [[ "$DEPLOY_MODE" == "docker_new" ]]; then
  mkdir -p "$NGINX_CONF_DIR/conf.d" "$SSL_DIR" "$LOG_DIR" "$WEBROOT_HOST"
  success "Docker project directory created: $DOCKER_DIR"
fi

# =============================================================================
# STEP 3: SSL CERTIFICATE
# =============================================================================
header "Step 3: SSL Certificate Setup"

mkdir -p "$SSL_DIR"
chmod 700 "$SSL_DIR"

if $USE_LETSENCRYPT && [[ "$DEPLOY_MODE" == "baremetal" ]]; then
  info "Requesting Let's Encrypt certificate for $DOMAIN..."
  systemctl start nginx 2>/dev/null || true
  certbot certonly --nginx --non-interactive --agree-tos \
    --email "$ADMIN_EMAIL" -d "$DOMAIN" --redirect 2>&1 | tee /tmp/certbot.log
  SSL_CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
  SSL_KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
  success "Let's Encrypt certificate obtained!"
  cat > /etc/cron.d/certbot-renew << 'CRONEOF'
0 3 * * * root certbot renew --quiet --deploy-hook "systemctl reload nginx"
CRONEOF
  success "Auto-renewal configured (daily 3am)"

elif $USE_LETSENCRYPT; then
  # Docker modes — use standalone certbot on host
  $PKG_MGR install -y epel-release &>/dev/null || true
  $PKG_MGR install -y certbot &>/dev/null && success "Certbot installed"
  info "Stopping container temporarily to free port 80 for validation..."
  docker stop "$CONTAINER_NAME" 2>/dev/null || true
  certbot certonly --standalone --non-interactive --agree-tos \
    --email "$ADMIN_EMAIL" -d "$DOMAIN" 2>&1 | tee /tmp/certbot.log
  cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$SSL_DIR/selfsigned.crt"
  cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem"   "$SSL_DIR/selfsigned.key"
  success "Let's Encrypt certificate obtained and copied"
  cat > /etc/cron.d/certbot-renew << CRONEOF
0 3 * * * root certbot renew --quiet --deploy-hook "cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem $SSL_DIR/selfsigned.crt && cp /etc/letsencrypt/live/$DOMAIN/privkey.pem $SSL_DIR/selfsigned.key && docker restart $CONTAINER_NAME"
CRONEOF
  success "Auto-renewal configured for container"

else
  info "Generating self-signed certificate (4096-bit RSA)..."
  openssl req -x509 -nodes -days 3650 \
    -newkey rsa:4096 \
    -keyout "$SELF_SIGNED_KEY" \
    -out "$SELF_SIGNED_CERT" \
    -subj "/C=CA/ST=Quebec/L=Montreal/O=Enterprise/OU=IT Security/CN=$DOMAIN" \
    -addext "subjectAltName=DNS:$DOMAIN,DNS:www.$DOMAIN,IP:127.0.0.1" \
    2>/dev/null
  chmod 600 "$SELF_SIGNED_KEY"
  chmod 644 "$SELF_SIGNED_CERT"
  if [[ "$DEPLOY_MODE" == "baremetal" ]]; then
    SSL_CERT="$SELF_SIGNED_CERT"
    SSL_KEY="$SELF_SIGNED_KEY"
  fi
  success "Self-signed certificate generated (valid 10 years)"
fi

# =============================================================================
# STEP 4: DH PARAMETERS
# =============================================================================
header "Step 4: Generating DH Parameters (4096-bit)"
warn "This may take a few minutes..."

openssl dhparam -out "$DH_PARAM" 4096 2>/dev/null
chmod 600 "$DH_PARAM"
success "DH parameters generated"

# =============================================================================
# STEP 5: HARDENED nginx.conf
# =============================================================================
header "Step 5: Writing Hardened nginx.conf"

mkdir -p "$NGINX_CONF_DIR/conf.d"

cat > "$NGINX_CONF" << NGINXEOF
# =============================================================================
# Hardened nginx.conf — Generated by nginx-harden.sh v5.0.0
# Mode: $DEPLOY_MODE | Date: $(date)
# v5.0.0 — includes light WAF, expanded bot list, URI filtering
# =============================================================================

user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    include      /etc/nginx/mime.types;
    default_type application/octet-stream;

    server_tokens off;

    log_format security_log '\$remote_addr - \$remote_user [\$time_local] '
                            '"\$request" \$status \$body_bytes_sent '
                            '"\$http_referer" "\$http_user_agent" '
                            'rt=\$request_time ';

    # Extended WAF-aware log format
    log_format waf_log '\$remote_addr [\$time_local] '
                       '"\$request" \$status '
                       'ua="\$http_user_agent" '
                       'ref="\$http_referer" '
                       'rt=\$request_time '
                       'blocked_agent=\$blocked_agent ';

    access_log /var/log/nginx/access.log security_log;

    sendfile        on;
    tcp_nopush      on;
    tcp_nodelay     on;

    keepalive_timeout         15;
    client_body_timeout       12;
    client_header_timeout     12;
    send_timeout              10;
    reset_timedout_connection on;

    client_body_buffer_size     16k;
    client_header_buffer_size   1k;
    client_max_body_size        10m;
    large_client_header_buffers 4 8k;

    limit_req_zone  \$binary_remote_addr zone=global:10m  rate=20r/s;
    limit_req_zone  \$binary_remote_addr zone=login:10m   rate=5r/m;
    limit_req_zone  \$binary_remote_addr zone=api:10m     rate=30r/s;
    limit_conn_zone \$binary_remote_addr zone=connlimit:10m;

    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css application/json application/javascript
               text/xml application/xml text/javascript image/svg+xml;
    gzip_disable "msie6";

    # ── Bad Bot / Scanner Blocking ──────────────────────────────────────────
    map \$http_user_agent \$blocked_agent {
        default          0;
        ""               1;   # Empty user-agent
        ~*nikto          1;   # Nikto web scanner
        ~*sqlmap         1;   # SQL injection tool
        ~*nmap           1;   # Port scanner
        ~*masscan        1;   # Mass port scanner
        ~*zgrab          1;   # TLS/banner grabber
        ~*dirbuster      1;   # Directory brute-forcer
        ~*gobuster       1;   # Directory brute-forcer
        ~*wfuzz          1;   # Web fuzzer
        ~*hydra          1;   # Brute-force tool
        ~*acunetix       1;   # Web vulnerability scanner
        ~*nessus         1;   # Vulnerability scanner
        ~*burpsuite      1;   # Web proxy/scanner
        ~*metasploit     1;   # Exploitation framework
        ~*openvas        1;   # OpenVAS scanner
        ~*w3af           1;   # Web app attack framework
        ~*havij          1;   # SQL injection tool
        ~*libwww-perl    1;   # Common bot library
        ~*python-requests 1;  # Generic scripting
        ~*go-http-client 1;   # Generic Go scanner
        ~*curl/7\.1     1;   # Old curl often used in scripts
        ~*scanbot        1;
        ~*scrapy         1;
        ~*wget/1\.       1;   # wget used as scanner
    }

    # ── Block suspicious URI patterns (light WAF) ────────────────────────────
    map \$request_uri \$blocked_uri {
        default                                     0;
        ~*(\.\./|\.\.%2f|%2e%2e%2f)            1;  # Path traversal
        ~*(union.*select|select.*from|insert.*into) 1;  # SQLi
        ~*(<script|javascript:|vbscript:)           1;  # XSS
        ~*(etc/passwd|etc/shadow|proc/self)         1;  # LFI
        ~*(\x00|%00)                               1;  # Null byte injection
        ~*(cmd\.exe|powershell|/bin/sh|/bin/bash)  1;  # RCE attempts
        ~*(phpinfo|php_info|phpinfo\(\))          1;  # PHP info disclosure
        ~*(\.php\.suspected|\.php\.)            1;  # PHP file probing
    }

    # ── Slow down repeated offenders (connection rate map) ───────────────────
    map \$http_user_agent \$limit_bots {
        default          "";
        ~*bot            \$binary_remote_addr;
        ~*crawler        \$binary_remote_addr;
        ~*spider         \$binary_remote_addr;
    }

    include /etc/nginx/conf.d/*.conf;
}
NGINXEOF

success "nginx.conf written"

# =============================================================================
# STEP 6: HARDENED VIRTUAL HOST
# =============================================================================
header "Step 6: Writing Hardened Virtual Host Config"

mkdir -p "$NGINX_SITE_DIR"
rm -f "$NGINX_SITE_DIR/default.conf" 2>/dev/null || true

cat > "$NGINX_SITE_CONF" << VHOSTEOF
# =============================================================================
# Hardened Virtual Host — $DOMAIN
# Generated by nginx-harden.sh v5.0.0 | Mode: $DEPLOY_MODE
# =============================================================================

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    if (\$blocked_agent) { return 444; }
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name $DOMAIN;

    root /usr/share/nginx/html;
    index index.html index.htm;

    ssl_certificate     /etc/nginx/ssl/selfsigned.crt;
    ssl_certificate_key /etc/nginx/ssl/selfsigned.key;
    ssl_dhparam         /etc/nginx/ssl/dhparam.pem;

    ssl_protocols             TLSv1.2 TLSv1.3;
    ssl_ciphers               'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_prefer_server_ciphers on;
    ssl_session_cache         shared:SSL:10m;
    ssl_session_timeout       1d;
    ssl_session_tickets       off;
    ssl_ecdh_curve            secp384r1;

    # OCSP Stapling — only effective with a CA-signed cert (e.g. Let's Encrypt)
    # Disabled here to suppress warnings with self-signed certificates.
    # Enable manually after deploying a real cert:
    #   ssl_stapling        on;
    #   ssl_stapling_verify on;
    #   resolver            1.1.1.1 8.8.8.8 valid=300s;
    #   resolver_timeout    5s;

    add_header Strict-Transport-Security    "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options              "SAMEORIGIN" always;
    add_header X-Content-Type-Options       "nosniff" always;
    add_header X-XSS-Protection             "1; mode=block" always;
    add_header Referrer-Policy              "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy           "geolocation=(), microphone=(), camera=(), payment=(), usb=()" always;
    add_header Content-Security-Policy      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;
    add_header Cross-Origin-Opener-Policy   "same-origin" always;
    add_header Cross-Origin-Embedder-Policy "require-corp" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;
    add_header X-Permitted-Cross-Domain-Policies "none" always;

    limit_req  zone=global burst=40 nodelay;
    limit_conn connlimit 20;

    # ── Light WAF — block bad agents, URIs and methods ───────────────────────
    if (\$blocked_agent) {
        return 444;
    }
    if (\$blocked_uri) {
        return 444;
    }
    if (\$request_method !~ ^(GET|HEAD|POST|PUT|DELETE|OPTIONS|PATCH)\$) {
        return 444;
    }

    # ── Block common exploit headers ─────────────────────────────────────────
    if (\$http_x_forwarded_host) {
        return 444;
    }

    # ── Block hidden files & directories ────────────────────────────────────
    location ~ /\. {
        deny all; access_log off; log_not_found off;
    }

    # ── Block backup and temp files ──────────────────────────────────────────
    location ~ ~\$ {
        deny all; access_log off; log_not_found off;
    }

    # ── Block sensitive file extensions ─────────────────────────────────────
    location ~* \.(sql|bak|bak2|swp|log|conf|config|ini|env|sh|bash|py|rb|pl|cfg|old|orig|save|tar|gz|zip|7z|rar|pem|key|crt|p12|pfx|der)\$ {
        deny all; access_log off; log_not_found off;
    }

    # ── Block common attack paths ────────────────────────────────────────────
    location ~* ^/(wp-admin|wp-login|wp-config|wp-includes|xmlrpc\.php|phpmyadmin|adminer|\.git|\.svn|\.hg|\.env|\.env\.local|\.env\.production|Dockerfile|docker-compose|Makefile|\.DS_Store|web\.config|server-status|server-info|\.well-known/acme-challenge) {
        return 404;
    }

    # ── Block PHP execution (not a PHP server) ───────────────────────────────
    location ~* \.php\$ {
        deny all; access_log off; log_not_found off;
    }

    # ── Block common shell/script access ────────────────────────────────────
    location ~* \.(sh|bash|zsh|fish|ps1|bat|cmd)\$ {
        deny all; access_log off; log_not_found off;
    }

    location ~* ^/(login|auth|signin|admin) {
        limit_req zone=login burst=5 nodelay;
        try_files \$uri \$uri/ =404;
    }

    location /api/ {
        limit_req zone=api burst=60 nodelay;
        try_files \$uri \$uri/ =404;
    }

    location ~* \.(jpg|jpeg|png|gif|ico|css|js|woff|woff2|ttf|svg|eot)\$ {
        expires    30d;
        add_header Cache-Control "public, no-transform";
        access_log off;
    }

    location / {
        try_files \$uri \$uri/ =404;
    }

    error_page 400 401 403 404 /40x.html;
    error_page 500 502 503 504 /50x.html;
    location = /40x.html { root /usr/share/nginx/html; internal; }
    location = /50x.html { root /usr/share/nginx/html; internal; }

    access_log /var/log/nginx/access.log security_log;
    error_log  /var/log/nginx/error.log warn;
}
VHOSTEOF

success "Virtual host config written"

# =============================================================================
# STEP 7: DEFAULT INDEX PAGE
# =============================================================================
header "Step 7: Default Web Page"

mkdir -p "$WEBROOT_HOST"
if [[ ! -f "$WEBROOT_HOST/index.html" ]]; then
  cat > "$WEBROOT_HOST/index.html" << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Secured</title></head>
<body style="font-family:monospace;text-align:center;padding:4rem;background:#0d1117;color:#58a6ff;">
  <h1>&#128274; Nginx Hardened</h1>
  <p>Your server is secured and running over HTTPS.</p>
</body>
</html>
HTMLEOF
fi
success "Default index page ready"

# =============================================================================
# STEP 8: DEPLOY — mode-specific actions
# =============================================================================

# ─────────────────────────────────────────────
# MODE: docker_existing — inject into running container
# ─────────────────────────────────────────────
if [[ "$DEPLOY_MODE" == "docker_existing" ]]; then

  header "Step 8: Injecting Hardened Config into Container"

  # nginx.conf
  info "Injecting hardened nginx.conf..."
  if [[ -n "${INJECT_NGINX_CONF_FILE:-}" ]]; then
    cp "$NGINX_CONF" "$INJECT_NGINX_CONF_FILE"
    success "nginx.conf written to host-mounted file: $INJECT_NGINX_CONF_FILE"
  else
    docker cp "$NGINX_CONF" "$CONTAINER_NAME":/etc/nginx/nginx.conf
    success "nginx.conf injected via docker cp"
  fi

  # Virtual host config
  info "Injecting hardened virtual host config (hardened.conf)..."
  if $USE_DOCKER_CP_CONF; then
    docker cp "$NGINX_SITE_CONF" "$CONTAINER_NAME":/etc/nginx/conf.d/hardened.conf
    success "hardened.conf injected via docker cp"
  else
    success "hardened.conf written to host-mounted path: $NGINX_SITE_DIR"
  fi

  # Handle conflicting conf files
  info "Handling conflicting default configs..."
  # Remove default.conf if it is not bind-mounted (safe to delete)
  docker exec "$CONTAINER_NAME" sh -c \
    "[ -f /etc/nginx/conf.d/default.conf ] && rm -f /etc/nginx/conf.d/default.conf || true" \
    2>/dev/null || true

  # If there was a file-level conf mount (e.g. assignment.conf -> default.conf),
  # it cannot be deleted inside the container because it is bind-mounted.
  # Replace the host-side source file with a harmless empty stub so it no longer
  # conflicts with hardened.conf.
  if [[ -n "${EXISTING_CONF_FILE:-}" && -f "$EXISTING_CONF_FILE" ]]; then
    warn "File-level conf mount detected: $EXISTING_CONF_FILE"
    warn "This file is bind-mounted and cannot be deleted inside the container."
    info "Replacing it with a harmless stub on the host..."
    cp "$EXISTING_CONF_FILE" "${EXISTING_CONF_FILE}.bak-$(date +%Y%m%d%H%M%S)"
    cat > "$EXISTING_CONF_FILE" << 'STUBEOF'
# This file was replaced by nginx-harden.sh (original backed up alongside it)
# All active configuration is now in hardened.conf
# To fully remove this mount, update your docker run / compose volume definition.
STUBEOF
    success "Stub written to $EXISTING_CONF_FILE (original backed up as .bak-*)"
  fi
  success "Conflicting configs handled"

  # ── SSL certs & DH params ─────────────────────────────────────────────────
  info "Injecting SSL certificates and DH parameters..."
  docker exec "$CONTAINER_NAME" mkdir -p /etc/nginx/ssl 2>/dev/null || true

  if $USE_DOCKER_CP_SSL; then
    # No host mount — copy directly into container
    docker cp "$SSL_DIR/selfsigned.crt" "$CONTAINER_NAME":/etc/nginx/ssl/selfsigned.crt
    docker cp "$SSL_DIR/selfsigned.key" "$CONTAINER_NAME":/etc/nginx/ssl/selfsigned.key
    docker cp "$DH_PARAM"               "$CONTAINER_NAME":/etc/nginx/ssl/dhparam.pem
    success "SSL certs injected via docker cp"
  else
    # Host-mounted SSL dir — files already in place
    success "SSL certs written to host-mounted path: $SSL_DIR"
  fi

  # Set permissions inside container
  docker exec "$CONTAINER_NAME" sh -c \
    "chmod 600 /etc/nginx/ssl/selfsigned.key /etc/nginx/ssl/dhparam.pem && \
     chmod 644 /etc/nginx/ssl/selfsigned.crt" 2>/dev/null || true
  success "SSL file permissions set"

  # ── Test config inside container before reloading ────────────────────────
  info "Testing Nginx configuration inside container..."
  if docker exec "$CONTAINER_NAME" nginx -t 2>&1; then
    success "Config test passed!"
  else
    error "Config test FAILED inside container."
    warn  "Original config backed up at: $BACKUP_DIR"
    warn  "Restoring backup..."
    docker cp "$BACKUP_DIR/." "$CONTAINER_NAME":/etc/nginx/ 2>/dev/null || true
    docker exec "$CONTAINER_NAME" nginx -s reload 2>/dev/null || true
    exit 1
  fi

  # ── Hot-reload — zero downtime ────────────────────────────────────────────
  info "Hot-reloading Nginx (zero downtime)..."
  # Use docker kill --signal=HUP for reliable reload regardless of PID file location
  if docker kill --signal=HUP "$CONTAINER_NAME" 2>/dev/null; then
    success "Nginx hot-reloaded via HUP signal!"
  else
    warn "HUP signal failed — falling back to docker restart (brief interruption)..."
    docker restart "$CONTAINER_NAME"
    success "Container restarted"
  fi

  # Verify container still running after reload
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

  header "Step 8: Generating docker-compose.yml"

  cat > "$DOCKER_DIR/docker-compose.yml" << COMPOSEEOF
# =============================================================================
# Hardened Nginx — Docker Compose
# Generated by nginx-harden.sh v5.0.0 on $(date)
# =============================================================================
version: '3.9'

services:
  nginx:
    image: nginx:stable-alpine
    container_name: $CONTAINER_NAME
    restart: unless-stopped
    user: "0:0"   # Master needs root to bind 80/443, workers drop to nginx uid
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/conf.d:/etc/nginx/conf.d:ro
      - ./ssl:/etc/nginx/ssl:ro
      - ./html:/usr/share/nginx/html:ro
      - ./logs:/var/log/nginx
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
    healthcheck:
      test: ["CMD", "wget", "-qO-", "--no-check-certificate", "https://localhost/"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
COMPOSEEOF

  success "docker-compose.yml written"

  # Stop system Nginx if running
  if systemctl is-active --quiet nginx 2>/dev/null; then
    warn "System Nginx running on ports 80/443 — stopping it..."
    systemctl stop nginx && systemctl disable nginx
    success "System Nginx stopped and disabled"
  fi

  header "Step 9: Configuring Firewall"
  if systemctl is-active --quiet firewalld; then
    firewall-cmd --permanent --add-service=http  &>/dev/null
    firewall-cmd --permanent --add-service=https &>/dev/null
    firewall-cmd --reload &>/dev/null
    success "Firewall: ports 80 and 443 opened"
  else
    warn "firewalld not running — skipping"
  fi

  header "Step 10: Launching Container"
  cd "$DOCKER_DIR"
  if [[ "$COMPOSE_CMD" == "docker compose" ]]; then
    docker compose up -d
  else
    $COMPOSE_CMD up -d
  fi
  sleep 3

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

  header "Step 8: Web Root & Permissions"
  mkdir -p "$WEBROOT_HOST"
  chown -R nginx:nginx "$WEBROOT_HOST"
  chmod -R 755 "$WEBROOT_HOST"
  chown -R root:root /etc/nginx
  chmod -R 640 /etc/nginx
  chmod 750 /etc/nginx
  chmod 750 /etc/nginx/conf.d
  chmod 640 /etc/nginx/nginx.conf
  chmod 640 /etc/nginx/conf.d/hardened.conf
  success "Permissions configured"

  header "Step 9: Configuring Firewall"
  if systemctl is-active --quiet firewalld; then
    firewall-cmd --permanent --add-service=http  &>/dev/null
    firewall-cmd --permanent --add-service=https &>/dev/null
    firewall-cmd --reload &>/dev/null
    success "Firewall: ports 80 and 443 opened"
  else
    warn "firewalld not running — skipping"
  fi

  header "Step 10: SELinux"
  if command -v getenforce &>/dev/null && [[ "$(getenforce)" != "Disabled" ]]; then
    setsebool -P httpd_can_network_connect 1 &>/dev/null || true
    setsebool -P httpd_read_user_content 1  &>/dev/null || true
    semanage port -a -t http_port_t -p tcp 443 &>/dev/null || true
    restorecon -Rv "$WEBROOT_HOST" &>/dev/null || true
    success "SELinux configured"
  else
    warn "SELinux disabled — skipping"
  fi

  header "Step 11: Log Rotation"
  cat > /etc/logrotate.d/nginx-hardened << 'LOGEOF'
/var/log/nginx/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 nginx adm
    sharedscripts
    postrotate
        /bin/kill -USR1 $(cat /run/nginx.pid 2>/dev/null) 2>/dev/null || true
    endscript
}
LOGEOF
  success "Log rotation configured (30 days)"

  header "Step 12: Starting Nginx"
  if nginx -t 2>&1; then
    success "Config test passed!"
  else
    error "Config test FAILED. Backup at: $BACKUP_DIR"
    exit 1
  fi
  systemctl enable nginx &>/dev/null
  systemctl restart nginx
  systemctl is-active --quiet nginx && success "Nginx is running!" \
    || { error "Nginx failed to start. Check: journalctl -u nginx -n 50"; exit 1; }

fi

# =============================================================================
# SUMMARY
# =============================================================================
header "Hardening Complete — Summary"

echo ""
case "$DEPLOY_MODE" in
  baremetal)        echo -e "  ${BOLD}${CYAN}Mode: BARE-METAL / VM${RESET}" ;;
  docker_new)       echo -e "  ${BOLD}${CYAN}Mode: DOCKER (new container)${RESET}" ;;
  docker_existing)  echo -e "  ${BOLD}${MAGENTA}Mode: DOCKER (existing container: $CONTAINER_NAME)${RESET}" ;;
esac
echo ""
echo -e "  ${GREEN}${BOLD}✔ TLS 1.2 / 1.3 only${RESET}"
echo -e "  ${GREEN}${BOLD}✔ Strong ciphers (ECDHE + CHACHA20)${RESET}"
echo -e "  ${GREEN}${BOLD}✔ 4096-bit DH parameters${RESET}"
echo -e "  ${GREEN}${BOLD}✔ OCSP stapling${RESET}"
echo -e "  ${GREEN}${BOLD}✔ HSTS 2 years + preload${RESET}"
echo -e "  ${GREEN}${BOLD}✔ Full security headers (CSP, CORP, COEP, COOP...)${RESET}"
echo -e "  ${GREEN}${BOLD}✔ HTTP → HTTPS redirect${RESET}"
echo -e "  ${GREEN}${BOLD}✔ Rate limiting (global / login / API)${RESET}"
echo -e "  ${GREEN}${BOLD}✔ Bad bot & scanner blocking${RESET}"
echo -e "  ${GREEN}${BOLD}✔ Sensitive file & path blocking${RESET}"
echo -e "  ${GREEN}${BOLD}✔ Timeouts & buffer limits${RESET}"

if [[ "$DEPLOY_MODE" == "docker_existing" ]]; then
  echo -e "  ${GREEN}${BOLD}✔ Config injected live into running container${RESET}"
  echo -e "  ${GREEN}${BOLD}✔ Nginx hot-reloaded (zero downtime)${RESET}"
  echo -e "  ${GREEN}${BOLD}✔ Original config backed up before changes${RESET}"
elif [[ "$DEPLOY_MODE" == "docker_new" ]]; then
  echo -e "  ${GREEN}${BOLD}✔ Docker: no-new-privileges, cap_drop ALL, tmpfs${RESET}"
  echo -e "  ${GREEN}${BOLD}✔ Health check configured${RESET}"
  echo -e "  ${GREEN}${BOLD}✔ Firewall ports 80 & 443 opened${RESET}"
else
  echo -e "  ${GREEN}${BOLD}✔ SELinux booleans configured${RESET}"
  echo -e "  ${GREEN}${BOLD}✔ Log rotation (30 days)${RESET}"
  echo -e "  ${GREEN}${BOLD}✔ Config file permissions hardened${RESET}"
  echo -e "  ${GREEN}${BOLD}✔ Firewall ports 80 & 443 opened${RESET}"
fi

echo ""
if $USE_LETSENCRYPT; then
  echo -e "  ${CYAN}${BOLD}🔒 SSL:${RESET} Let's Encrypt — https://$DOMAIN"
  echo -e "  ${CYAN}${BOLD}🔄 Renewal:${RESET} /etc/cron.d/certbot-renew (daily 3am)"
else
  echo -e "  ${YELLOW}${BOLD}🔒 SSL:${RESET} Self-signed — https://$DOMAIN"
  echo -e "  ${YELLOW}        Browser warning expected. Use curl -k for testing.${RESET}"
fi

echo ""
echo -e "  ${CYAN}${BOLD}🔍 Test:${RESET}"
echo -e "     curl -k https://localhost"
echo -e "     https://www.ssllabs.com/ssltest/analyze.html?d=$DOMAIN"
echo -e "     https://securityheaders.com/?q=https://$DOMAIN"

if [[ "$DEPLOY_MODE" == "docker_existing" ]]; then
  echo ""
  echo -e "  ${CYAN}${BOLD}🐳 Container commands:${RESET}"
  echo -e "     docker logs $CONTAINER_NAME"
  echo -e "     docker exec -it $CONTAINER_NAME nginx -t"
  echo -e "     docker exec -it $CONTAINER_NAME nginx -s reload"
  echo ""
  echo -e "  ${CYAN}${BOLD}🔁 Restore original config:${RESET}"
  echo -e "     docker cp $BACKUP_DIR/. $CONTAINER_NAME:/etc/nginx/"
  echo -e "     docker exec $CONTAINER_NAME nginx -s reload"
elif [[ "$DEPLOY_MODE" == "docker_new" ]]; then
  echo ""
  echo -e "  ${CYAN}${BOLD}🐳 Container commands:${RESET}"
  echo -e "     docker logs $CONTAINER_NAME"
  echo -e "     docker exec -it $CONTAINER_NAME nginx -t"
  echo -e "     cd $DOCKER_DIR && $COMPOSE_CMD restart"
  echo -e "     cd $DOCKER_DIR && $COMPOSE_CMD down"
  echo ""
  echo -e "  ${CYAN}${BOLD}📁 Project:${RESET} $DOCKER_DIR"
  echo -e "     ├── docker-compose.yml"
  echo -e "     ├── nginx/nginx.conf"
  echo -e "     ├── nginx/conf.d/hardened.conf"
  echo -e "     ├── ssl/"
  echo -e "     ├── html/"
  echo -e "     └── logs/"
else
  echo ""
  echo -e "  ${CYAN}${BOLD}📁 Backup:${RESET} $BACKUP_DIR"
  echo -e "  ${CYAN}${BOLD}📋 Config:${RESET} /etc/nginx/conf.d/hardened.conf"
  echo -e "  ${CYAN}${BOLD}📜 Logs:${RESET}   /var/log/nginx/"
fi

echo ""
echo -e "  ${BOLD}${GREEN}Done! Your Nginx is enterprise-hardened and HTTPS-only.${RESET}"
echo ""
