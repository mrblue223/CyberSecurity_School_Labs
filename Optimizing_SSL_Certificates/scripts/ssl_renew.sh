#!/usr/bin/env bash
# =============================================================================
#  ssl-renew.sh — Automated SSL Certificate Renewal Script
#  Handles: Let's Encrypt renewal for Nginx + Postfix
#  Methods: DNS-01 via AWS Route 53 (recommended) | HTTP-01 standalone
#  Supports: Bare-Metal & Docker (auto-detected)
#  Version: 2.0.0
# =============================================================================
# HOW IT WORKS:
#   1. Auto-detects running services (Nginx, Postfix, Docker containers)
#   2. Checks current certificate expiry for each domain
#   3. Renews if expiry is within the threshold (default: 30 days)
#   4. Reloads services automatically after renewal
#   5. Copies renewed certs to Docker container paths if needed
#   6. Sends a summary report (optional — if ALERT_EMAIL is set)
#   7. Installs automation via CRON -or- SYSTEMD timer (your choice)
#
# SCHEDULER OPTIONS (prompted during setup):
#   [1] Cron job   — classic /etc/cron.d entry, runs daily at 03:15 AM
#   [2] Systemd    — ssl-renew.service + ssl-renew.timer, configurable interval
#                    Advantages: journald logging, dependency tracking,
#                    auto-restart on failure, OnCalendar scheduling
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
   ██████╗███████╗██████╗ ████████╗    ██████╗ ███████╗███╗   ██╗███████╗██╗    ██╗ █████╗ ██╗
  ██╔════╝██╔════╝██╔══██╗╚══██╔══╝    ██╔══██╗██╔════╝████╗  ██║██╔════╝██║    ██║██╔══██╗██║
  ██║     █████╗  ██████╔╝   ██║       ██████╔╝█████╗  ██╔██╗ ██║█████╗  ██║ █╗ ██║███████║██║
  ██║     ██╔══╝  ██╔══██╗   ██║       ██╔══██╗██╔══╝  ██║╚██╗██║██╔══╝  ██║███╗██║██╔══██║██║
  ╚██████╗███████╗██║  ██║   ██║       ██║  ██║███████╗██║ ╚████║███████╗╚███╔███╔╝██║  ██║███████╗
   ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝       ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝
EOF
echo -e "${RESET}"
echo -e "  ${BOLD}SSL Certificate Renewal Script v2.0.0${RESET}"
echo -e "  ${CYAN}Let's Encrypt • DNS-01 (Route 53) • Cron or Systemd • Nginx & Postfix${RESET}"
echo ""

# =============================================================================
# CONFIGURATION — edit these or pass as environment variables
# =============================================================================

# Days before expiry to trigger renewal (Let's Encrypt recommends 30)
RENEW_THRESHOLD="${RENEW_THRESHOLD:-30}"

# Challenge method: dns-route53 | standalone | nginx
# dns-route53 is strongly recommended — no port conflicts, works for all services
CHALLENGE_METHOD="${CHALLENGE_METHOD:-dns-route53}"

# Optional: email address for renewal failure alerts (leave blank to disable)
ALERT_EMAIL="${ALERT_EMAIL:-}"

# Log file
LOG_FILE="${LOG_FILE:-/var/log/ssl-renew.log}"

# Docker SSL dirs (where certs are copied after renewal)
NGINX_DOCKER_SSL_DIR="${NGINX_DOCKER_SSL_DIR:-/opt/nginx-hardened/ssl}"
POSTFIX_DOCKER_SSL_DIR="${POSTFIX_DOCKER_SSL_DIR:-/opt/postfix-hardened/ssl}"

# =============================================================================
# LOGGING SETUP
# =============================================================================
mkdir -p "$(dirname "$LOG_FILE")"
exec > >(tee -a "$LOG_FILE") 2>&1
echo ""
echo "========================================"
echo "  ssl-renew.sh run: $(date)"
echo "========================================"

# =============================================================================
# TRACKING VARIABLES
# =============================================================================
RENEWED_DOMAINS=()
SKIPPED_DOMAINS=()
FAILED_DOMAINS=()
NGINX_NEEDS_RELOAD=false
POSTFIX_NEEDS_RELOAD=false
NGINX_CONTAINER=""
POSTFIX_CONTAINER=""

# =============================================================================
# HELPER: get days until a certificate expires
# =============================================================================
cert_days_left() {
  local DOMAIN="$1"
  local CERT_PATH="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"

  if [[ ! -f "$CERT_PATH" ]]; then
    echo "-1"
    return
  fi

  local EXPIRY
  EXPIRY=$(openssl x509 -enddate -noout -in "$CERT_PATH" 2>/dev/null \
    | cut -d= -f2)

  if [[ -z "$EXPIRY" ]]; then
    echo "-1"
    return
  fi

  local EXPIRY_EPOCH NOW_EPOCH
  EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null \
    || date -j -f "%b %d %T %Y %Z" "$EXPIRY" +%s 2>/dev/null || echo 0)
  NOW_EPOCH=$(date +%s)

  echo $(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
}

# =============================================================================
# HELPER: send alert email if ALERT_EMAIL is set
# =============================================================================
send_alert() {
  local SUBJECT="$1"
  local BODY="$2"

  if [[ -z "$ALERT_EMAIL" ]]; then
    return
  fi

  if command -v mail &>/dev/null; then
    echo "$BODY" | mail -s "$SUBJECT" "$ALERT_EMAIL" 2>/dev/null \
      && info "Alert email sent to $ALERT_EMAIL" \
      || warn "Failed to send alert email"
  elif command -v sendmail &>/dev/null; then
    printf "Subject: %s\n\n%s" "$SUBJECT" "$BODY" \
      | sendmail "$ALERT_EMAIL" 2>/dev/null || warn "sendmail alert failed"
  else
    warn "No mail command found — cannot send alert to $ALERT_EMAIL"
  fi
}

# =============================================================================
# STEP 1: INSTALL / VERIFY DEPENDENCIES
# =============================================================================
header "Step 1: Verifying Dependencies"

# Package manager detection
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

# Certbot
if ! command -v certbot &>/dev/null; then
  warn "Certbot not found — installing..."
  if [[ "$PKG_MGR" != "apt-get" ]]; then
    install_pkg epel-release &>/dev/null || true
  fi
  install_pkg certbot
  success "Certbot installed: $(certbot --version 2>&1 | head -1)"
else
  success "Certbot found: $(certbot --version 2>&1 | head -1)"
fi

# DNS-01 Route 53 plugin
if [[ "$CHALLENGE_METHOD" == "dns-route53" ]]; then
  if ! python3 -c "import certbot_dns_route53" &>/dev/null 2>&1; then
    warn "certbot-dns-route53 plugin not found — installing..."
    if [[ "$PKG_MGR" == "apt-get" ]]; then
      install_pkg python3-certbot-dns-route53
    else
      install_pkg python3-certbot-dns-route53 || \
        pip3 install certbot-dns-route53 &>/dev/null
    fi
    success "certbot-dns-route53 plugin installed"
  else
    success "certbot-dns-route53 plugin: available"
  fi

  # Check AWS credentials
  if [[ -f /root/.aws/credentials ]] || [[ -n "${AWS_ACCESS_KEY_ID:-}" ]]; then
    success "AWS credentials: found"
  elif curl -s --max-time 2 \
       "http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
       &>/dev/null; then
    success "AWS credentials: using EC2 IAM instance role"
  else
    warn "AWS credentials not found — DNS-01 challenge may fail"
    warn "Set up IAM role on EC2 or create /root/.aws/credentials"
    warn "Required IAM permissions: route53:ListHostedZones, route53:GetChange,"
    warn "  route53:ChangeResourceRecordSets"
  fi
fi

# openssl
if command -v openssl &>/dev/null; then
  success "openssl: $(openssl version)"
else
  install_pkg openssl && success "openssl installed"
fi

# =============================================================================
# STEP 2: AUTO-DETECT SERVICES AND DOMAINS
# =============================================================================
header "Step 2: Auto-Detecting Services & Domains"

DOMAINS_TO_RENEW=()
SERVICE_MAP=()   # parallel array: domain|nginx|postfix|nginx_container|postfix_container

# ── Docker scan ───────────────────────────────────────────────────────────────
if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
  detect "Docker available — scanning for Nginx and Postfix containers..."

  NGINX_FOUND=$(docker ps --format '{{.Names}}|{{.Image}}' 2>/dev/null \
    | grep -iE '(nginx|proxy)' | head -1 || true)
  POSTFIX_FOUND=$(docker ps --format '{{.Names}}|{{.Image}}' 2>/dev/null \
    | grep -iE '(postfix|mail|smtp|mta)' | head -1 || true)

  if [[ -n "$NGINX_FOUND" ]]; then
    NGINX_CONTAINER=$(echo "$NGINX_FOUND" | cut -d'|' -f1)
    detect "Nginx container: $NGINX_CONTAINER"
  fi
  if [[ -n "$POSTFIX_FOUND" ]]; then
    POSTFIX_CONTAINER=$(echo "$POSTFIX_FOUND" | cut -d'|' -f1)
    detect "Postfix container: $POSTFIX_CONTAINER"
  fi
fi

# ── System Nginx ──────────────────────────────────────────────────────────────
NGINX_DOMAINS=()
if command -v nginx &>/dev/null || [[ -n "$NGINX_CONTAINER" ]]; then
  detect "Scanning for Nginx virtual host domains..."

  NGINX_CONF_SEARCH_PATHS=(
    /etc/nginx/conf.d/*.conf
    /etc/nginx/sites-enabled/*
    /opt/nginx-hardened/nginx/conf.d/*.conf
  )

  for CONF_GLOB in "${NGINX_CONF_SEARCH_PATHS[@]}"; do
    for CONF_FILE in $CONF_GLOB; do
      [[ -f "$CONF_FILE" ]] || continue
      while IFS= read -r SNAME; do
        SNAME=$(echo "$SNAME" | xargs)
        # Skip wildcards, localhost, IP addresses, and catch-all _
        [[ "$SNAME" == "_" ]]         && continue
        [[ "$SNAME" == "localhost" ]]  && continue
        [[ "$SNAME" =~ ^\*\. ]]        && continue
        [[ "$SNAME" =~ ^[0-9]+\. ]]    && continue
        [[ -z "$SNAME" ]]              && continue
        NGINX_DOMAINS+=("$SNAME")
      done < <(grep -E "^\s*server_name\s" "$CONF_FILE" 2>/dev/null \
        | sed 's/server_name//;s/;//' | tr ' ' '\n' | grep -v '^$' || true)
    done
  done

  # Deduplicate
  readarray -t NGINX_DOMAINS < <(printf '%s\n' "${NGINX_DOMAINS[@]}" | sort -u)

  if [[ ${#NGINX_DOMAINS[@]} -gt 0 ]]; then
    success "Nginx domains found: ${NGINX_DOMAINS[*]}"
    DOMAINS_TO_RENEW+=("${NGINX_DOMAINS[@]}")
  else
    warn "No Nginx domains detected from config files"
  fi
fi

# ── System Postfix ────────────────────────────────────────────────────────────
POSTFIX_DOMAINS=()
if command -v postfix &>/dev/null || [[ -n "$POSTFIX_CONTAINER" ]]; then
  detect "Scanning for Postfix mail hostname..."

  MAIN_CF_PATHS=(/etc/postfix/main.cf)
  [[ -n "$POSTFIX_CONTAINER" ]] && \
    MAIN_CF_PATHS+=("/opt/postfix-hardened/postfix/main.cf")

  for MAIN_CF in "${MAIN_CF_PATHS[@]}"; do
    [[ -f "$MAIN_CF" ]] || continue
    PF_HOST=$(grep -E "^myhostname\s*=" "$MAIN_CF" 2>/dev/null \
      | cut -d'=' -f2 | xargs)
    if [[ -n "$PF_HOST" ]] && [[ "$PF_HOST" != "localhost" ]]; then
      POSTFIX_DOMAINS+=("$PF_HOST")
      success "Postfix hostname found: $PF_HOST"
    fi
  done

  readarray -t POSTFIX_DOMAINS < <(printf '%s\n' "${POSTFIX_DOMAINS[@]}" | sort -u)
  DOMAINS_TO_RENEW+=("${POSTFIX_DOMAINS[@]}")
fi

# ── Deduplicate all domains ───────────────────────────────────────────────────
readarray -t DOMAINS_TO_RENEW < <(printf '%s\n' "${DOMAINS_TO_RENEW[@]}" | sort -u)

# ── Manual domain override ────────────────────────────────────────────────────
if [[ $# -gt 0 ]]; then
  info "Manual domain override provided: $*"
  DOMAINS_TO_RENEW=("$@")
fi

if [[ ${#DOMAINS_TO_RENEW[@]} -eq 0 ]]; then
  error "No domains detected. Pass domains manually: sudo $0 example.com mail.example.com"
  exit 1
fi

echo ""
info "Domains queued for renewal check:"
for D in "${DOMAINS_TO_RENEW[@]}"; do
  info "  • $D"
done

# =============================================================================
# STEP 3: CHECK EXPIRY FOR EACH DOMAIN
# =============================================================================
header "Step 3: Certificate Expiry Check"

DOMAINS_NEEDING_RENEWAL=()

for DOMAIN in "${DOMAINS_TO_RENEW[@]}"; do
  DAYS=$(cert_days_left "$DOMAIN")

  if [[ "$DAYS" -eq -1 ]]; then
    warn "$DOMAIN — no certificate found at /etc/letsencrypt/live/$DOMAIN/"
    warn "  Run the harden script first to obtain an initial certificate"
    SKIPPED_DOMAINS+=("$DOMAIN (no cert found)")
    continue
  fi

  if [[ "$DAYS" -le 0 ]]; then
    error "$DOMAIN — certificate has EXPIRED ($DAYS days)"
    DOMAINS_NEEDING_RENEWAL+=("$DOMAIN")
  elif [[ "$DAYS" -le "$RENEW_THRESHOLD" ]]; then
    warn "$DOMAIN — expires in ${DAYS} days (threshold: ${RENEW_THRESHOLD}) — WILL RENEW"
    DOMAINS_NEEDING_RENEWAL+=("$DOMAIN")
  else
    success "$DOMAIN — valid for ${DAYS} more days — skipping"
    SKIPPED_DOMAINS+=("$DOMAIN (${DAYS} days remaining)")
  fi
done

if [[ ${#DOMAINS_NEEDING_RENEWAL[@]} -eq 0 ]]; then
  echo ""
  success "All certificates are valid and not due for renewal."
  echo ""
  echo -e "  ${CYAN}${BOLD}Summary:${RESET}"
  for S in "${SKIPPED_DOMAINS[@]}"; do
    echo -e "    ${GREEN}✔${RESET} $S"
  done
  echo ""
  exit 0
fi

# =============================================================================
# STEP 4: RENEW CERTIFICATES
# =============================================================================
header "Step 4: Renewing Certificates"

# Build certbot renew flags based on challenge method
build_certbot_flags() {
  local DOMAIN="$1"
  local FLAGS="--non-interactive --agree-tos"

  case "$CHALLENGE_METHOD" in
    dns-route53)
      FLAGS="$FLAGS --dns-route53 --dns-route53-propagation-seconds 30"
      ;;
    nginx)
      FLAGS="$FLAGS --nginx"
      ;;
    standalone)
      FLAGS="$FLAGS --standalone"
      ;;
    *)
      warn "Unknown challenge method '$CHALLENGE_METHOD' — falling back to dns-route53"
      FLAGS="$FLAGS --dns-route53 --dns-route53-propagation-seconds 30"
      ;;
  esac

  echo "$FLAGS"
}

for DOMAIN in "${DOMAINS_NEEDING_RENEWAL[@]}"; do
  echo ""
  info "Renewing certificate for: $DOMAIN"

  CERTBOT_FLAGS=$(build_certbot_flags "$DOMAIN")

  # For standalone: stop services temporarily to free ports
  if [[ "$CHALLENGE_METHOD" == "standalone" ]]; then
    warn "Standalone mode: temporarily stopping Nginx/Postfix to free port 80..."
    systemctl stop nginx   2>/dev/null || true
    systemctl stop postfix 2>/dev/null || true
    [[ -n "$NGINX_CONTAINER"   ]] && docker stop "$NGINX_CONTAINER"   2>/dev/null || true
    [[ -n "$POSTFIX_CONTAINER" ]] && docker stop "$POSTFIX_CONTAINER" 2>/dev/null || true
  fi

  # Run certbot renew for this specific domain
  if certbot certonly \
       $CERTBOT_FLAGS \
       -d "$DOMAIN" \
       --cert-name "$DOMAIN" \
       2>&1 | tee /tmp/certbot-renew-${DOMAIN}.log; then

    RENEWED_DOMAINS+=("$DOMAIN")
    success "Certificate renewed: $DOMAIN"
    NEW_DAYS=$(cert_days_left "$DOMAIN")
    info "New expiry: $NEW_DAYS days from now"

    # ── Mark services for reload based on which domains they use ──────────────
    for ND in "${NGINX_DOMAINS[@]}"; do
      [[ "$ND" == "$DOMAIN" ]] && NGINX_NEEDS_RELOAD=true
    done
    for PD in "${POSTFIX_DOMAINS[@]}"; do
      [[ "$PD" == "$DOMAIN" ]] && POSTFIX_NEEDS_RELOAD=true
    done

  else
    FAILED_DOMAINS+=("$DOMAIN")
    error "Renewal FAILED for: $DOMAIN"
    error "Check log: /tmp/certbot-renew-${DOMAIN}.log"

    send_alert \
      "[ssl-renew] FAILED: $DOMAIN on $(hostname)" \
      "Certificate renewal failed for $DOMAIN on $(hostname) at $(date).
Check log: /tmp/certbot-renew-${DOMAIN}.log"
  fi

  # Restart services if stopped for standalone
  if [[ "$CHALLENGE_METHOD" == "standalone" ]]; then
    info "Restarting services after standalone challenge..."
    systemctl start nginx   2>/dev/null || true
    systemctl start postfix 2>/dev/null || true
    [[ -n "$NGINX_CONTAINER"   ]] && docker start "$NGINX_CONTAINER"   2>/dev/null || true
    [[ -n "$POSTFIX_CONTAINER" ]] && docker start "$POSTFIX_CONTAINER" 2>/dev/null || true
  fi
done

# =============================================================================
# STEP 5: COPY RENEWED CERTS TO DOCKER PATHS
# =============================================================================
header "Step 5: Syncing Certs to Docker Volumes"

for DOMAIN in "${RENEWED_DOMAINS[@]}"; do
  LE_CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
  LE_KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"

  # ── Nginx Docker container ────────────────────────────────────────────────
  for ND in "${NGINX_DOMAINS[@]}"; do
    [[ "$ND" != "$DOMAIN" ]] && continue

    if [[ -n "$NGINX_CONTAINER" ]]; then
      info "Copying cert to Nginx container: $NGINX_CONTAINER"
      docker cp "$LE_CERT" "$NGINX_CONTAINER":/etc/nginx/ssl/selfsigned.crt 2>/dev/null \
        && success "  fullchain.pem → /etc/nginx/ssl/selfsigned.crt" \
        || warn "  Failed to copy cert to Nginx container"
      docker cp "$LE_KEY"  "$NGINX_CONTAINER":/etc/nginx/ssl/selfsigned.key 2>/dev/null \
        && success "  privkey.pem   → /etc/nginx/ssl/selfsigned.key" \
        || warn "  Failed to copy key to Nginx container"
    fi

    # Also copy to host-mounted SSL dir if it exists
    if [[ -d "$NGINX_DOCKER_SSL_DIR" ]]; then
      cp "$LE_CERT" "$NGINX_DOCKER_SSL_DIR/selfsigned.crt" \
        && success "  Copied to host mount: $NGINX_DOCKER_SSL_DIR/selfsigned.crt" \
        || warn "  Failed to copy to $NGINX_DOCKER_SSL_DIR"
      cp "$LE_KEY"  "$NGINX_DOCKER_SSL_DIR/selfsigned.key" \
        && chmod 600 "$NGINX_DOCKER_SSL_DIR/selfsigned.key" \
        || warn "  Failed to copy key to $NGINX_DOCKER_SSL_DIR"
    fi
  done

  # ── Postfix Docker container ──────────────────────────────────────────────
  for PD in "${POSTFIX_DOMAINS[@]}"; do
    [[ "$PD" != "$DOMAIN" ]] && continue

    if [[ -n "$POSTFIX_CONTAINER" ]]; then
      info "Copying cert to Postfix container: $POSTFIX_CONTAINER"
      docker cp "$LE_CERT" "$POSTFIX_CONTAINER":/etc/postfix/ssl/postfix.crt 2>/dev/null \
        && success "  fullchain.pem → /etc/postfix/ssl/postfix.crt" \
        || warn "  Failed to copy cert to Postfix container"
      docker cp "$LE_KEY"  "$POSTFIX_CONTAINER":/etc/postfix/ssl/postfix.key 2>/dev/null \
        && success "  privkey.pem   → /etc/postfix/ssl/postfix.key" \
        || warn "  Failed to copy key to Postfix container"
      docker exec "$POSTFIX_CONTAINER" \
        chmod 600 /etc/postfix/ssl/postfix.key 2>/dev/null || true
    fi

    # Also copy to host-mounted SSL dir if it exists
    if [[ -d "$POSTFIX_DOCKER_SSL_DIR" ]]; then
      cp "$LE_CERT" "$POSTFIX_DOCKER_SSL_DIR/postfix.crt" \
        && success "  Copied to host mount: $POSTFIX_DOCKER_SSL_DIR/postfix.crt" \
        || warn "  Failed to copy to $POSTFIX_DOCKER_SSL_DIR"
      cp "$LE_KEY"  "$POSTFIX_DOCKER_SSL_DIR/postfix.key" \
        && chmod 600 "$POSTFIX_DOCKER_SSL_DIR/postfix.key" \
        || warn "  Failed to copy key to $POSTFIX_DOCKER_SSL_DIR"
    fi
  done
done

# =============================================================================
# STEP 6: RELOAD SERVICES
# =============================================================================
header "Step 6: Reloading Services"

# ── Nginx ─────────────────────────────────────────────────────────────────────
if $NGINX_NEEDS_RELOAD; then
  if [[ -n "$NGINX_CONTAINER" ]]; then
    info "Hot-reloading Nginx container: $NGINX_CONTAINER"
    if docker kill --signal=HUP "$NGINX_CONTAINER" 2>/dev/null; then
      success "Nginx container hot-reloaded (HUP signal — zero downtime)"
    else
      warn "HUP failed — restarting container..."
      docker restart "$NGINX_CONTAINER" && success "Nginx container restarted"
    fi
  fi

  if systemctl is-active --quiet nginx 2>/dev/null; then
    info "Reloading system Nginx..."
    if nginx -t 2>/dev/null; then
      systemctl reload nginx && success "System Nginx reloaded"
    else
      error "Nginx config test failed — NOT reloading. Check nginx -t"
    fi
  fi
else
  info "Nginx reload not required (no Nginx domains were renewed)"
fi

# ── Postfix ───────────────────────────────────────────────────────────────────
if $POSTFIX_NEEDS_RELOAD; then
  if [[ -n "$POSTFIX_CONTAINER" ]]; then
    info "Reloading Postfix container: $POSTFIX_CONTAINER"
    if docker exec "$POSTFIX_CONTAINER" postfix reload 2>/dev/null; then
      success "Postfix container reloaded"
    else
      warn "postfix reload failed — restarting container..."
      docker restart "$POSTFIX_CONTAINER" && success "Postfix container restarted"
    fi
  fi

  if systemctl is-active --quiet postfix 2>/dev/null; then
    info "Reloading system Postfix..."
    postfix reload 2>/dev/null && success "System Postfix reloaded" \
      || warn "Postfix reload failed — try: systemctl restart postfix"
  fi
else
  info "Postfix reload not required (no Postfix domains were renewed)"
fi

# =============================================================================
# STEP 7: SCHEDULER SETUP — Cron or Systemd Timer
# =============================================================================
header "Step 7: Scheduler Setup"

SCRIPT_PATH="$(realpath "$0")"

# ── Skip scheduler prompt if called with --check-only ────────────────────────
if [[ "${1:-}" != "--check-only" ]]; then

  echo ""
  echo -e "  ${BOLD}How would you like to schedule automatic renewal?${RESET}"
  echo ""
  echo -e "  ${BOLD}[1]${RESET} Cron job     — /etc/cron.d entry, runs daily at 03:15 AM"
  echo -e "               Simple, works on all Linux distros"
  echo ""
  echo -e "  ${BOLD}[2]${RESET} Systemd timer — ssl-renew.service + ssl-renew.timer"
  echo -e "               Configurable interval, journald logging,"
  echo -e "               auto-restart on failure, boot-time awareness"
  echo ""
  echo -e "  ${BOLD}[3]${RESET} Skip          — I will schedule it manually"
  echo ""

  SCHEDULER_CHOICE=""
  while true; do
    read -rp "$(echo -e "${BOLD}Select scheduler [1-3]: ${RESET}")" SCHEDULER_CHOICE
    case "$SCHEDULER_CHOICE" in
      1|2|3) break ;;
      *) warn "Please enter 1, 2, or 3" ;;
    esac
  done

  # ── Option 1: Cron ─────────────────────────────────────────────────────────
  if [[ "$SCHEDULER_CHOICE" == "1" ]]; then

    CRON_FILE="/etc/cron.d/ssl-renew"

    # Build env vars to preserve config in cron context
    CRON_ENV=""
    [[ "$CHALLENGE_METHOD" != "dns-route53" ]] && \
      CRON_ENV="CHALLENGE_METHOD=$CHALLENGE_METHOD "
    [[ -n "$ALERT_EMAIL" ]] && \
      CRON_ENV="${CRON_ENV}ALERT_EMAIL=$ALERT_EMAIL "
    [[ "$RENEW_THRESHOLD" != "30" ]] && \
      CRON_ENV="${CRON_ENV}RENEW_THRESHOLD=$RENEW_THRESHOLD "

    cat > "$CRON_FILE" << CRONEOF
# =============================================================================
#  SSL Certificate Auto-Renewal — managed by ssl-renew.sh v2.0.0
#  Runs daily at 03:15 AM — renews certs expiring within ${RENEW_THRESHOLD} days
#  Challenge: $CHALLENGE_METHOD
# =============================================================================
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Daily renewal check
15 3 * * * root ${CRON_ENV}${SCRIPT_PATH} >> ${LOG_FILE} 2>&1

# Weekly expiry status check every Sunday at 08:00 AM
0 8 * * 0 root ${CRON_ENV}${SCRIPT_PATH} --check-only >> ${LOG_FILE} 2>&1
CRONEOF

    chmod 640 "$CRON_FILE"
    success "Cron job installed: $CRON_FILE"
    info "Daily renewal:  03:15 AM every day"
    info "Weekly check:   08:00 AM every Sunday"
    info "Log:            $LOG_FILE"

  # ── Option 2: Systemd Timer ────────────────────────────────────────────────
  elif [[ "$SCHEDULER_CHOICE" == "2" ]]; then

    echo ""
    echo -e "  ${BOLD}Select renewal check interval:${RESET}"
    echo ""
    echo -e "  ${BOLD}[1]${RESET} Daily        — recommended (checks every day, only renews when due)"
    echo -e "  ${BOLD}[2]${RESET} Every 12h    — more frequent checks, same renewal logic"
    echo -e "  ${BOLD}[3]${RESET} Weekly       — lighter, but less responsive if cert expires early"
    echo -e "  ${BOLD}[4]${RESET} Custom       — enter your own OnCalendar value"
    echo ""

    TIMER_CHOICE=""
    while true; do
      read -rp "$(echo -e "${BOLD}Select interval [1-4]: ${RESET}")" TIMER_CHOICE
      case "$TIMER_CHOICE" in
        1|2|3|4) break ;;
        *) warn "Please enter 1, 2, 3, or 4" ;;
      esac
    done

    case "$TIMER_CHOICE" in
      1) ON_CALENDAR="daily";         TIMER_DESC="Daily (00:00 + random 1h delay)" ;;
      2) ON_CALENDAR="*-*-* 03,15:00:00"; TIMER_DESC="Every 12 hours (03:00 and 15:00)" ;;
      3) ON_CALENDAR="weekly";        TIMER_DESC="Weekly (Monday 00:00)" ;;
      4)
        echo ""
        echo -e "  ${CYAN}Examples:${RESET}"
        echo -e "    daily               — every day at midnight"
        echo -e "    *-*-* 03:15:00      — every day at 03:15 AM"
        echo -e "    Mon *-*-* 04:00:00  — every Monday at 4 AM"
        echo -e "    *-*-1,15 02:00:00   — 1st and 15th of each month"
        echo ""
        read -rp "$(echo -e "${BOLD}Enter OnCalendar value: ${RESET}")" ON_CALENDAR
        ON_CALENDAR="${ON_CALENDAR:-daily}"
        TIMER_DESC="Custom: $ON_CALENDAR"
        ;;
    esac

    # Build environment file for systemd service
    ENV_FILE="/etc/ssl-renew.env"
    cat > "$ENV_FILE" << ENVEOF
# ssl-renew.sh environment — managed by ssl-renew.sh v2.0.0
CHALLENGE_METHOD=${CHALLENGE_METHOD}
RENEW_THRESHOLD=${RENEW_THRESHOLD}
ALERT_EMAIL=${ALERT_EMAIL}
LOG_FILE=${LOG_FILE}
NGINX_DOCKER_SSL_DIR=${NGINX_DOCKER_SSL_DIR}
POSTFIX_DOCKER_SSL_DIR=${POSTFIX_DOCKER_SSL_DIR}
ENVEOF
    chmod 640 "$ENV_FILE"
    success "Environment file written: $ENV_FILE"

    # ── systemd service unit ──────────────────────────────────────────────────
    cat > /etc/systemd/system/ssl-renew.service << SERVICEEOF
# =============================================================================
#  ssl-renew.service — SSL Certificate Renewal Service
#  Managed by ssl-renew.sh v2.0.0
#  Run manually:  systemctl start ssl-renew.service
#  View logs:     journalctl -u ssl-renew.service -n 50
# =============================================================================
[Unit]
Description=SSL Certificate Renewal (Let's Encrypt)
Documentation=https://certbot.eff.org/docs/
# Run after network and DNS are fully up — critical for DNS-01 challenge
After=network-online.target nss-lookup.target
Wants=network-online.target
# Do not run if system time is not synced (avoids cert issues at boot)
After=time-sync.target

[Service]
Type=oneshot
# Load environment variables (challenge method, email, etc.)
EnvironmentFile=-${ENV_FILE}
# Run as root — required for certbot and service reloads
User=root
Group=root
# The renewal script itself
ExecStart=${SCRIPT_PATH}
# On failure: wait 5 minutes then retry once
Restart=on-failure
RestartSec=300
# Give certbot plenty of time (DNS propagation can take a while)
TimeoutStartSec=600
# Capture all output to journald
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ssl-renew
# Security hardening for the service process
NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=false
# Allow writing to /etc/letsencrypt and cert copy destinations
ReadWritePaths=/etc/letsencrypt /var/log ${NGINX_DOCKER_SSL_DIR} ${POSTFIX_DOCKER_SSL_DIR}

[Install]
WantedBy=multi-user.target
SERVICEEOF

    success "Systemd service unit written: /etc/systemd/system/ssl-renew.service"

    # ── systemd timer unit ────────────────────────────────────────────────────
    # RandomizedDelaySec spreads the run across a window to avoid hammering
    # Let's Encrypt rate limits if multiple servers renew at the exact same time
    cat > /etc/systemd/system/ssl-renew.timer << TIMEREOF
# =============================================================================
#  ssl-renew.timer — SSL Certificate Renewal Timer
#  Managed by ssl-renew.sh v2.0.0
#  Schedule: ${TIMER_DESC}
#  Check status:  systemctl status ssl-renew.timer
#  Next trigger:  systemctl list-timers ssl-renew.timer
# =============================================================================
[Unit]
Description=SSL Certificate Renewal Timer
Documentation=https://certbot.eff.org/docs/

[Timer]
# When to run
OnCalendar=${ON_CALENDAR}
# Add up to 1 hour of random delay to spread load across the renewal window
RandomizedDelaySec=3600
# If the system was off when the timer was due, run it on next boot
Persistent=true
# Name of the service to trigger
Unit=ssl-renew.service

[Install]
WantedBy=timers.target
TIMEREOF

    success "Systemd timer unit written: /etc/systemd/system/ssl-renew.timer"

    # ── Also install a weekly check-only timer ────────────────────────────────
    cat > /etc/systemd/system/ssl-renew-check.service << CHECKSERVICEEOF
# ssl-renew-check.service — Weekly expiry status check (no renewal)
[Unit]
Description=SSL Certificate Expiry Status Check
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=-${ENV_FILE}
User=root
ExecStart=${SCRIPT_PATH} --check-only
TimeoutStartSec=120
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ssl-renew-check
CHECKSERVICEEOF

    cat > /etc/systemd/system/ssl-renew-check.timer << CHECKTIMEREOF
# ssl-renew-check.timer — Runs expiry check every Sunday at 08:00
[Unit]
Description=Weekly SSL Certificate Expiry Check Timer

[Timer]
OnCalendar=Sun *-*-* 08:00:00
RandomizedDelaySec=600
Persistent=true
Unit=ssl-renew-check.service

[Install]
WantedBy=timers.target
CHECKTIMEREOF

    # ── Enable and start ──────────────────────────────────────────────────────
    systemctl daemon-reload

    systemctl enable ssl-renew.timer        &>/dev/null
    systemctl start  ssl-renew.timer
    systemctl enable ssl-renew-check.timer  &>/dev/null
    systemctl start  ssl-renew-check.timer

    # Verify timers are active
    if systemctl is-active --quiet ssl-renew.timer; then
      success "ssl-renew.timer is active and enabled"
    else
      warn "ssl-renew.timer may not have started — check: systemctl status ssl-renew.timer"
    fi

    if systemctl is-active --quiet ssl-renew-check.timer; then
      success "ssl-renew-check.timer is active (weekly expiry check)"
    fi

    # Show next scheduled run
    echo ""
    info "Next scheduled runs:"
    systemctl list-timers ssl-renew.timer ssl-renew-check.timer \
      --no-pager 2>/dev/null | grep -v "^$" | sed 's/^/    /' || true

    echo ""
    info "Systemd timer commands:"
    echo -e "     systemctl status ssl-renew.timer"
    echo -e "     systemctl list-timers ssl-renew.timer"
    echo -e "     journalctl -u ssl-renew.service -n 50 -f"
    echo -e "     systemctl start ssl-renew.service   # run NOW manually"

  # ── Option 3: Skip ─────────────────────────────────────────────────────────
  else
    warn "Scheduler setup skipped."
    info "To run manually:           sudo ${SCRIPT_PATH}"
    info "To check-only:             sudo ${SCRIPT_PATH} --check-only"
    info "To install cron later:     re-run this script and choose option 1"
    info "To install systemd later:  re-run this script and choose option 2"
  fi

fi  # end skip for --check-only

# =============================================================================
# STEP 8: CHECK-ONLY MODE (--check-only flag)
# =============================================================================
# If script was called with --check-only, skip renewal and just report status
if [[ "${1:-}" == "--check-only" ]]; then
  header "Certificate Status Report (check-only)"
  for DOMAIN in "${DOMAINS_TO_RENEW[@]}"; do
    DAYS=$(cert_days_left "$DOMAIN")
    if [[ "$DAYS" -eq -1 ]]; then
      warn "$DOMAIN — no certificate found"
    elif [[ "$DAYS" -le 0 ]]; then
      error "$DOMAIN — EXPIRED"
      send_alert "[ssl-renew] EXPIRED: $DOMAIN on $(hostname)" \
        "Certificate for $DOMAIN has EXPIRED on $(hostname). Immediate renewal required."
    elif [[ "$DAYS" -le 7 ]]; then
      error "$DOMAIN — CRITICAL: expires in $DAYS days"
      send_alert "[ssl-renew] CRITICAL: $DOMAIN expires in ${DAYS}d on $(hostname)" \
        "Certificate for $DOMAIN expires in $DAYS days on $(hostname). Renew immediately."
    elif [[ "$DAYS" -le "$RENEW_THRESHOLD" ]]; then
      warn "$DOMAIN — expires in $DAYS days (renewal due)"
    else
      success "$DOMAIN — valid for $DAYS more days"
    fi
  done
  exit 0
fi

# =============================================================================
# SUMMARY
# =============================================================================
header "Renewal Complete — Summary"

echo ""
echo -e "  ${BOLD}Results:${RESET}"
echo ""

if [[ ${#RENEWED_DOMAINS[@]} -gt 0 ]]; then
  echo -e "  ${GREEN}${BOLD}Renewed (${#RENEWED_DOMAINS[@]}):${RESET}"
  for D in "${RENEWED_DOMAINS[@]}"; do
    DAYS=$(cert_days_left "$D")
    echo -e "    ${GREEN}✔${RESET} $D — now valid for $DAYS days"
  done
  echo ""
fi

if [[ ${#SKIPPED_DOMAINS[@]} -gt 0 ]]; then
  echo -e "  ${CYAN}${BOLD}Skipped — not due for renewal (${#SKIPPED_DOMAINS[@]}):${RESET}"
  for D in "${SKIPPED_DOMAINS[@]}"; do
    echo -e "    ${CYAN}–${RESET} $D"
  done
  echo ""
fi

if [[ ${#FAILED_DOMAINS[@]} -gt 0 ]]; then
  echo -e "  ${RED}${BOLD}FAILED (${#FAILED_DOMAINS[@]}):${RESET}"
  for D in "${FAILED_DOMAINS[@]}"; do
    echo -e "    ${RED}✘${RESET} $D — check /tmp/certbot-renew-${D}.log"
  done
  echo ""
fi

echo -e "  ${CYAN}${BOLD}Challenge method:${RESET}  $CHALLENGE_METHOD"
echo -e "  ${CYAN}${BOLD}Renewal threshold:${RESET} $RENEW_THRESHOLD days"
echo -e "  ${CYAN}${BOLD}Log file:${RESET}          $LOG_FILE"

# Show scheduler status
if [[ -f /etc/systemd/system/ssl-renew.timer ]]; then
  echo -e "  ${CYAN}${BOLD}Scheduler:${RESET}         systemd timer (ssl-renew.timer)"
  NEXT=$(systemctl list-timers ssl-renew.timer --no-pager 2>/dev/null \
    | grep ssl-renew | awk '{print $1, $2}' || echo "check with systemctl list-timers")
  echo -e "  ${CYAN}${BOLD}Next run:${RESET}          $NEXT"
elif [[ -f /etc/cron.d/ssl-renew ]]; then
  echo -e "  ${CYAN}${BOLD}Scheduler:${RESET}         cron (/etc/cron.d/ssl-renew — daily 03:15 AM)"
fi

echo ""
echo -e "  ${CYAN}${BOLD}Useful commands:${RESET}"
echo -e "     # Check all cert expiry dates:"
echo -e "     sudo certbot certificates"
echo -e ""
echo -e "     # Force renew a specific domain now:"
echo -e "     sudo certbot certonly --dns-route53 -d yourdomain.com --force-renewal"
echo -e ""
echo -e "     # Dry-run to test without making changes:"
echo -e "     sudo certbot renew --dry-run"
echo -e ""
echo -e "     # Run this script in check-only mode:"
echo -e "     sudo $0 --check-only"
echo -e ""
echo -e "     # View renewal log:"
echo -e "     tail -f $LOG_FILE"
echo -e ""
if [[ -f /etc/systemd/system/ssl-renew.timer ]]; then
  echo -e "     # Systemd timer commands:"
  echo -e "     systemctl status ssl-renew.timer"
  echo -e "     systemctl list-timers ssl-renew.timer"
  echo -e "     systemctl start ssl-renew.service      # trigger run NOW"
  echo -e "     journalctl -u ssl-renew.service -n 50  # view logs"
  echo -e "     systemctl stop ssl-renew.timer          # pause renewals"
  echo -e "     systemctl disable ssl-renew.timer       # remove from boot"
fi
echo ""

# Exit with failure count so cron can detect issues
exit ${#FAILED_DOMAINS[@]}
