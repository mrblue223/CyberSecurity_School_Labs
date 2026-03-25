#!/usr/bin/env bash
# =============================================================================
#  nginx-verify.sh — Nginx Hardening Verification Script
#  Verifies both Docker and Bare-Metal nginx hardening
#  Version: 1.0.0
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ─────────────────────────────────────────────
# COLORS & HELPERS
# ─────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
RESET='\033[0m'

PASS=0
FAIL=0
WARN=0
TOTAL=0

pass()   { echo -e "  ${GREEN}${BOLD}[PASS]${RESET} $*"; PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); }
fail()   { echo -e "  ${RED}${BOLD}[FAIL]${RESET} $*"; FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); }
warn()   { echo -e "  ${YELLOW}${BOLD}[WARN]${RESET} $*"; WARN=$((WARN+1)); TOTAL=$((TOTAL+1)); }
info()   { echo -e "  ${CYAN}[INFO]${RESET} $*"; }
header() { echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════${RESET}"; \
           echo -e "${BOLD}${BLUE}  $*${RESET}"; \
           echo -e "${BOLD}${BLUE}══════════════════════════════════════════${RESET}"; }
section(){ echo -e "\n  ${BOLD}${MAGENTA}── $* ──${RESET}"; }

check_header() {
  local HEADER="$1"
  local EXPECTED="$2"
  local ACTUAL="$3"
  local LABEL="$4"

  if [[ -z "$ACTUAL" ]]; then
    fail "$LABEL — header missing"
  elif [[ -n "$EXPECTED" && "$ACTUAL" != *"$EXPECTED"* ]]; then
    warn "$LABEL — present but unexpected value: $ACTUAL"
  else
    pass "$LABEL — $ACTUAL"
  fi
}

# ─────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────
clear
echo -e "${BOLD}${BLUE}"
cat << 'EOF'
  ███╗   ██╗ ██████╗ ██╗███╗   ██╗██╗  ██╗   ██╗   ██╗███████╗██████╗ ██╗███████╗██╗   ██╗
  ████╗  ██║██╔════╝ ██║████╗  ██║╚██╗██╔╝   ██║   ██║██╔════╝██╔══██╗██║██╔════╝╚██╗ ██╔╝
  ██╔██╗ ██║██║  ███╗██║██╔██╗ ██║ ╚███╔╝    ██║   ██║█████╗  ██████╔╝██║█████╗   ╚████╔╝ 
  ██║╚██╗██║██║   ██║██║██║╚██╗██║ ██╔██╗    ╚██╗ ██╔╝██╔══╝  ██╔══██╗██║██╔══╝    ╚██╔╝  
  ██║ ╚████║╚██████╔╝██║██║ ╚████║██╔╝ ██╗    ╚████╔╝ ███████╗██║  ██║██║██║        ██║   
  ╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝    ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   
EOF
echo -e "${RESET}"
echo -e "  ${BOLD}Nginx Hardening Verification Script v1.0.0${RESET}"
echo -e "  ${CYAN}Checks TLS • Headers • Container • Firewall • Config${RESET}"
echo ""

# ─────────────────────────────────────────────
# TARGET DETECTION
# ─────────────────────────────────────────────
header "Target Detection"

TARGET_HOST="localhost"
TARGET_HTTP="http://$TARGET_HOST"
TARGET_HTTPS="https://$TARGET_HOST"
DEPLOY_MODE="unknown"
CONTAINER_NAME=""
NGINX_CONF=""

# Override host if argument given
if [[ $# -gt 0 ]]; then
  TARGET_HOST="$1"
  TARGET_HTTP="http://$TARGET_HOST"
  TARGET_HTTPS="https://$TARGET_HOST"
  info "Target overridden: $TARGET_HOST"
fi

# Detect Docker container
if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
  FOUND=$(docker ps --format '{{.Names}}|{{.Image}}' 2>/dev/null \
    | grep -iE '(nginx|proxy)' | head -1 || true)
  if [[ -n "$FOUND" ]]; then
    CONTAINER_NAME=$(echo "$FOUND" | cut -d'|' -f1)
    CONTAINER_IMAGE=$(echo "$FOUND" | cut -d'|' -f2)
    DEPLOY_MODE="docker"
    info "Docker container detected: ${BOLD}$CONTAINER_NAME${RESET} ($CONTAINER_IMAGE)"
  fi
fi

# Detect system nginx
if systemctl is-active --quiet nginx 2>/dev/null; then
  if [[ "$DEPLOY_MODE" == "unknown" ]]; then
    DEPLOY_MODE="baremetal"
    NGINX_CONF="/etc/nginx/nginx.conf"
    info "System Nginx detected (bare-metal mode)"
  else
    info "System Nginx also present (but Docker takes priority)"
  fi
fi

if [[ "$DEPLOY_MODE" == "unknown" ]]; then
  echo -e "  ${RED}No running Nginx detected (Docker or system). Is it running?${RESET}"
  exit 1
fi

info "Mode: ${BOLD}$DEPLOY_MODE${RESET}"
echo ""

# ─────────────────────────────────────────────
# 1. CONTAINER / PROCESS CHECKS
# ─────────────────────────────────────────────
header "1. Service & Container Health"

if [[ "$DEPLOY_MODE" == "docker" ]]; then
  section "Docker Container"

  # Running status
  STATUS=$(docker inspect "$CONTAINER_NAME" --format '{{.State.Status}}' 2>/dev/null)
  if [[ "$STATUS" == "running" ]]; then
    pass "Container is running (status: $STATUS)"
  else
    fail "Container is not running (status: $STATUS)"
  fi

  # Restart count
  RESTARTS=$(docker inspect "$CONTAINER_NAME" --format '{{.RestartCount}}' 2>/dev/null)
  if [[ "$RESTARTS" -eq 0 ]]; then
    pass "Container restart count: $RESTARTS"
  elif [[ "$RESTARTS" -lt 3 ]]; then
    warn "Container has restarted $RESTARTS times"
  else
    fail "Container has restarted $RESTARTS times — check logs"
  fi

  # Health check
  HEALTH=$(docker inspect "$CONTAINER_NAME" --format '{{.State.Health.Status}}' 2>/dev/null || echo "none")
  case "$HEALTH" in
    healthy)   pass "Health check: $HEALTH" ;;
    starting)  warn "Health check: still starting" ;;
    unhealthy) fail "Health check: UNHEALTHY" ;;
    none)      warn "No health check configured" ;;
    *)         warn "Health check status: $HEALTH" ;;
  esac

  # Port mappings
  PORTS=$(docker inspect "$CONTAINER_NAME" \
    --format '{{range $p,$b := .NetworkSettings.Ports}}{{$p}}->{{range $b}}{{.HostPort}}{{end}} {{end}}' \
    2>/dev/null)
  if echo "$PORTS" | grep -q "443"; then
    pass "Port 443 is mapped: $PORTS"
  else
    fail "Port 443 is NOT mapped — HTTPS unreachable from host: $PORTS"
  fi
  if echo "$PORTS" | grep -q "80"; then
    pass "Port 80 is mapped (for HTTP redirect)"
  else
    warn "Port 80 not mapped — HTTP redirect won't work"
  fi

  section "Container Security Config"

  # no-new-privileges
  NO_NEW_PRIV=$(docker inspect "$CONTAINER_NAME" \
    --format '{{.HostConfig.SecurityOpt}}' 2>/dev/null)
  if echo "$NO_NEW_PRIV" | grep -q "no-new-privileges"; then
    pass "no-new-privileges: enabled"
  else
    warn "no-new-privileges: not set"
  fi

  # Cap drop
  CAP_DROP=$(docker inspect "$CONTAINER_NAME" \
    --format '{{.HostConfig.CapDrop}}' 2>/dev/null)
  if echo "$CAP_DROP" | grep -qi "ALL"; then
    pass "Capabilities: cap_drop ALL is set"
  else
    warn "Capabilities: cap_drop ALL not detected — $CAP_DROP"
  fi

  # Not running as root
  CONTAINER_USER=$(docker exec "$CONTAINER_NAME" id -u 2>/dev/null || echo "unknown")
  if [[ "$CONTAINER_USER" == "0" ]]; then
    warn "Nginx worker may be running as root (uid 0)"
  else
    pass "Nginx not running as root (uid: $CONTAINER_USER)"
  fi

else
  section "System Nginx"

  if systemctl is-active --quiet nginx; then
    pass "Nginx service is active"
  else
    fail "Nginx service is not running"
  fi

  if systemctl is-enabled --quiet nginx; then
    pass "Nginx is enabled on boot"
  else
    warn "Nginx is not enabled on boot"
  fi

  NGINX_PID=$(pgrep -x nginx | head -1 || echo "")
  if [[ -n "$NGINX_PID" ]]; then
    NGINX_USER=$(ps -o user= -p "$NGINX_PID" 2>/dev/null | xargs)
    if [[ "$NGINX_USER" == "root" ]]; then
      warn "Nginx master running as root (expected, workers should drop to nginx)"
    else
      pass "Nginx running as: $NGINX_USER"
    fi
  fi
fi

# ─────────────────────────────────────────────
# 2. CONNECTIVITY CHECKS
# ─────────────────────────────────────────────
header "2. Connectivity & Protocol"

section "HTTP → HTTPS Redirect"

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  --max-time 5 "$TARGET_HTTP" 2>/dev/null || echo "000")

if [[ "$HTTP_CODE" == "301" || "$HTTP_CODE" == "302" ]]; then
  pass "HTTP redirect: $HTTP_CODE (redirecting to HTTPS)"
elif [[ "$HTTP_CODE" == "000" ]]; then
  fail "HTTP: no response (connection refused or timeout)"
else
  warn "HTTP returned $HTTP_CODE instead of 301/302"
fi

section "HTTPS Connectivity"

HTTPS_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
  --max-time 5 "$TARGET_HTTPS" 2>/dev/null || echo "000")

if [[ "$HTTPS_CODE" == "200" ]]; then
  pass "HTTPS: $HTTPS_CODE OK"
elif [[ "$HTTPS_CODE" == "000" ]]; then
  fail "HTTPS: no response — port 443 may not be open"
else
  warn "HTTPS returned: $HTTPS_CODE"
fi

section "TLS Protocol Versions"

# TLS 1.2
TLS12=$(curl -sk --tls-max 1.2 --tlsv1.2 -o /dev/null -w "%{http_code}" \
  --max-time 5 "$TARGET_HTTPS" 2>/dev/null || echo "000")
if [[ "$TLS12" == "200" ]]; then
  pass "TLS 1.2: accepted"
else
  warn "TLS 1.2: not accepted or no response ($TLS12)"
fi

# TLS 1.3
TLS13=$(curl -sk --tlsv1.3 -o /dev/null -w "%{http_code}" \
  --max-time 5 "$TARGET_HTTPS" 2>/dev/null || echo "000")
if [[ "$TLS13" == "200" ]]; then
  pass "TLS 1.3: accepted"
else
  warn "TLS 1.3: not accepted or not supported by this curl build ($TLS13)"
fi

# TLS 1.1 should be REJECTED
# For TLS 1.0/1.1: connection failure = correctly rejected
# We check the exit code rather than HTTP code since a rejected TLS
# handshake never produces an HTTP response code
if ! curl -sk --tls-max 1.1 --tlsv1.1 -o /dev/null   --max-time 5 "$TARGET_HTTPS" 2>/dev/null; then
  pass "TLS 1.1: correctly rejected (connection failed)"
else
  TLS11_CODE=$(curl -sk --tls-max 1.1 --tlsv1.1 -o /dev/null -w "%{http_code}"     --max-time 5 "$TARGET_HTTPS" 2>/dev/null || echo "000")
  if [[ "$TLS11_CODE" == "000" ]]; then
    pass "TLS 1.1: correctly rejected"
  else
    fail "TLS 1.1: accepted (should be disabled!) — response: $TLS11_CODE"
  fi
fi

# TLS 1.0 should be REJECTED
if ! curl -sk --tls-max 1.0 --tlsv1.0 -o /dev/null   --max-time 5 "$TARGET_HTTPS" 2>/dev/null; then
  pass "TLS 1.0: correctly rejected (connection failed)"
else
  TLS10_CODE=$(curl -sk --tls-max 1.0 --tlsv1.0 -o /dev/null -w "%{http_code}"     --max-time 5 "$TARGET_HTTPS" 2>/dev/null || echo "000")
  if [[ "$TLS10_CODE" == "000" ]]; then
    pass "TLS 1.0: correctly rejected"
  else
    fail "TLS 1.0: accepted (should be disabled!) — response: $TLS10_CODE"
  fi
fi

section "HTTP/2"

HTTP2=$(curl -sk -I --http2 -o /dev/null -w "%{http_version}" \
  --max-time 5 "$TARGET_HTTPS" 2>/dev/null || echo "unknown")
if [[ "$HTTP2" == "2" ]]; then
  pass "HTTP/2: active"
else
  warn "HTTP/2: not detected (version: $HTTP2)"
fi

# ─────────────────────────────────────────────
# 3. SECURITY HEADERS
# ─────────────────────────────────────────────
header "3. Security Headers"

HEADERS=$(curl -sk -I --max-time 5 "$TARGET_HTTPS" 2>/dev/null | tr '[:upper:]' '[:lower:]')

section "Transport Security"
HSTS=$(echo "$HEADERS" | grep "^strict-transport-security:" | sed 's/strict-transport-security: //' | tr -d '\r')
if [[ -z "$HSTS" ]]; then
  fail "Strict-Transport-Security — MISSING"
elif echo "$HSTS" | grep -q "max-age=6307"; then
  pass "Strict-Transport-Security: $HSTS"
elif echo "$HSTS" | grep -q "max-age="; then
  warn "Strict-Transport-Security present but max-age may be short: $HSTS"
else
  warn "Strict-Transport-Security: $HSTS"
fi

section "Clickjacking & Content Protection"
XFO_VAL=$(echo "$HEADERS" | grep "^x-frame-options:" | sed 's/x-frame-options: //' | tr -d '\r')
XFO_UPPER=$(echo "$XFO_VAL" | tr '[:lower:]' '[:upper:]')
if [[ -z "$XFO_VAL" ]]; then
  fail "X-Frame-Options — header missing"
elif [[ "$XFO_UPPER" == "SAMEORIGIN" || "$XFO_UPPER" == "DENY" ]]; then
  pass "X-Frame-Options — $XFO_VAL"
else
  warn "X-Frame-Options — unexpected value: $XFO_VAL"
fi

check_header "x-content-type-options" "nosniff" \
  "$(echo "$HEADERS" | grep "^x-content-type-options:" | sed 's/x-content-type-options: //' | tr -d '\r')" \
  "X-Content-Type-Options"

check_header "x-xss-protection" "1" \
  "$(echo "$HEADERS" | grep "^x-xss-protection:" | sed 's/x-xss-protection: //' | tr -d '\r')" \
  "X-XSS-Protection"

section "Privacy & Referrer"
check_header "referrer-policy" "strict-origin" \
  "$(echo "$HEADERS" | grep "^referrer-policy:" | sed 's/referrer-policy: //' | tr -d '\r')" \
  "Referrer-Policy"

check_header "permissions-policy" "geolocation=()" \
  "$(echo "$HEADERS" | grep "^permissions-policy:" | sed 's/permissions-policy: //' | tr -d '\r')" \
  "Permissions-Policy"

section "Content Security Policy"
CSP=$(echo "$HEADERS" | grep "^content-security-policy:" | sed 's/content-security-policy: //' | tr -d '\r')
if [[ -z "$CSP" ]]; then
  fail "Content-Security-Policy — MISSING"
else
  pass "Content-Security-Policy: present"
  if echo "$CSP" | grep -q "default-src 'self'"; then
    pass "  CSP default-src: 'self'"
  else
    warn "  CSP default-src: not set to 'self'"
  fi
  if echo "$CSP" | grep -q "frame-ancestors 'none'"; then
    pass "  CSP frame-ancestors: 'none'"
  else
    warn "  CSP frame-ancestors: not set to 'none'"
  fi
fi

section "Cross-Origin Policies"
check_header "cross-origin-opener-policy" "same-origin" \
  "$(echo "$HEADERS" | grep "^cross-origin-opener-policy:" | sed 's/cross-origin-opener-policy: //' | tr -d '\r')" \
  "Cross-Origin-Opener-Policy"

check_header "cross-origin-embedder-policy" "require-corp" \
  "$(echo "$HEADERS" | grep "^cross-origin-embedder-policy:" | sed 's/cross-origin-embedder-policy: //' | tr -d '\r')" \
  "Cross-Origin-Embedder-Policy"

check_header "cross-origin-resource-policy" "same-origin" \
  "$(echo "$HEADERS" | grep "^cross-origin-resource-policy:" | sed 's/cross-origin-resource-policy: //' | tr -d '\r')" \
  "Cross-Origin-Resource-Policy"

check_header "x-permitted-cross-domain-policies" "none" \
  "$(echo "$HEADERS" | grep "^x-permitted-cross-domain-policies:" | sed 's/x-permitted-cross-domain-policies: //' | tr -d '\r')" \
  "X-Permitted-Cross-Domain-Policies"

section "Information Disclosure"
SERVER_HEADER=$(echo "$HEADERS" | grep "^server:" | sed 's/server: //' | tr -d '\r')
if [[ -z "$SERVER_HEADER" ]]; then
  pass "Server header: not present (best)"
elif echo "$SERVER_HEADER" | grep -qiE "nginx/[0-9]"; then
  fail "Server header leaks version: $SERVER_HEADER"
else
  pass "Server header: no version disclosed ($SERVER_HEADER)"
fi

POWERED_BY=$(echo "$HEADERS" | grep "^x-powered-by:" | tr -d '\r')
if [[ -z "$POWERED_BY" ]]; then
  pass "X-Powered-By: not present"
else
  fail "X-Powered-By header present — leaks backend info: $POWERED_BY"
fi

# ─────────────────────────────────────────────
# 4. SSL CERTIFICATE
# ─────────────────────────────────────────────
header "4. SSL Certificate"

CERT_INFO=$(echo | openssl s_client -connect "$TARGET_HOST:443" \
  -servername "$TARGET_HOST" 2>/dev/null | openssl x509 -noout \
  -subject -issuer -dates -fingerprint 2>/dev/null || echo "")

if [[ -z "$CERT_INFO" ]]; then
  fail "Could not retrieve SSL certificate"
else
  section "Certificate Details"

  SUBJECT=$(echo "$CERT_INFO" | grep "subject=" | sed 's/subject=//')
  ISSUER=$(echo  "$CERT_INFO" | grep "issuer="  | sed 's/issuer=//')
  NOT_AFTER=$(echo "$CERT_INFO" | grep "notAfter=" | sed 's/notAfter=//')

  info "Subject:  $SUBJECT"
  info "Issuer:   $ISSUER"
  info "Expires:  $NOT_AFTER"

  # Self-signed check
  if [[ "$SUBJECT" == "$ISSUER" ]]; then
    warn "Certificate is self-signed (expected in lab — replace with Let's Encrypt for production)"
  else
    pass "Certificate is CA-signed"
  fi

  # Expiry check
  EXPIRY_DATE=$(echo | openssl s_client -connect "$TARGET_HOST:443" \
    -servername "$TARGET_HOST" 2>/dev/null \
    | openssl x509 -noout -enddate 2>/dev/null \
    | cut -d= -f2)

  if [[ -n "$EXPIRY_DATE" ]]; then
    EXPIRY_EPOCH=$(date -d "$EXPIRY_DATE" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$EXPIRY_DATE" +%s 2>/dev/null || echo 0)
    NOW_EPOCH=$(date +%s)
    DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

    if [[ $DAYS_LEFT -gt 30 ]]; then
      pass "Certificate valid for $DAYS_LEFT more days"
    elif [[ $DAYS_LEFT -gt 0 ]]; then
      warn "Certificate expires in $DAYS_LEFT days — renew soon!"
    else
      fail "Certificate has EXPIRED"
    fi
  fi

  # Key size
  KEY_BITS=$(echo | openssl s_client -connect "$TARGET_HOST:443" \
    -servername "$TARGET_HOST" 2>/dev/null \
    | openssl x509 -noout -text 2>/dev/null \
    | grep "Public-Key:" | grep -oE "[0-9]+" | head -1)

  if [[ -n "$KEY_BITS" ]]; then
    if [[ "$KEY_BITS" -ge 4096 ]]; then
      pass "Key size: ${KEY_BITS}-bit (strong)"
    elif [[ "$KEY_BITS" -ge 2048 ]]; then
      warn "Key size: ${KEY_BITS}-bit (acceptable, 4096 preferred)"
    else
      fail "Key size: ${KEY_BITS}-bit (too weak)"
    fi
  fi
fi

# ─────────────────────────────────────────────
# 5. SENSITIVE PATH BLOCKING
# ─────────────────────────────────────────────
header "5. Sensitive Path Blocking"

section "Common Attack Paths"

check_blocked() {
  local PATH_TO_CHECK="$1"
  local CODE
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
    --max-time 5 "${TARGET_HTTPS}${PATH_TO_CHECK}" 2>/dev/null || echo "000")
  if [[ "$CODE" == "404" || "$CODE" == "403" || "$CODE" == "444" || "$CODE" == "000" ]]; then
    pass "Blocked: $PATH_TO_CHECK ($CODE)"
  elif [[ "$CODE" == "301" || "$CODE" == "302" ]]; then
    warn "Redirected: $PATH_TO_CHECK ($CODE) — verify destination"
  else
    fail "EXPOSED: $PATH_TO_CHECK returned $CODE"
  fi
}

check_blocked "/.env"
check_blocked "/.git/config"
check_blocked "/wp-admin"
check_blocked "/wp-login.php"
check_blocked "/phpmyadmin"
check_blocked "/adminer"
check_blocked "/Makefile"
check_blocked "/Dockerfile"
check_blocked "/config.bak"
check_blocked "/backup.sql"
check_blocked "/.htaccess"

section "Hidden Files"
check_blocked "/.hidden"
check_blocked "/test~"

# ─────────────────────────────────────────────
# 6. BAD BOT BLOCKING
# ─────────────────────────────────────────────
header "6. Bad Bot & Scanner Blocking"

check_bot() {
  local AGENT="$1"
  local LABEL="$2"
  local CODE
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
    --max-time 5 -A "$AGENT" "$TARGET_HTTPS" 2>/dev/null || echo "000")
  if [[ "$CODE" == "403" || "$CODE" == "444" || "$CODE" == "000" ]]; then
    pass "Blocked bot: $LABEL ($CODE)"
  else
    fail "Bot NOT blocked: $LABEL — returned $CODE"
  fi
}

check_bot "nikto/2.1.6" "Nikto scanner"
check_bot "sqlmap/1.0" "SQLmap"
check_bot "masscan/1.0" "Masscan"
check_bot "Mozilla/5.0 zgrab/0.x" "ZGrab"
check_bot "" "Empty User-Agent"

# ─────────────────────────────────────────────
# 7. HTTP METHOD RESTRICTIONS
# ─────────────────────────────────────────────
header "7. HTTP Method Restrictions"

check_method() {
  local METHOD="$1"
  local EXPECT_BLOCKED="$2"
  local CODE
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
    --max-time 5 -X "$METHOD" "$TARGET_HTTPS" 2>/dev/null || echo "000")
  if $EXPECT_BLOCKED; then
    if [[ "$CODE" == "405" || "$CODE" == "444" || "$CODE" == "403" ]]; then
      pass "$METHOD blocked ($CODE)"
    else
      fail "$METHOD NOT blocked — returned $CODE"
    fi
  else
    if [[ "$CODE" == "200" || "$CODE" == "301" || "$CODE" == "404" ]]; then
      pass "$METHOD allowed ($CODE)"
    else
      warn "$METHOD returned $CODE"
    fi
  fi
}

check_method "GET"     false
check_method "POST"    false
check_method "TRACE"   true
check_method "TRACK"   true
check_method "DELETE"  false
check_method "OPTIONS" false

# ─────────────────────────────────────────────
# 8. FIREWALL CHECKS
# ─────────────────────────────────────────────
header "8. Firewall"

if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld 2>/dev/null; then
  section "firewalld"

  HTTP_FW=$(firewall-cmd --list-services 2>/dev/null | grep -o "http" || true)
  HTTPS_FW=$(firewall-cmd --list-services 2>/dev/null | grep -o "https" || true)

  if [[ -n "$HTTP_FW" ]]; then
    pass "firewalld: HTTP (port 80) is open"
  else
    fail "firewalld: HTTP (port 80) is NOT open"
  fi

  if [[ -n "$HTTPS_FW" ]]; then
    pass "firewalld: HTTPS (port 443) is open"
  else
    fail "firewalld: HTTPS (port 443) is NOT open"
  fi

  ZONE=$(firewall-cmd --get-default-zone 2>/dev/null)
  info "Default zone: $ZONE"
else
  warn "firewalld not running — skipping firewall checks"
fi

# Check ports actually listening
section "Listening Ports"
if command -v ss &>/dev/null; then
  PORT80=$(ss -tlnp 2>/dev/null | grep ":80 " || true)
  PORT443=$(ss -tlnp 2>/dev/null | grep ":443 " || true)
  if [[ -n "$PORT80" ]]; then
    pass "Port 80 is listening"
  else
    fail "Port 80 is NOT listening"
  fi
  if [[ -n "$PORT443" ]]; then
    pass "Port 443 is listening"
  else
    fail "Port 443 is NOT listening"
  fi
fi

# ─────────────────────────────────────────────
# 9. NGINX CONFIG CHECKS (Docker)
# ─────────────────────────────────────────────
if [[ "$DEPLOY_MODE" == "docker" ]]; then
  header "9. Nginx Config Validation (inside container)"

  CONFIG_TEST=$(docker exec "$CONTAINER_NAME" nginx -t 2>&1 || true)
  if echo "$CONFIG_TEST" | grep -q "test is successful"; then
    pass "nginx -t: configuration test passed"
  else
    fail "nginx -t: configuration test FAILED"
    echo "$CONFIG_TEST" | sed 's/^/         /'
  fi

  section "Key Directives"

  NGINX_CONF_CONTENT=$(docker exec "$CONTAINER_NAME" \
    cat /etc/nginx/nginx.conf 2>/dev/null || echo "")
  VHOST_CONTENT=$(docker exec "$CONTAINER_NAME" \
    cat /etc/nginx/conf.d/hardened.conf 2>/dev/null || echo "")

  if echo "$NGINX_CONF_CONTENT" | grep -q "server_tokens off"; then
    pass "server_tokens: off"
  else
    fail "server_tokens: not set to off"
  fi

  if echo "$NGINX_CONF_CONTENT" | grep -q "worker_processes auto"; then
    pass "worker_processes: auto"
  else
    warn "worker_processes: not set to auto"
  fi

  if echo "$NGINX_CONF_CONTENT" | grep -q "limit_req_zone"; then
    pass "Rate limiting zones: configured"
  else
    fail "Rate limiting zones: NOT configured"
  fi

  if echo "$VHOST_CONTENT" | grep -q "TLSv1.2 TLSv1.3"; then
    pass "TLS protocols: TLSv1.2 TLSv1.3 only"
  else
    warn "TLS protocols: could not verify"
  fi

  if echo "$VHOST_CONTENT" | grep -q "ssl_session_tickets.*off"; then
    pass "SSL session tickets: disabled"
  else
    warn "SSL session tickets: not explicitly disabled"
  fi

  if echo "$VHOST_CONTENT" | grep -q "ssl_dhparam"; then
    pass "DH params: configured"
  else
    fail "DH params: NOT configured"
  fi

  if echo "$VHOST_CONTENT" | grep -q "http2 on\|http2;"; then
    pass "HTTP/2: enabled"
  else
    warn "HTTP/2: directive not found"
  fi

  section "Volume Mounts (read-only)"
  MOUNTS=$(docker inspect "$CONTAINER_NAME" \
    --format '{{range .Mounts}}{{.Destination}}:{{.Mode}} {{end}}' 2>/dev/null)
  for MOUNT in $MOUNTS; do
    DEST=$(echo "$MOUNT" | cut -d: -f1)
    MODE=$(echo "$MOUNT" | cut -d: -f2)
    if [[ "$MODE" == "ro" ]]; then
      pass "Volume $DEST is read-only"
    else
      warn "Volume $DEST is NOT read-only (mode: $MODE)"
    fi
  done

elif [[ "$DEPLOY_MODE" == "baremetal" ]]; then
  header "9. Nginx Config Validation (system)"

  if nginx -t 2>&1 | grep -q "test is successful"; then
    pass "nginx -t: configuration test passed"
  else
    fail "nginx -t: FAILED"
  fi

  if grep -r "server_tokens off" /etc/nginx/ &>/dev/null; then
    pass "server_tokens: off"
  else
    fail "server_tokens: not set to off"
  fi

  if grep -r "limit_req_zone" /etc/nginx/ &>/dev/null; then
    pass "Rate limiting: configured"
  else
    fail "Rate limiting: NOT configured"
  fi
fi

# ─────────────────────────────────────────────
# 10. LOG CHECK
# ─────────────────────────────────────────────
header "10. Log Verification"

if [[ "$DEPLOY_MODE" == "docker" ]]; then
  RECENT_LOGS=$(docker logs --tail 20 "$CONTAINER_NAME" 2>&1 || echo "")
  if echo "$RECENT_LOGS" | grep -qi "emerg\|crit\|alert"; then
    fail "Critical errors found in recent logs:"
    echo "$RECENT_LOGS" | grep -i "emerg\|crit\|alert" | sed 's/^/         /'
  else
    pass "No critical errors in recent container logs"
  fi
  if echo "$RECENT_LOGS" | grep -qi "\[error\]"; then
    warn "Errors found in recent logs (may be normal):"
    echo "$RECENT_LOGS" | grep -i "\[error\]" | tail -3 | sed 's/^/         /'
  else
    pass "No errors in recent container logs"
  fi

  # Check log file on host if mounted
  HOST_LOG="/opt/nginx-hardened/logs/access.log"
  if [[ -f "$HOST_LOG" ]]; then
    LOG_LINES=$(wc -l < "$HOST_LOG")
    pass "Access log exists on host: $HOST_LOG ($LOG_LINES lines)"
  else
    warn "Access log not found on host at $HOST_LOG"
  fi
fi

# ─────────────────────────────────────────────
# FINAL SCORE
# ─────────────────────────────────────────────
header "Verification Complete — Final Score"

echo ""
echo -e "  ${BOLD}Results:${RESET}"
echo -e "  ${GREEN}${BOLD}PASS: $PASS${RESET}   ${RED}${BOLD}FAIL: $FAIL${RESET}   ${YELLOW}${BOLD}WARN: $WARN${RESET}   Total: $TOTAL"
echo ""

SCORE=$(( (PASS * 100) / TOTAL ))

if [[ $FAIL -eq 0 && $WARN -eq 0 ]]; then
  echo -e "  ${GREEN}${BOLD}★ PERFECT — $SCORE% — Fully hardened!${RESET}"
elif [[ $FAIL -eq 0 ]]; then
  echo -e "  ${CYAN}${BOLD}✔ GOOD — $SCORE% — Minor warnings to review${RESET}"
elif [[ $FAIL -le 3 ]]; then
  echo -e "  ${YELLOW}${BOLD}⚠ PARTIAL — $SCORE% — Some issues need attention${RESET}"
else
  echo -e "  ${RED}${BOLD}✘ CRITICAL — $SCORE% — Multiple hardening failures${RESET}"
fi

echo ""

if [[ $FAIL -gt 0 ]]; then
  echo -e "  ${RED}${BOLD}Failed checks:${RESET}"
  echo -e "  Review the [FAIL] items above and re-run after fixing."
fi

if [[ $WARN -gt 0 ]]; then
  echo -e "  ${YELLOW}${BOLD}Warnings:${RESET}"
  echo -e "  Review the [WARN] items above — they are not critical but worth improving."
fi

echo ""
echo -e "  ${CYAN}${BOLD}Next steps:${RESET}"
echo -e "   • Replace self-signed cert with Let's Encrypt for production"
echo -e "   • Run: https://www.ssllabs.com/ssltest/analyze.html?d=YOUR_DOMAIN"
echo -e "   • Run: https://securityheaders.com/?q=YOUR_DOMAIN"
echo ""

exit $FAIL
