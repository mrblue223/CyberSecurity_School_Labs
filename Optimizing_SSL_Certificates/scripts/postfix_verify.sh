#!/usr/bin/env bash
# =============================================================================
#  postfix-verify.sh — Postfix Hardening Verification Script
#  Verifies both Docker and Bare-Metal Postfix hardening
#  Checks: TLS • Ciphers • Ports • SASL • DKIM • SPF • DMARC • Config • Firewall
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

pass()    { echo -e "  ${GREEN}${BOLD}[PASS]${RESET} $*"; PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); }
fail()    { echo -e "  ${RED}${BOLD}[FAIL]${RESET} $*"; FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); }
warn()    { echo -e "  ${YELLOW}${BOLD}[WARN]${RESET} $*"; WARN=$((WARN+1)); TOTAL=$((TOTAL+1)); }
info()    { echo -e "  ${CYAN}[INFO]${RESET} $*"; }
header()  { echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════${RESET}"; \
            echo -e "${BOLD}${BLUE}  $*${RESET}"; \
            echo -e "${BOLD}${BLUE}══════════════════════════════════════════${RESET}"; }
section() { echo -e "\n  ${BOLD}${MAGENTA}── $* ──${RESET}"; }

# ─────────────────────────────────────────────
# SMTP TLS HELPER
# Performs an openssl s_client STARTTLS or wrapper handshake
# and returns the output for parsing
# ─────────────────────────────────────────────
smtp_tls_check() {
  local HOST="$1"
  local PORT="$2"
  local MODE="${3:-starttls}"   # starttls | wrapper
  local EXTRA_FLAGS="${4:-}"

  if [[ "$MODE" == "wrapper" ]]; then
    # Port 465 — implicit TLS, no STARTTLS
    timeout 10 openssl s_client \
      -connect "${HOST}:${PORT}" \
      -servername "$HOST" \
      $EXTRA_FLAGS \
      </dev/null 2>/dev/null || true
  else
    # Port 587 — STARTTLS
    timeout 10 openssl s_client \
      -connect "${HOST}:${PORT}" \
      -servername "$HOST" \
      -starttls smtp \
      $EXTRA_FLAGS \
      </dev/null 2>/dev/null || true
  fi
}

# ─────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────
clear
echo -e "${BOLD}${BLUE}"
cat << 'EOF'
  ██████╗  ██████╗ ███████╗████████╗███████╗██╗██╗  ██╗   ██╗   ██╗███████╗██████╗ ██╗███████╗██╗   ██╗
  ██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝██╔════╝██║╚██╗██╔╝   ██║   ██║██╔════╝██╔══██╗██║██╔════╝╚██╗ ██╔╝
  ██████╔╝██║   ██║███████╗   ██║   █████╗  ██║ ╚███╔╝    ██║   ██║█████╗  ██████╔╝██║█████╗   ╚████╔╝
  ██╔═══╝ ██║   ██║╚════██║   ██║   ██╔══╝  ██║ ██╔██╗    ╚██╗ ██╔╝██╔══╝  ██╔══██╗██║██╔══╝    ╚██╔╝
  ██║     ╚██████╔╝███████║   ██║   ██║     ██║██╔╝ ██╗    ╚████╔╝ ███████╗██║  ██║██║██║        ██║
  ╚═╝      ╚═════╝ ╚══════╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═╝    ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝╚═╝        ╚═╝
EOF
echo -e "${RESET}"
echo -e "  ${BOLD}Postfix Hardening Verification Script v1.0.0${RESET}"
echo -e "  ${CYAN}Checks TLS • Ciphers • SASL • DKIM • SPF • DMARC • Config • Firewall${RESET}"
echo ""

# ─────────────────────────────────────────────
# ROOT CHECK
# ─────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo -e "  ${RED}This script must be run as root. Use: sudo $0${RESET}"
  exit 1
fi

# ─────────────────────────────────────────────
# TARGET DETECTION
# ─────────────────────────────────────────────
header "Target Detection"

TARGET_HOST="localhost"
DEPLOY_MODE="unknown"
CONTAINER_NAME=""

# Allow host override as argument
if [[ $# -gt 0 ]]; then
  TARGET_HOST="$1"
  info "Target overridden: $TARGET_HOST"
fi

# ── Docker scan ───────────────────────────────────────────────────────────────
if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
  FOUND=$(docker ps --format '{{.Names}}|{{.Image}}' 2>/dev/null \
    | grep -iE '(postfix|mail|smtp|mta)' | head -1 || true)
  if [[ -n "$FOUND" ]]; then
    CONTAINER_NAME=$(echo "$FOUND" | cut -d'|' -f1)
    CONTAINER_IMAGE=$(echo "$FOUND" | cut -d'|' -f2)
    DEPLOY_MODE="docker"
    info "Docker container detected: ${BOLD}$CONTAINER_NAME${RESET} ($CONTAINER_IMAGE)"
  fi
fi

# ── System Postfix scan ───────────────────────────────────────────────────────
if systemctl is-active --quiet postfix 2>/dev/null; then
  if [[ "$DEPLOY_MODE" == "unknown" ]]; then
    DEPLOY_MODE="baremetal"
    info "System Postfix detected (bare-metal mode)"
  else
    info "System Postfix also present (Docker container takes priority)"
  fi
fi

if [[ "$DEPLOY_MODE" == "unknown" ]]; then
  echo -e "\n  ${RED}No running Postfix detected (Docker or system). Is it running?${RESET}"
  exit 1
fi

info "Mode:   ${BOLD}$DEPLOY_MODE${RESET}"
info "Target: ${BOLD}$TARGET_HOST${RESET}"
echo ""

# =============================================================================
# 1. SERVICE & CONTAINER HEALTH
# =============================================================================
header "1. Service & Container Health"

if [[ "$DEPLOY_MODE" == "docker" ]]; then
  section "Docker Container"

  STATUS=$(docker inspect "$CONTAINER_NAME" --format '{{.State.Status}}' 2>/dev/null)
  if [[ "$STATUS" == "running" ]]; then
    pass "Container is running (status: $STATUS)"
  else
    fail "Container is not running (status: $STATUS)"
  fi

  RESTARTS=$(docker inspect "$CONTAINER_NAME" --format '{{.RestartCount}}' 2>/dev/null)
  if [[ "$RESTARTS" -eq 0 ]]; then
    pass "Container restart count: $RESTARTS"
  elif [[ "$RESTARTS" -lt 3 ]]; then
    warn "Container has restarted $RESTARTS times"
  else
    fail "Container has restarted $RESTARTS times — check logs"
  fi

  HEALTH=$(docker inspect "$CONTAINER_NAME" --format '{{.State.Health.Status}}' 2>/dev/null || echo "none")
  case "$HEALTH" in
    healthy)   pass "Health check: $HEALTH" ;;
    starting)  warn "Health check: still starting" ;;
    unhealthy) fail "Health check: UNHEALTHY" ;;
    none)      warn "No health check configured" ;;
    *)         warn "Health check status: $HEALTH" ;;
  esac

  section "Port Mappings"
  PORTS=$(docker inspect "$CONTAINER_NAME" \
    --format '{{range $p,$b := .NetworkSettings.Ports}}{{$p}}->{{range $b}}{{.HostPort}}{{end}} {{end}}' \
    2>/dev/null)
  info "Mapped ports: $PORTS"

  if echo "$PORTS" | grep -q "587"; then
    pass "Port 587 (submission) is mapped"
  else
    fail "Port 587 (submission) is NOT mapped"
  fi
  if echo "$PORTS" | grep -q "465"; then
    pass "Port 465 (smtps) is mapped"
  else
    fail "Port 465 (smtps) is NOT mapped"
  fi
  if echo "$PORTS" | grep -q "25[^0-9]"; then
    fail "Port 25 is mapped — should be DISABLED for this project"
  else
    pass "Port 25 is NOT mapped (correctly disabled)"
  fi

  section "Container Security Config"

  NO_NEW_PRIV=$(docker inspect "$CONTAINER_NAME" \
    --format '{{.HostConfig.SecurityOpt}}' 2>/dev/null)
  if echo "$NO_NEW_PRIV" | grep -q "no-new-privileges"; then
    pass "no-new-privileges: enabled"
  else
    warn "no-new-privileges: not set"
  fi

  CAP_DROP=$(docker inspect "$CONTAINER_NAME" \
    --format '{{.HostConfig.CapDrop}}' 2>/dev/null)
  if echo "$CAP_DROP" | grep -qi "ALL"; then
    pass "Capabilities: cap_drop ALL is set"
  else
    warn "Capabilities: cap_drop ALL not detected — $CAP_DROP"
  fi

  CONTAINER_USER=$(docker exec "$CONTAINER_NAME" id -u 2>/dev/null || echo "unknown")
  if [[ "$CONTAINER_USER" == "0" ]]; then
    warn "Postfix may be running as root inside container (uid 0)"
  else
    pass "Postfix not running as root (uid: $CONTAINER_USER)"
  fi

else
  section "System Postfix"

  if systemctl is-active --quiet postfix; then
    pass "Postfix service is active"
  else
    fail "Postfix service is not running"
  fi

  if systemctl is-enabled --quiet postfix; then
    pass "Postfix is enabled on boot"
  else
    warn "Postfix is not enabled on boot"
  fi

  # postfix check
  if postfix check 2>/dev/null; then
    pass "postfix check: configuration is valid"
  else
    fail "postfix check: configuration has errors"
  fi
fi

# =============================================================================
# 2. PORT & CONNECTIVITY CHECKS
# =============================================================================
header "2. Port & Connectivity Checks"

section "Listening Ports"

if command -v ss &>/dev/null; then
  PORT587=$(ss -tlnp 2>/dev/null | grep ":587 " || true)
  PORT465=$(ss -tlnp 2>/dev/null | grep ":465 " || true)
  PORT25=$(ss -tlnp  2>/dev/null | grep ":25 "  || true)

  if [[ -n "$PORT587" ]]; then
    pass "Port 587 (submission) is listening"
  else
    fail "Port 587 (submission) is NOT listening"
  fi
  if [[ -n "$PORT465" ]]; then
    pass "Port 465 (smtps) is listening"
  else
    fail "Port 465 (smtps) is NOT listening"
  fi
  if [[ -n "$PORT25" ]]; then
    fail "Port 25 is listening — should be DISABLED"
  else
    pass "Port 25 is NOT listening (correctly disabled)"
  fi
else
  warn "ss not available — skipping port listener checks"
fi

section "SMTP Banner (port 587)"
BANNER=$(timeout 5 bash -c "echo QUIT | nc -w3 $TARGET_HOST 587 2>/dev/null" | head -1 || echo "")
if [[ -n "$BANNER" ]]; then
  pass "Port 587 responds: $BANNER"
  # Check banner does not leak software version
  if echo "$BANNER" | grep -qiE "postfix/[0-9]"; then
    fail "Banner leaks Postfix version — set smtp_banner in main.cf"
  else
    pass "Banner does not leak version info"
  fi
else
  warn "No banner received on port 587 (nc may not be installed, or port is filtered)"
fi

# =============================================================================
# 3. TLS PROTOCOL CHECKS
# =============================================================================
header "3. TLS Protocol Checks"

section "Port 587 — STARTTLS"

# TLS 1.2 should be ACCEPTED
TLS12_OUT=$(smtp_tls_check "$TARGET_HOST" 587 starttls "-tls1_2" 2>/dev/null || true)
if echo "$TLS12_OUT" | grep -q "Protocol  : TLSv1.2"; then
  pass "Port 587 — TLS 1.2: accepted"
elif echo "$TLS12_OUT" | grep -q "Cipher"; then
  pass "Port 587 — TLS 1.2: handshake succeeded"
else
  warn "Port 587 — TLS 1.2: could not verify (openssl may not support -tls1_2 flag on this build)"
fi

# TLS 1.3 should be ACCEPTED
TLS13_OUT=$(smtp_tls_check "$TARGET_HOST" 587 starttls "-tls1_3" 2>/dev/null || true)
if echo "$TLS13_OUT" | grep -q "Protocol  : TLSv1.3"; then
  pass "Port 587 — TLS 1.3: accepted"
elif echo "$TLS13_OUT" | grep -q "Cipher"; then
  pass "Port 587 — TLS 1.3: handshake succeeded"
else
  warn "Port 587 — TLS 1.3: not detected (may not be supported by this openssl build)"
fi

# TLS 1.1 should be REJECTED
TLS11_OUT=$(smtp_tls_check "$TARGET_HOST" 587 starttls "-tls1_1" 2>/dev/null || true)
if echo "$TLS11_OUT" | grep -qiE "no protocols available|handshake failure|alert|errno"; then
  pass "Port 587 — TLS 1.1: correctly rejected"
elif [[ -z "$TLS11_OUT" ]]; then
  pass "Port 587 — TLS 1.1: connection refused (correctly rejected)"
else
  fail "Port 587 — TLS 1.1: may have been accepted — verify manually"
fi

# TLS 1.0 should be REJECTED
TLS10_OUT=$(smtp_tls_check "$TARGET_HOST" 587 starttls "-tls1" 2>/dev/null || true)
if echo "$TLS10_OUT" | grep -qiE "no protocols available|handshake failure|alert|errno"; then
  pass "Port 587 — TLS 1.0: correctly rejected"
elif [[ -z "$TLS10_OUT" ]]; then
  pass "Port 587 — TLS 1.0: connection refused (correctly rejected)"
else
  fail "Port 587 — TLS 1.0: may have been accepted — verify manually"
fi

section "Port 465 — Implicit TLS (SMTPS)"

TLS465_OUT=$(smtp_tls_check "$TARGET_HOST" 465 wrapper "" 2>/dev/null || true)
if echo "$TLS465_OUT" | grep -q "Cipher"; then
  pass "Port 465 — TLS handshake: succeeded"
  TLS465_PROTO=$(echo "$TLS465_OUT" | grep "Protocol" | awk '{print $3}' | tr -d '\r')
  if [[ -n "$TLS465_PROTO" ]]; then
    info "Port 465 — Protocol negotiated: $TLS465_PROTO"
    if [[ "$TLS465_PROTO" == "TLSv1.2" || "$TLS465_PROTO" == "TLSv1.3" ]]; then
      pass "Port 465 — Protocol is TLS 1.2 or 1.3"
    else
      fail "Port 465 — Unexpected protocol: $TLS465_PROTO"
    fi
  fi
else
  fail "Port 465 — TLS handshake failed or port not reachable"
fi

# =============================================================================
# 4. CIPHER SUITE CHECKS
# =============================================================================
header "4. Cipher Suite Checks"

section "Port 587 — Active Cipher"

CIPHER_OUT=$(smtp_tls_check "$TARGET_HOST" 587 starttls "" 2>/dev/null || true)
ACTIVE_CIPHER=$(echo "$CIPHER_OUT" | grep "^Cipher" | awk '{print $3}' | tr -d '\r' || true)
ACTIVE_PROTO=$(echo "$CIPHER_OUT"  | grep "^Protocol" | awk '{print $3}' | tr -d '\r' || true)

if [[ -n "$ACTIVE_CIPHER" ]]; then
  info "Negotiated cipher:   $ACTIVE_CIPHER"
  info "Negotiated protocol: $ACTIVE_PROTO"

  # Check for ECDHE or DHE (PFS)
  if echo "$ACTIVE_CIPHER" | grep -qE "^(ECDHE|DHE)"; then
    pass "Cipher uses PFS key exchange (ECDHE/DHE): $ACTIVE_CIPHER"
  else
    fail "Cipher does NOT use PFS — ECDHE or DHE required: $ACTIVE_CIPHER"
  fi

  # Check for GCM or CHACHA20 (AEAD)
  if echo "$ACTIVE_CIPHER" | grep -qE "GCM|CHACHA20|POLY1305"; then
    pass "Cipher uses AEAD mode (GCM/CHACHA20): $ACTIVE_CIPHER"
  else
    warn "Cipher may not be AEAD — check cipher suite config: $ACTIVE_CIPHER"
  fi

  # Check for weak ciphers
  if echo "$ACTIVE_CIPHER" | grep -qiE "RC4|DES|3DES|NULL|EXPORT|MD5|ANON"; then
    fail "Weak cipher negotiated: $ACTIVE_CIPHER"
  else
    pass "No weak cipher components detected"
  fi
else
  warn "Could not determine active cipher — is port 587 reachable?"
fi

section "Weak Cipher Rejection"

# Try to force RC4 — should be rejected
RC4_OUT=$(timeout 10 openssl s_client \
  -connect "${TARGET_HOST}:587" \
  -starttls smtp \
  -cipher "RC4" \
  </dev/null 2>/dev/null || true)
if echo "$RC4_OUT" | grep -qiE "no ciphers available|handshake failure|no shared cipher"; then
  pass "RC4 cipher: correctly rejected"
else
  warn "RC4 rejection could not be confirmed — verify manually with: openssl s_client -connect $TARGET_HOST:587 -starttls smtp -cipher RC4"
fi

# Try to force 3DES — should be rejected
DES3_OUT=$(timeout 10 openssl s_client \
  -connect "${TARGET_HOST}:587" \
  -starttls smtp \
  -cipher "3DES" \
  </dev/null 2>/dev/null || true)
if echo "$DES3_OUT" | grep -qiE "no ciphers available|handshake failure|no shared cipher"; then
  pass "3DES cipher: correctly rejected"
else
  warn "3DES rejection could not be confirmed — verify manually"
fi

# =============================================================================
# 5. SSL CERTIFICATE CHECKS
# =============================================================================
header "5. SSL Certificate"

section "Certificate Details (port 587)"

CERT_OUT=$(smtp_tls_check "$TARGET_HOST" 587 starttls "" 2>/dev/null || true)
CERT_INFO=$(echo "$CERT_OUT" | openssl x509 -noout \
  -subject -issuer -dates -fingerprint 2>/dev/null || echo "")

if [[ -z "$CERT_INFO" ]]; then
  # Fallback: try fetching cert directly
  CERT_INFO=$(echo | timeout 10 openssl s_client \
    -connect "${TARGET_HOST}:587" \
    -starttls smtp \
    </dev/null 2>/dev/null \
    | openssl x509 -noout -subject -issuer -dates 2>/dev/null || echo "")
fi

if [[ -z "$CERT_INFO" ]]; then
  fail "Could not retrieve SSL certificate from port 587"
else
  SUBJECT=$(echo "$CERT_INFO"  | grep "subject=" | sed 's/subject=//')
  ISSUER=$(echo "$CERT_INFO"   | grep "issuer="  | sed 's/issuer=//')
  NOT_AFTER=$(echo "$CERT_INFO" | grep "notAfter=" | sed 's/notAfter=//')

  info "Subject:  $SUBJECT"
  info "Issuer:   $ISSUER"
  info "Expires:  $NOT_AFTER"

  # Self-signed check
  if [[ "$SUBJECT" == "$ISSUER" ]]; then
    warn "Certificate is self-signed (replace with Let's Encrypt for production)"
  else
    pass "Certificate is CA-signed"
  fi

  # Domain match
  if echo "$SUBJECT" | grep -q "$TARGET_HOST"; then
    pass "Certificate CN matches target host: $TARGET_HOST"
  else
    warn "Certificate CN may not match $TARGET_HOST — check SAN entries"
  fi

  # Expiry
  EXPIRY_DATE=$(echo "$CERT_INFO" | grep "notAfter=" | sed 's/notAfter=//')
  if [[ -n "$EXPIRY_DATE" ]]; then
    EXPIRY_EPOCH=$(date -d "$EXPIRY_DATE" +%s 2>/dev/null \
      || date -j -f "%b %d %T %Y %Z" "$EXPIRY_DATE" +%s 2>/dev/null || echo 0)
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

  # Key size check
  KEY_BITS=$(echo "$CERT_OUT" | openssl x509 -noout -text 2>/dev/null \
    | grep "Public-Key:" | grep -oE "[0-9]+" | head -1 || echo "")
  if [[ -n "$KEY_BITS" ]]; then
    if [[ "$KEY_BITS" -ge 4096 ]]; then
      pass "Key size: ${KEY_BITS}-bit (strong)"
    elif [[ "$KEY_BITS" -ge 2048 ]]; then
      warn "Key size: ${KEY_BITS}-bit (acceptable, 4096 preferred)"
    else
      fail "Key size: ${KEY_BITS}-bit (too weak — minimum 2048)"
    fi
  fi
fi

# =============================================================================
# 6. SASL AUTHENTICATION CHECKS
# =============================================================================
header "6. SASL Authentication"

section "Auth Enforcement (port 587)"

# STARTTLS must complete before AUTH is offered — test via raw SMTP
AUTH_TEST=$(timeout 10 bash -c "
  {
    sleep 1
    echo 'EHLO verify-test.local'
    sleep 1
    echo 'QUIT'
  } | openssl s_client -connect ${TARGET_HOST}:587 -starttls smtp -quiet 2>/dev/null
" || true)

if echo "$AUTH_TEST" | grep -q "AUTH"; then
  pass "AUTH advertised after STARTTLS on port 587"
  if echo "$AUTH_TEST" | grep -q "PLAIN\|LOGIN"; then
    pass "AUTH mechanisms include PLAIN/LOGIN (standard for SASL)"
  else
    warn "No PLAIN/LOGIN AUTH mechanism detected — check SASL config"
  fi
else
  warn "AUTH not detected in EHLO response — may require STARTTLS first (expected)"
fi

section "Plain-text Auth Rejection (port 587 pre-TLS)"

# Try AUTH before STARTTLS — must be rejected
PLAIN_AUTH=$(timeout 8 bash -c "
  {
    sleep 0.5
    echo 'EHLO verify-test.local'
    sleep 0.5
    echo 'AUTH PLAIN dGVzdAB0ZXN0AHRlc3Q='
    sleep 0.5
    echo 'QUIT'
  } | nc -w5 ${TARGET_HOST} 587 2>/dev/null
" || true)

if echo "$PLAIN_AUTH" | grep -qE "^530|^538|^534"; then
  pass "Plain-text AUTH before TLS correctly rejected (5xx response)"
elif echo "$PLAIN_AUTH" | grep -q "STARTTLS"; then
  pass "Server requires STARTTLS before AUTH (smtpd_tls_auth_only working)"
else
  warn "Could not confirm plain-text AUTH rejection — verify smtpd_tls_auth_only=yes"
fi

section "Unauthenticated Relay Rejection"

# Try to relay without auth — must be rejected
RELAY_TEST=$(timeout 8 bash -c "
  {
    sleep 0.5
    echo 'EHLO verify-test.local'
    sleep 0.5
    echo 'MAIL FROM:<test@external.com>'
    sleep 0.5
    echo 'RCPT TO:<victim@another-external.com>'
    sleep 0.5
    echo 'QUIT'
  } | nc -w5 ${TARGET_HOST} 587 2>/dev/null
" || true)

if echo "$RELAY_TEST" | grep -qE "^554|^550|^530|^535|^503"; then
  pass "Unauthenticated relay: correctly rejected"
elif echo "$RELAY_TEST" | grep -q "Relay access denied"; then
  pass "Unauthenticated relay: rejected (Relay access denied)"
else
  warn "Relay rejection could not be confirmed — verify smtpd_relay_restrictions"
fi

# =============================================================================
# 7. POSTFIX CONFIG CHECKS
# =============================================================================
header "7. Postfix Configuration"

get_main_cf() {
  if [[ "$DEPLOY_MODE" == "docker" ]]; then
    docker exec "$CONTAINER_NAME" cat /etc/postfix/main.cf 2>/dev/null || echo ""
  else
    cat /etc/postfix/main.cf 2>/dev/null || echo ""
  fi
}

get_master_cf() {
  if [[ "$DEPLOY_MODE" == "docker" ]]; then
    docker exec "$CONTAINER_NAME" cat /etc/postfix/master.cf 2>/dev/null || echo ""
  else
    cat /etc/postfix/master.cf 2>/dev/null || echo ""
  fi
}

MAIN_CF=$(get_main_cf)
MASTER_CF=$(get_master_cf)

if [[ -z "$MAIN_CF" ]]; then
  fail "Could not read main.cf"
else
  section "TLS Settings"

  # TLS security level — should be encrypt (not may, since port 25 is disabled)
  TLS_LEVEL=$(echo "$MAIN_CF" | grep "^smtpd_tls_security_level" | awk -F'=' '{print $2}' | xargs)
  if [[ "$TLS_LEVEL" == "encrypt" ]]; then
    pass "smtpd_tls_security_level = encrypt (mandatory TLS)"
  elif [[ "$TLS_LEVEL" == "may" ]]; then
    warn "smtpd_tls_security_level = may (opportunistic — should be 'encrypt' since port 25 is disabled)"
  else
    warn "smtpd_tls_security_level = '${TLS_LEVEL:-not set}'"
  fi

  # Auth only over TLS
  if echo "$MAIN_CF" | grep -q "smtpd_tls_auth_only.*=.*yes"; then
    pass "smtpd_tls_auth_only = yes"
  else
    fail "smtpd_tls_auth_only not set to yes — auth may be allowed without TLS"
  fi

  # Protocol exclusions
  PROTOCOLS=$(echo "$MAIN_CF" | grep "^smtpd_tls_protocols" | cut -d'=' -f2- | xargs)
  if echo "$PROTOCOLS" | grep -qE "!TLSv1\.1" && echo "$PROTOCOLS" | grep -qE "!TLSv1[^\.2]?[^3]?"; then
    pass "smtpd_tls_protocols: TLS 1.0 and 1.1 disabled ($PROTOCOLS)"
  else
    warn "smtpd_tls_protocols: could not confirm TLS 1.0/1.1 are disabled — check: $PROTOCOLS"
  fi

  # DH params
  if echo "$MAIN_CF" | grep -q "smtpd_tls_dh1024_param_file"; then
    DH_FILE=$(echo "$MAIN_CF" | grep "smtpd_tls_dh1024_param_file" | cut -d'=' -f2 | xargs)
    if [[ "$DEPLOY_MODE" == "baremetal" ]] && [[ -f "$DH_FILE" ]]; then
      DH_SIZE=$(openssl dhparam -in "$DH_FILE" -text -noout 2>/dev/null \
        | grep "DH Parameters" | grep -oE "[0-9]+" | head -1 || echo "unknown")
      if [[ "$DH_SIZE" -ge 4096 ]]; then
        pass "DH parameters: ${DH_SIZE}-bit (strong)"
      else
        warn "DH parameters: ${DH_SIZE}-bit (4096 preferred)"
      fi
    else
      pass "DH parameters file configured: $DH_FILE"
    fi
  else
    fail "DH parameters (smtpd_tls_dh1024_param_file) not configured"
  fi

  # Cipher exclusions
  EXCL=$(echo "$MAIN_CF" | grep "smtpd_tls_exclude_ciphers" | cut -d'=' -f2- | xargs)
  if [[ -n "$EXCL" ]]; then
    pass "smtpd_tls_exclude_ciphers: $EXCL"
    for BAD in RC4 DES 3DES NULL EXPORT; do
      if echo "$EXCL" | grep -qi "$BAD"; then
        pass "  Excluded cipher: $BAD"
      else
        warn "  $BAD not in smtpd_tls_exclude_ciphers — consider adding it"
      fi
    done
  else
    warn "smtpd_tls_exclude_ciphers not set — weak ciphers may be available"
  fi

  section "Anti-Relay & Restrictions"

  if echo "$MAIN_CF" | grep -q "reject_unauth_destination"; then
    pass "Open relay protection: reject_unauth_destination present"
  else
    fail "reject_unauth_destination NOT found — server may be an open relay"
  fi

  if echo "$MAIN_CF" | grep -q "smtpd_helo_required.*=.*yes"; then
    pass "HELO required: yes"
  else
    warn "smtpd_helo_required not set to yes"
  fi

  if echo "$MAIN_CF" | grep -q "disable_vrfy_command.*=.*yes"; then
    pass "VRFY command: disabled (anti-enumeration)"
  else
    warn "disable_vrfy_command not set — VRFY may expose local users"
  fi

  if echo "$MAIN_CF" | grep -q "reject_unauth_pipelining"; then
    pass "Pipelining abuse: reject_unauth_pipelining set"
  else
    warn "reject_unauth_pipelining not configured"
  fi

  # RBL checks
  if echo "$MAIN_CF" | grep -q "reject_rbl_client"; then
    RBL_LIST=$(echo "$MAIN_CF" | grep "reject_rbl_client" | grep -oE "reject_rbl_client [^ ,]+" | awk '{print $2}' | tr '\n' ' ')
    pass "RBL checks configured: $RBL_LIST"
  else
    warn "No RBL (DNS blacklist) checks configured"
  fi

  # Connection rate limiting
  if echo "$MAIN_CF" | grep -q "smtpd_client_connection_rate_limit"; then
    RATE=$(echo "$MAIN_CF" | grep "smtpd_client_connection_rate_limit" | cut -d'=' -f2 | xargs)
    pass "Connection rate limit: $RATE per minute"
  else
    warn "smtpd_client_connection_rate_limit not set"
  fi

  section "Master.cf Port Configuration"

  if [[ -n "$MASTER_CF" ]]; then
    # Port 587 submission entry
    if echo "$MASTER_CF" | grep -qE "^submission"; then
      pass "master.cf: submission (port 587) service defined"
      if echo "$MASTER_CF" | grep -A5 "^submission" | grep -q "smtpd_tls_security_level=encrypt"; then
        pass "master.cf: submission enforces TLS (smtpd_tls_security_level=encrypt)"
      else
        warn "master.cf: submission TLS enforcement not confirmed"
      fi
      if echo "$MASTER_CF" | grep -A5 "^submission" | grep -q "smtpd_sasl_auth_enable=yes"; then
        pass "master.cf: submission enables SASL auth"
      else
        fail "master.cf: submission SASL auth not enabled"
      fi
    else
      fail "master.cf: submission (port 587) service NOT defined"
    fi

    # Port 465 smtps entry
    if echo "$MASTER_CF" | grep -qE "^smtps"; then
      pass "master.cf: smtps (port 465) service defined"
      if echo "$MASTER_CF" | grep -A5 "^smtps" | grep -q "smtpd_tls_wrappermode=yes"; then
        pass "master.cf: smtps uses TLS wrapper mode (implicit TLS)"
      else
        warn "master.cf: smtpd_tls_wrappermode not set for smtps"
      fi
    else
      fail "master.cf: smtps (port 465) service NOT defined"
    fi

    # Port 25 must NOT be active
    if echo "$MASTER_CF" | grep -qE "^smtp[[:space:]]+inet" && \
       ! echo "$MASTER_CF" | grep -E "^smtp[[:space:]]+inet" | grep -q "^#"; then
      fail "master.cf: port 25 (smtp inet) is ACTIVE — should be disabled"
    else
      pass "master.cf: port 25 (smtp inet) is disabled"
    fi
  else
    warn "Could not read master.cf"
  fi
fi

# =============================================================================
# 8. DKIM CHECKS
# =============================================================================
header "8. DKIM"

section "OpenDKIM Service"

if [[ "$DEPLOY_MODE" == "baremetal" ]]; then
  if systemctl is-active --quiet opendkim 2>/dev/null; then
    pass "OpenDKIM service is running"
  else
    warn "OpenDKIM service is not running (DKIM signing disabled)"
  fi

  if [[ -f /etc/opendkim.conf ]]; then
    pass "OpenDKIM config file exists: /etc/opendkim.conf"

    if grep -q "^Socket" /etc/opendkim.conf; then
      SOCK=$(grep "^Socket" /etc/opendkim.conf | awk '{print $2}')
      pass "OpenDKIM socket: $SOCK"
    else
      warn "OpenDKIM Socket not configured"
    fi

    if grep -q "^KeyTable" /etc/opendkim.conf; then
      pass "OpenDKIM KeyTable configured"
    else
      warn "OpenDKIM KeyTable not configured"
    fi

    if grep -q "^SigningTable" /etc/opendkim.conf; then
      pass "OpenDKIM SigningTable configured"
    else
      warn "OpenDKIM SigningTable not configured"
    fi
  else
    warn "OpenDKIM config not found at /etc/opendkim.conf"
  fi

  # Check milter wired into Postfix
  if [[ -n "$MAIN_CF" ]]; then
    if echo "$MAIN_CF" | grep -q "smtpd_milters.*8891\|smtpd_milters.*opendkim"; then
      pass "Postfix milter: OpenDKIM wired via smtpd_milters"
    else
      warn "OpenDKIM milter not found in smtpd_milters — DKIM signing may not work"
    fi
  fi

  # Key file check
  if [[ -d /etc/opendkim/keys ]]; then
    KEY_COUNT=$(find /etc/opendkim/keys -name "*.private" 2>/dev/null | wc -l)
    if [[ "$KEY_COUNT" -gt 0 ]]; then
      pass "DKIM private key(s) found: $KEY_COUNT key(s)"
      find /etc/opendkim/keys -name "*.private" 2>/dev/null | while read -r KEY; do
        KPERMS=$(stat -c "%a" "$KEY" 2>/dev/null || stat -f "%Lp" "$KEY" 2>/dev/null || echo "unknown")
        if [[ "$KPERMS" == "600" ]]; then
          pass "  Key permissions OK (600): $KEY"
        else
          warn "  Key permissions too open ($KPERMS): $KEY — should be 600"
        fi
      done
    else
      warn "No DKIM private keys found in /etc/opendkim/keys"
    fi
  fi

else
  # Docker mode — check milter config
  if [[ -n "$MAIN_CF" ]] && echo "$MAIN_CF" | grep -q "smtpd_milters"; then
    pass "Postfix milter configured (DKIM likely active)"
  else
    warn "DKIM milter not detected in container config"
  fi
fi

section "DKIM DNS Record"

# Try to detect the mail domain from main.cf
MAIL_DOMAIN=""
if [[ -n "$MAIN_CF" ]]; then
  MAIL_DOMAIN=$(echo "$MAIN_CF" | grep "^mydomain" | cut -d'=' -f2 | xargs)
fi

if [[ -n "$MAIL_DOMAIN" ]]; then
  info "Checking DKIM DNS record for domain: $MAIL_DOMAIN"
  DKIM_DNS=$(dig +short TXT "mail._domainkey.$MAIL_DOMAIN" 2>/dev/null | head -1 || echo "")
  if [[ -n "$DKIM_DNS" ]]; then
    pass "DKIM TXT record found: mail._domainkey.$MAIL_DOMAIN"
    if echo "$DKIM_DNS" | grep -q "v=DKIM1"; then
      pass "DKIM TXT record has valid v=DKIM1 tag"
    else
      warn "DKIM TXT record may be malformed — does not start with v=DKIM1"
    fi
  else
    warn "No DKIM TXT record found for mail._domainkey.$MAIL_DOMAIN — add to Route 53"
  fi
else
  warn "Could not detect mail domain from main.cf — skipping DKIM DNS check"
fi

# =============================================================================
# 9. SPF / DMARC / MTA-STS DNS CHECKS
# =============================================================================
header "9. SPF / DMARC / MTA-STS"

# Detect domain
DOMAIN_TO_CHECK=""
if [[ -n "$MAIL_DOMAIN" ]]; then
  DOMAIN_TO_CHECK="$MAIL_DOMAIN"
elif [[ "$TARGET_HOST" != "localhost" ]]; then
  DOMAIN_TO_CHECK="$TARGET_HOST"
fi

if [[ -z "$DOMAIN_TO_CHECK" ]]; then
  warn "Cannot check DNS records — no domain detected. Pass your domain as argument: sudo $0 mail.example.com"
else
  section "SPF Record"
  SPF=$(dig +short TXT "$DOMAIN_TO_CHECK" 2>/dev/null | grep "v=spf1" | head -1 || echo "")
  if [[ -n "$SPF" ]]; then
    pass "SPF TXT record found: $SPF"
    if echo "$SPF" | grep -q "~all\|-all"; then
      pass "SPF has a restrictive all mechanism (~all or -all)"
    else
      warn "SPF uses ?all or +all — consider ~all or -all"
    fi
  else
    fail "No SPF TXT record found for $DOMAIN_TO_CHECK — add to Route 53"
  fi

  section "DMARC Record"
  DMARC=$(dig +short TXT "_dmarc.$DOMAIN_TO_CHECK" 2>/dev/null | head -1 || echo "")
  if [[ -n "$DMARC" ]]; then
    pass "DMARC TXT record found: $DMARC"
    if echo "$DMARC" | grep -q "p=reject"; then
      pass "DMARC policy: reject (strongest)"
    elif echo "$DMARC" | grep -q "p=quarantine"; then
      pass "DMARC policy: quarantine (good)"
    elif echo "$DMARC" | grep -q "p=none"; then
      warn "DMARC policy: none (monitoring only — upgrade to quarantine/reject)"
    fi
    if echo "$DMARC" | grep -q "rua="; then
      pass "DMARC has aggregate reporting (rua) configured"
    else
      warn "DMARC has no rua= reporting address — consider adding one"
    fi
  else
    fail "No DMARC TXT record found for _dmarc.$DOMAIN_TO_CHECK — add to Route 53"
  fi

  section "MTA-STS Record"
  MTASTS=$(dig +short TXT "_mta-sts.$DOMAIN_TO_CHECK" 2>/dev/null | head -1 || echo "")
  if [[ -n "$MTASTS" ]]; then
    pass "MTA-STS TXT record found: $MTASTS"
    if echo "$MTASTS" | grep -q "v=STSv1"; then
      pass "MTA-STS has valid v=STSv1 tag"
    else
      warn "MTA-STS record may be malformed"
    fi
  else
    warn "No MTA-STS TXT record found for _mta-sts.$DOMAIN_TO_CHECK"
  fi

  section "MX Record"
  MX=$(dig +short MX "$DOMAIN_TO_CHECK" 2>/dev/null | head -3 || echo "")
  if [[ -n "$MX" ]]; then
    pass "MX record found: $MX"
  else
    warn "No MX record found for $DOMAIN_TO_CHECK — mail delivery will fail"
  fi
fi

# =============================================================================
# 10. FIREWALL CHECKS
# =============================================================================
header "10. Firewall"

if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld 2>/dev/null; then
  section "firewalld"

  PORTS_OPEN=$(firewall-cmd --list-ports 2>/dev/null)

  if echo "$PORTS_OPEN" | grep -q "587/tcp"; then
    pass "firewalld: port 587/tcp (submission) is open"
  else
    warn "firewalld: port 587/tcp not found in --list-ports (may be opened by service)"
  fi

  if echo "$PORTS_OPEN" | grep -q "465/tcp"; then
    pass "firewalld: port 465/tcp (smtps) is open"
  else
    warn "firewalld: port 465/tcp not found in --list-ports"
  fi

  if echo "$PORTS_OPEN" | grep -q "25/tcp"; then
    fail "firewalld: port 25/tcp is OPEN — should be closed"
  else
    pass "firewalld: port 25/tcp is NOT open (correctly blocked)"
  fi

  ZONE=$(firewall-cmd --get-default-zone 2>/dev/null)
  info "Default firewall zone: $ZONE"

elif command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  section "ufw"

  UFW_STATUS=$(ufw status 2>/dev/null)

  if echo "$UFW_STATUS" | grep -q "587"; then
    pass "ufw: port 587 is allowed"
  else
    warn "ufw: port 587 not found in rules"
  fi

  if echo "$UFW_STATUS" | grep -q "465"; then
    pass "ufw: port 465 is allowed"
  else
    warn "ufw: port 465 not found in rules"
  fi

  if echo "$UFW_STATUS" | grep -qE "^25[[:space:]]"; then
    fail "ufw: port 25 is ALLOWED — should be blocked"
  else
    pass "ufw: port 25 is NOT allowed (correctly blocked)"
  fi

else
  warn "No active firewall manager detected (firewalld/ufw) — skipping firewall checks"
fi

section "AWS Security Group Reminder"
info "If running on AWS EC2, also verify your Security Group:"
info "  ✔ Inbound 587/tcp — allowed (your mail clients)"
info "  ✔ Inbound 465/tcp — allowed (your mail clients)"
info "  ✗ Inbound 25/tcp  — should NOT be open (AWS blocks outbound 25 anyway)"

# =============================================================================
# 11. LOG CHECKS
# =============================================================================
header "11. Log Verification"

if [[ "$DEPLOY_MODE" == "docker" ]]; then
  section "Container Logs"
  RECENT_LOGS=$(docker logs --tail 30 "$CONTAINER_NAME" 2>&1 || echo "")

  if echo "$RECENT_LOGS" | grep -qiE "panic|fatal"; then
    fail "Fatal errors found in recent logs"
    echo "$RECENT_LOGS" | grep -iE "panic|fatal" | sed 's/^/         /'
  else
    pass "No fatal errors in recent container logs"
  fi

  if echo "$RECENT_LOGS" | grep -qi "TLS connection established"; then
    pass "TLS connection established entries found in logs (TLS working)"
  else
    warn "No TLS connection log entries found — send a test email to confirm"
  fi

  if echo "$RECENT_LOGS" | grep -qi "warning\|error"; then
    warn "Warnings/errors found in recent logs (may be normal):"
    echo "$RECENT_LOGS" | grep -i "warning\|error" | tail -3 | sed 's/^/         /'
  fi

else
  section "System Mail Log"
  MAIL_LOG=""
  for LOG_FILE in /var/log/mail.log /var/log/maillog; do
    if [[ -f "$LOG_FILE" ]]; then
      MAIL_LOG="$LOG_FILE"
      break
    fi
  done

  if [[ -n "$MAIL_LOG" ]]; then
    pass "Mail log found: $MAIL_LOG"
    RECENT=$(tail -50 "$MAIL_LOG" 2>/dev/null || echo "")

    if echo "$RECENT" | grep -qi "TLS connection established"; then
      pass "TLS connection entries found in mail log"
    else
      warn "No recent TLS connection entries — send a test email to verify"
    fi

    if echo "$RECENT" | grep -qi "fatal\|panic"; then
      fail "Fatal errors found in mail log"
      echo "$RECENT" | grep -i "fatal\|panic" | tail -3 | sed 's/^/         /'
    else
      pass "No fatal errors in recent mail log"
    fi
  else
    warn "Mail log not found — checked /var/log/mail.log and /var/log/maillog"
    info "Try: journalctl -u postfix -n 50"
  fi
fi

# =============================================================================
# FINAL SCORE
# =============================================================================
header "Verification Complete — Final Score"

echo ""
echo -e "  ${BOLD}Results:${RESET}"
echo -e "  ${GREEN}${BOLD}PASS: $PASS${RESET}   ${RED}${BOLD}FAIL: $FAIL${RESET}   ${YELLOW}${BOLD}WARN: $WARN${RESET}   Total: $TOTAL"
echo ""

# Guard against division by zero
if [[ $TOTAL -eq 0 ]]; then
  echo -e "  ${YELLOW}${BOLD}No checks completed.${RESET}"
  exit 1
fi

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
  echo ""
fi

if [[ $WARN -gt 0 ]]; then
  echo -e "  ${YELLOW}${BOLD}Warnings:${RESET}"
  echo -e "  Review the [WARN] items above — not critical but worth improving."
  echo ""
fi

echo -e "  ${CYAN}${BOLD}Next steps:${RESET}"
echo -e "   • Replace self-signed cert with Let's Encrypt (DNS-01 via Route 53)"
echo -e "   • Test TLS:   openssl s_client -connect $TARGET_HOST:587 -starttls smtp"
echo -e "   • Test SMTPS: openssl s_client -connect $TARGET_HOST:465"
echo -e "   • Online:     https://www.checktls.com/"
echo -e "   • Online:     https://mxtoolbox.com/diagnostic.aspx"
echo -e "   • Online:     https://mail-tester.com  (send a test email)"
echo -e "   • DMARC:      https://dmarcian.com/dmarc-inspector/"
echo ""

exit $FAIL
