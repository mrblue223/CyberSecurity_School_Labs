#!/bin/bash
# Great Wall PKI - Certificate Auto-Renewal Script
# Renews leaf certs 30 days before expiry
# Author: mrblue
# Version: 1.0

LOG="/var/log/gwall-cert-renewal.log"
CA_CRT="/etc/pki/great-wall-ca/intermediate.crt"
CA_KEY="/etc/pki/great-wall-ca/intermediate.key"
CHAIN_TMP="/tmp/chain-$$.pem"
DAYS_BEFORE_EXPIRY=30

log() {
  echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') $1" | tee -a "$LOG"
}

check_expiry() {
  local cert=$1
  local days_left=$(( ( $(date -d "$(openssl x509 -enddate -noout -in $cert | cut -d= -f2)" +%s) - $(date +%s) ) / 86400 ))
  echo $days_left
}

renew_indexer() {
  log "INFO: Checking indexer certificate..."
  local days=$(check_expiry /etc/wazuh-indexer/certs/indexer.pem)
  log "INFO: Indexer cert expires in $days days"

  if [ "$days" -le "$DAYS_BEFORE_EXPIRY" ]; then
    log "INFO: Renewing indexer certificate..."
    step certificate create wazuh-indexer.gwall.local /tmp/indexer-$$.crt /tmp/indexer-$$.key \
      --profile leaf \
      --ca "$CA_CRT" \
      --ca-key "$CA_KEY" \
      --no-password --insecure \
      --not-after 8760h \
      --kty RSA --size 2048

    if [ $? -ne 0 ]; then
      log "ERROR: Failed to generate indexer certificate"
      exit 1
    fi

    openssl rsa -in /tmp/indexer-$$.key -out /tmp/indexer-trad-$$.key
    cp /tmp/indexer-$$.crt /etc/wazuh-indexer/certs/indexer.pem
    cp /tmp/indexer-trad-$$.key /etc/wazuh-indexer/certs/indexer-key.pem
    chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs/indexer.pem \
      /etc/wazuh-indexer/certs/indexer-key.pem
    chmod 640 /etc/wazuh-indexer/certs/indexer.pem \
      /etc/wazuh-indexer/certs/indexer-key.pem
    rm -f /tmp/indexer-$$.crt /tmp/indexer-$$.key /tmp/indexer-trad-$$.key
    log "INFO: Indexer certificate renewed successfully"
    echo "RENEWED_INDEXER=true"
  else
    log "INFO: Indexer certificate OK - no renewal needed"
    echo "RENEWED_INDEXER=false"
  fi
}

renew_dashboard() {
  log "INFO: Checking dashboard certificate..."
  local days=$(check_expiry /etc/wazuh-dashboard/certs/dashboard.pem)
  log "INFO: Dashboard cert expires in $days days"

  if [ "$days" -le "$DAYS_BEFORE_EXPIRY" ]; then
    log "INFO: Renewing dashboard certificate..."
    step certificate create wazuh.gwall.local /tmp/dashboard-$$.crt /tmp/dashboard-$$.key \
      --profile leaf \
      --ca "$CA_CRT" \
      --ca-key "$CA_KEY" \
      --no-password --insecure \
      --not-after 8760h \
      --kty RSA --size 2048

    if [ $? -ne 0 ]; then
      log "ERROR: Failed to generate dashboard certificate"
      exit 1
    fi

    openssl rsa -in /tmp/dashboard-$$.key -out /tmp/dashboard-trad-$$.key
    cat /tmp/dashboard-$$.crt "$CA_CRT" > /tmp/dashboard-chain-$$.pem
    cp /tmp/dashboard-chain-$$.pem /etc/wazuh-dashboard/certs/dashboard.pem
    cp /tmp/dashboard-trad-$$.key /etc/wazuh-dashboard/certs/dashboard-key.pem
    chown wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs/dashboard.pem \
      /etc/wazuh-dashboard/certs/dashboard-key.pem
    chmod 640 /etc/wazuh-dashboard/certs/dashboard.pem \
      /etc/wazuh-dashboard/certs/dashboard-key.pem
    rm -f /tmp/dashboard-$$.crt /tmp/dashboard-$$.key \
      /tmp/dashboard-trad-$$.key /tmp/dashboard-chain-$$.pem
    log "INFO: Dashboard certificate renewed successfully"
    echo "RENEWED_DASHBOARD=true"
  else
    log "INFO: Dashboard certificate OK - no renewal needed"
    echo "RENEWED_DASHBOARD=false"
  fi
}

renew_crl() {
  log "INFO: Regenerating CRL..."
  openssl ca -gencrl \
    -config /etc/pki/great-wall-ca/openssl.cnf \
    -out /etc/pki/great-wall-ca/crl/intermediate.crl
  if [ $? -eq 0 ]; then
    log "INFO: CRL regenerated successfully"
  else
    log "ERROR: CRL regeneration failed"
  fi
}

restart_services() {
  local renewed_indexer=$1
  local renewed_dashboard=$2

  if [ "$renewed_indexer" = "true" ]; then
    log "INFO: Restarting wazuh-indexer..."
    systemctl restart wazuh-indexer
    sleep 30

    # Run securityadmin
    log "INFO: Running securityadmin..."
    env JAVA_HOME=/usr/share/wazuh-indexer/jdk \
    /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
      -cd /etc/wazuh-indexer/opensearch-security/ \
      -icl -nhnv \
      -cacert /etc/wazuh-indexer/certs/root-ca.pem \
      -cert /etc/wazuh-indexer/certs/indexer.pem \
      -key /etc/wazuh-indexer/certs/indexer-key.pem >> "$LOG" 2>&1

    if [ $? -eq 0 ]; then
      log "INFO: securityadmin completed successfully"
    else
      log "ERROR: securityadmin failed"
      exit 1
    fi
  fi

  if [ "$renewed_dashboard" = "true" ]; then
    log "INFO: Restarting wazuh-dashboard..."
    systemctl restart wazuh-dashboard
    sleep 60
  fi
}

# ─── MAIN ───────────────────────────────────────────────────
log "INFO: ===== Starting Great Wall cert renewal check ====="
INDEXER_RESULT=$(renew_indexer)
DASHBOARD_RESULT=$(renew_dashboard)
renew_crl

RENEWED_INDEXER=$(echo "$INDEXER_RESULT" | grep RENEWED_INDEXER | cut -d= -f2)
RENEWED_DASHBOARD=$(echo "$DASHBOARD_RESULT" | grep RENEWED_DASHBOARD | cut -d= -f2)

restart_services "$RENEWED_INDEXER" "$RENEWED_DASHBOARD"
log "INFO: ===== Cert renewal check complete ====="
