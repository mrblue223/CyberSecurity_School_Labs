#!/bin/bash
# Great Wall PKI - Certificate Auto-Renewal Script
# Renews leaf certs 30 days before expiry
# Author: mrblue
# Version: 1.0

LOG="/var/log/gwall-cert-renewal.log"
CA_CRT="/etc/pki/great-wall-ca/intermediate.crt"
CA_KEY="/etc/pki/great-wall-ca/intermediate.key"
DAYS_BEFORE_EXPIRY=30

log() {
  echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') $1" | tee -a "$LOG"
}

check_expiry() {
  local cert=$1
  local expiry=$(openssl x509 -enddate -noout -in "$cert" | cut -d= -f2)
  local days_left=$(( ( $(date -d "$expiry" +%s) - $(date +%s) ) / 86400 ))
  echo $days_left
}

renew_indexer() {
  log "INFO: Checking indexer certificate..."
  local days=$(check_expiry /etc/wazuh-indexer/certs/indexer.pem)
  log "INFO: Indexer cert expires in $days days"
  if [ "$days" -le "$DAYS_BEFORE_EXPIRY" ]; then
    log "INFO: Renewing indexer certificate..."
    step certificate create wazuh-indexer.gwall.local /tmp/idx.crt /tmp/idx.key \
      --profile leaf \
      --ca "$CA_CRT" --ca-key "$CA_KEY" \
      --no-password --insecure --not-after 8760h \
      --kty RSA --size 2048
    if [ $? -ne 0 ]; then
      log "ERROR: Failed to generate indexer certificate"
      return 1
    fi
    openssl rsa -in /tmp/idx.key -out /tmp/idx-trad.key
    cp /tmp/idx.crt /etc/wazuh-indexer/certs/indexer.pem
    cp /tmp/idx-trad.key /etc/wazuh-indexer/certs/indexer-key.pem
    chown wazuh-indexer:wazuh-indexer \
      /etc/wazuh-indexer/certs/indexer.pem \
      /etc/wazuh-indexer/certs/indexer-key.pem
    chmod 640 \
      /etc/wazuh-indexer/certs/indexer.pem \
      /etc/wazuh-indexer/certs/indexer-key.pem
    rm -f /tmp/idx.crt /tmp/idx.key /tmp/idx-trad.key
    log "INFO: Indexer certificate renewed successfully"
    return 0
  fi
  return 2
}

renew_dashboard() {
  log "INFO: Checking dashboard certificate..."
  local days=$(check_expiry /etc/wazuh-dashboard/certs/dashboard.pem)
  log "INFO: Dashboard cert expires in $days days"
  if [ "$days" -le "$DAYS_BEFORE_EXPIRY" ]; then
    log "INFO: Renewing dashboard certificate..."
    step certificate create wazuh.gwall.local /tmp/dash.crt /tmp/dash.key \
      --profile leaf \
      --ca "$CA_CRT" --ca-key "$CA_KEY" \
      --no-password --insecure --not-after 8760h \
      --kty RSA --size 2048
    if [ $? -ne 0 ]; then
      log "ERROR: Failed to generate dashboard certificate"
      return 1
    fi
    openssl rsa -in /tmp/dash.key -out /tmp/dash-trad.key
    cat /tmp/dash.crt "$CA_CRT" > /tmp/dash-chain.pem
    cp /tmp/dash-chain.pem /etc/wazuh-dashboard/certs/dashboard.pem
    cp /tmp/dash-trad.key /etc/wazuh-dashboard/certs/dashboard-key.pem
    chown wazuh-dashboard:wazuh-dashboard \
      /etc/wazuh-dashboard/certs/dashboard.pem \
      /etc/wazuh-dashboard/certs/dashboard-key.pem
    chmod 640 \
      /etc/wazuh-dashboard/certs/dashboard.pem \
      /etc/wazuh-dashboard/certs/dashboard-key.pem
    rm -f /tmp/dash.crt /tmp/dash.key /tmp/dash-trad.key /tmp/dash-chain.pem
    log "INFO: Dashboard certificate renewed successfully"
    return 0
  fi
  return 2
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

run_securityadmin() {
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
  fi
}

log "INFO: ===== Starting Great Wall cert renewal check ====="

renew_indexer
INDEXER_STATUS=$?

renew_dashboard
DASHBOARD_STATUS=$?

renew_crl

if [ "$INDEXER_STATUS" -eq 0 ]; then
  log "INFO: Restarting wazuh-indexer..."
  systemctl restart wazuh-indexer
  sleep 30
  run_securityadmin
fi

if [ "$DASHBOARD_STATUS" -eq 0 ]; then
  log "INFO: Restarting wazuh-dashboard..."
  systemctl restart wazuh-dashboard
  sleep 60
fi

log "INFO: ===== Cert renewal check complete ====="
