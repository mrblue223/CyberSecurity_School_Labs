#!/bin/bash
################################################################################
# Script Name:  dns-record-setup.sh
# Version:      2.1
# Description:  Deploy all production DNS records for gwallofchina.yulcyberhub.click
# Author:       Mrblue
# Updated:      2026-04-04
# Requirements: AWS CLI, Authorized SSO Session
# Usage:        ./dns-record-setup.sh <HOSTED_ZONE_ID> <SERVER_IP> <DKIM_KEY_FILE>
# Example:      ./dns-record-setup.sh Z0433076DMIP84BGAZGN 54.226.198.180 /etc/opendkim/keys/gwallofchina.yulcyberhub.click/mail.txt
################################################################################

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ─── Arguments ───────────────────────────────────────────────────────────────
if [ "$#" -lt 3 ]; then
    echo -e "${RED}❌ Usage: $0 <HOSTED_ZONE_ID> <SERVER_IP> <DKIM_KEY_FILE>${NC}"
    echo -e "${YELLOW}Example: $0 Z0433076DMIP84BGAZGN 54.226.198.180 /etc/opendkim/keys/gwallofchina.yulcyberhub.click/mail.txt${NC}"
    exit 1
fi

ZONE_ID="$1"
SERVER_IP="$2"
DKIM_KEY_FILE="$3"

# ─── Config ──────────────────────────────────────────────────────────────────
DOMAIN="gwallofchina.yulcyberhub.click"
ADMIN_EMAIL="admin@${DOMAIN}"
MTA_STS_ID=$(date +%Y%m%d%H%M%S)

SENDGRID_SUBDOMAIN="u61568083.wl084.sendgrid.net"
SENDGRID_S1="s1.domainkey.u61568083.wl084.sendgrid.net"
SENDGRID_S2="s2.domainkey.u61568083.wl084.sendgrid.net"

# ─── Validate IP ─────────────────────────────────────────────────────────────
if ! echo "$SERVER_IP" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
    echo -e "${RED}❌ Invalid IP: $SERVER_IP${NC}"
    exit 1
fi

# ─── Read DKIM key ────────────────────────────────────────────────────────────
if [ ! -f "$DKIM_KEY_FILE" ]; then
    echo -e "${RED}❌ DKIM key file not found: $DKIM_KEY_FILE${NC}"
    exit 1
fi

DKIM_KEY=$(grep -oP '(?<=p=)[^"]+' "$DKIM_KEY_FILE" | tr -d '\n ')
if [ -z "$DKIM_KEY" ]; then
    echo -e "${RED}❌ Could not extract DKIM key from $DKIM_KEY_FILE${NC}"
    echo -e "${YELLOW}   File must be the opendkim-genkey .txt output${NC}"
    exit 1
fi

# ─── Header ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║       dns-record-setup.sh v2.1 — DNS Deploy         ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Domain:${NC}      $DOMAIN"
echo -e "  ${BOLD}Zone ID:${NC}     $ZONE_ID"
echo -e "  ${BOLD}Server IP:${NC}   $SERVER_IP"
echo -e "  ${BOLD}MTA-STS ID:${NC}  $MTA_STS_ID"
echo -e "  ${BOLD}DKIM Key:${NC}    loaded from $DKIM_KEY_FILE"
echo ""

# ─── Build batch ─────────────────────────────────────────────────────────────
cat > /tmp/dns_batch.json <<JSON
{
  "Comment": "Production DNS deployment v2.1 for ${DOMAIN}",
  "Changes": [

    {
      "Comment": "INFRASTRUCTURE",
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "${DOMAIN}.",
        "Type": "A",
        "TTL": 300,
        "ResourceRecords": [{ "Value": "${SERVER_IP}" }]
      }
    },
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "${DOMAIN}.",
        "Type": "AAAA",
        "TTL": 300,
        "ResourceRecords": [{ "Value": "0000:0000:0000:0000:0000:0000:0000:0000" }]
      }
    },
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "mail.${DOMAIN}.",
        "Type": "A",
        "TTL": 300,
        "ResourceRecords": [{ "Value": "${SERVER_IP}" }]
      }
    },
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "mta-sts.${DOMAIN}.",
        "Type": "A",
        "TTL": 300,
        "ResourceRecords": [{ "Value": "${SERVER_IP}" }]
      }
    },
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "www.${DOMAIN}.",
        "Type": "CNAME",
        "TTL": 300,
        "ResourceRecords": [{ "Value": "${DOMAIN}" }]
      }
    },

    {
      "Comment": "CAA",
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "${DOMAIN}.",
        "Type": "CAA",
        "TTL": 300,
        "ResourceRecords": [
          { "Value": "0 issue \"letsencrypt.org\"" },
          { "Value": "0 issue \"amazonaws.com\"" }
        ]
      }
    },

    {
      "Comment": "MAIL ROUTING",
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "${DOMAIN}.",
        "Type": "MX",
        "TTL": 300,
        "ResourceRecords": [{ "Value": "10 mail.${DOMAIN}." }]
      }
    },

    {
      "Comment": "SPF",
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "${DOMAIN}.",
        "Type": "TXT",
        "TTL": 300,
        "ResourceRecords": [
          { "Value": "\"v=spf1 ip4:${SERVER_IP} include:sendgrid.net mx ~all\"" }
        ]
      }
    },
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "spf.${DOMAIN}.",
        "Type": "TXT",
        "TTL": 300,
        "ResourceRecords": [
          { "Value": "\"v=spf1 ip4:${SERVER_IP} include:sendgrid.net ~all\"" }
        ]
      }
    },

    {
      "Comment": "DMARC",
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "_dmarc.${DOMAIN}.",
        "Type": "TXT",
        "TTL": 300,
        "ResourceRecords": [
          { "Value": "\"v=DMARC1; p=reject; rua=mailto:${ADMIN_EMAIL}; ruf=mailto:${ADMIN_EMAIL}; sp=reject; adkim=s; aspf=s\"" }
        ]
      }
    },

    {
      "Comment": "DKIM - local OpenDKIM signing key (selector: mail)",
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "mail._domainkey.${DOMAIN}.",
        "Type": "TXT",
        "TTL": 300,
        "ResourceRecords": [
          { "Value": "\"v=DKIM1; k=rsa; p=${DKIM_KEY}\"" }
        ]
      }
    },

    {
      "Comment": "DKIM - SendGrid fallback selectors",
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "s1._domainkey.${DOMAIN}.",
        "Type": "CNAME",
        "TTL": 300,
        "ResourceRecords": [{ "Value": "${SENDGRID_S1}" }]
      }
    },
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "s2._domainkey.${DOMAIN}.",
        "Type": "CNAME",
        "TTL": 300,
        "ResourceRecords": [{ "Value": "${SENDGRID_S2}" }]
      }
    },

    {
      "Comment": "SendGrid tracking subdomain",
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "em5287.${DOMAIN}.",
        "Type": "CNAME",
        "TTL": 300,
        "ResourceRecords": [{ "Value": "${SENDGRID_SUBDOMAIN}" }]
      }
    },

    {
      "Comment": "MTA-STS",
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "_mta-sts.${DOMAIN}.",
        "Type": "TXT",
        "TTL": 300,
        "ResourceRecords": [
          { "Value": "\"v=STSv1; id=${MTA_STS_ID}\"" }
        ]
      }
    },

    {
      "Comment": "TLS-RPT",
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "_smtp._tls.${DOMAIN}.",
        "Type": "TXT",
        "TTL": 300,
        "ResourceRecords": [
          { "Value": "\"v=TLSRPTv1; rua=mailto:${ADMIN_EMAIL}\"" }
        ]
      }
    },

    {
      "Comment": "Mail client autodiscovery",
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "_autodiscover._tcp.${DOMAIN}.",
        "Type": "SRV",
        "TTL": 300,
        "ResourceRecords": [{ "Value": "0 0 443 mail.${DOMAIN}." }]
      }
    },

    {
      "Comment": "SendGrid domain verification",
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "_visual_hash.${DOMAIN}.",
        "Type": "TXT",
        "TTL": 300,
        "ResourceRecords": [
          { "Value": "\"v=vh1; h=7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1f\"" }
        ]
      }
    }

  ]
}
JSON

# ─── Deploy ───────────────────────────────────────────────────────────────────
echo -e "${CYAN}Deploying records...${NC}"
echo ""

CHANGE_ID=$(aws route53 change-resource-record-sets \
    --hosted-zone-id "$ZONE_ID" \
    --change-batch file:///tmp/dns_batch.json \
    --query 'ChangeInfo.Id' \
    --output text)

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Deployment failed — check AWS permissions or Zone ID${NC}"
    rm -f /tmp/dns_batch.json
    exit 1
fi

rm -f /tmp/dns_batch.json
echo -e "${GREEN}✅ Submitted — Change ID: ${CHANGE_ID}${NC}"

echo -e "\n  Waiting for Route 53 propagation..."
aws route53 wait resource-record-sets-changed --id "$CHANGE_ID" \
    && echo -e "${GREEN}  ✅ Propagated${NC}" \
    || echo -e "${YELLOW}  ⚠️  Timed out — records may still be propagating${NC}"

# ─── Verify ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}━━━ Verification ━━━${NC}"
echo ""

check() {
    local label="$1" cmd="$2" expected="$3"
    local result
    result=$(eval "$cmd" 2>/dev/null)
    if echo "$result" | grep -q "$expected"; then
        echo -e "  ${GREEN}✅ ${label}${NC}"
    else
        echo -e "  ${RED}❌ ${label}${NC} — got: $result"
    fi
}

check "A — apex"                        "dig A ${DOMAIN} +short"                          "$SERVER_IP"
check "A — mail"                        "dig A mail.${DOMAIN} +short"                     "$SERVER_IP"
check "A — mta-sts"                     "dig A mta-sts.${DOMAIN} +short"                  "$SERVER_IP"
check "CNAME — www"                     "dig CNAME www.${DOMAIN} +short"                  "$DOMAIN"
check "MX"                              "dig MX ${DOMAIN} +short"                         "mail.${DOMAIN}"
check "CAA — letsencrypt"               "dig CAA ${DOMAIN} +short"                        "letsencrypt"
check "CAA — amazonaws"                 "dig CAA ${DOMAIN} +short"                        "amazonaws"
check "SPF — apex"                      "dig TXT ${DOMAIN} +short"                        "v=spf1"
check "SPF — includes sendgrid.net"     "dig TXT ${DOMAIN} +short"                        "sendgrid.net"
check "SPF — includes server IP"        "dig TXT ${DOMAIN} +short"                        "$SERVER_IP"
check "SPF — subdomain"                 "dig TXT spf.${DOMAIN} +short"                    "v=spf1"
check "DMARC"                           "dig TXT _dmarc.${DOMAIN} +short"                 "p=reject"
check "DMARC — adkim strict"            "dig TXT _dmarc.${DOMAIN} +short"                 "adkim=s"
check "DMARC — aspf strict"             "dig TXT _dmarc.${DOMAIN} +short"                 "aspf=s"
check "DKIM — mail._domainkey"          "dig TXT mail._domainkey.${DOMAIN} +short"        "v=DKIM1"
check "DKIM — real key present"         "dig TXT mail._domainkey.${DOMAIN} +short"        "MII"
check "DKIM — s1 CNAME"                 "dig CNAME s1._domainkey.${DOMAIN} +short"        "sendgrid"
check "DKIM — s2 CNAME"                 "dig CNAME s2._domainkey.${DOMAIN} +short"        "sendgrid"
check "SendGrid — em5287 CNAME"         "dig CNAME em5287.${DOMAIN} +short"               "sendgrid"
check "MTA-STS TXT"                     "dig TXT _mta-sts.${DOMAIN} +short"               "STSv1"
check "TLS-RPT TXT"                     "dig TXT _smtp._tls.${DOMAIN} +short"             "TLSRPTv1"
check "SRV — autodiscovery"             "dig SRV _autodiscover._tcp.${DOMAIN} +short"     "443"
check "Visual hash"                     "dig TXT _visual_hash.${DOMAIN} +short"           "v=vh1"

echo ""
RECORD_COUNT=$(aws route53 list-resource-record-sets \
    --hosted-zone-id "$ZONE_ID" \
    --query 'length(ResourceRecordSets)' \
    --output text 2>/dev/null)
echo -e "  ${BOLD}Total records in zone:${NC} $RECORD_COUNT"
echo ""
echo -e "${BOLD}╔══════════════════════════════════════╗${NC}"
echo -e "${BOLD}║        Deployment complete ✅         ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════╝${NC}"
echo ""
