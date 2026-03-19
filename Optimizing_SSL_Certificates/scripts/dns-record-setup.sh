#!/bin/bash

################################################################################
# Script Name:  dns-record-setup.sh
# Version:      1.2
# Description:  Automated DNS records for gwallofchina.yulcyberhub.click
#               Hardened SPF (ip4 + mx) and DMARC (Reject + Reporting + Strict)
# Author:       Mrblue
# Date:         2026-03-19
# Requirements: AWS CLI, Authorized SSO Session
################################################################################

# Usage: ./dns-record-setup.sh <HOSTED_ZONE_ID>
if [ -z "$1" ]; then
    echo "❌ Error: Please provide your Hosted Zone ID."
    echo "Usage: $0 Z0123456789ABCDEF"
    exit 1
fi

ZONE_ID=$1
DOMAIN="gwallofchina.yulcyberhub.click"
STAGING_IP="127.0.0.1" 
STAGING_IPV6="::0"

# Placeholder for your OpenDKIM public key
DKIM_KEY="MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...[REPLACE_WITH_YOUR_KEY]"

echo "🛠️ Executing $0 v1.2 for $DOMAIN..."

cat <<EOF > dns_batch.json
{
  "Comment": "Lab Task 1: Automated Deployment of Hardened DNS Infrastructure v1.2",
  "Changes": [
    { "Action": "UPSERT", "ResourceRecordSet": { "Name": "$DOMAIN.", "Type": "A", "TTL": 300, "ResourceRecords": [{ "Value": "$STAGING_IP" }] } },
    { "Action": "UPSERT", "ResourceRecordSet": { "Name": "$DOMAIN.", "Type": "AAAA", "TTL": 300, "ResourceRecords": [{ "Value": "$STAGING_IPV6" }] } },
    { "Action": "UPSERT", "ResourceRecordSet": { "Name": "www.$DOMAIN.", "Type": "CNAME", "TTL": 300, "ResourceRecords": [{ "Value": "$DOMAIN" }] } },
    { "Action": "UPSERT", "ResourceRecordSet": { "Name": "mail.$DOMAIN.", "Type": "A", "TTL": 300, "ResourceRecords": [{ "Value": "$STAGING_IP" }] } },
    { "Action": "UPSERT", "ResourceRecordSet": { "Name": "$DOMAIN.", "Type": "MX", "TTL": 300, "ResourceRecords": [{ "Value": "10 mail.$DOMAIN." }] } },
    { "Action": "UPSERT", "ResourceRecordSet": { "Name": "$DOMAIN.", "Type": "CAA", "TTL": 300, "ResourceRecords": [{ "Value": "0 issue \"letsencrypt.org\"" }] } },
    { "Action": "UPSERT", "ResourceRecordSet": { "Name": "$DOMAIN.", "Type": "TXT", "TTL": 300, "ResourceRecords": [{ "Value": "\"v=spf1 ip4:$STAGING_IP mx -all\"" }] } },
    { "Action": "UPSERT", "ResourceRecordSet": { "Name": "_dmarc.$DOMAIN.", "Type": "TXT", "TTL": 300, "ResourceRecords": [{ "Value": "\"v=DMARC1; p=reject; rua=mailto:admin@$DOMAIN; ruf=mailto:admin@$DOMAIN; sp=reject; adkim=s; aspf=s\"" }] } },
    { "Action": "UPSERT", "ResourceRecordSet": { "Name": "default._domainkey.$DOMAIN.", "Type": "TXT", "TTL": 300, "ResourceRecords": [{ "Value": "\"v=DKIM1; k=rsa; p=$DKIM_KEY\"" }] } },
    { "Action": "UPSERT", "ResourceRecordSet": { "Name": "_mta-sts.$DOMAIN.", "Type": "TXT", "TTL": 300, "ResourceRecords": [{ "Value": "\"v=STSv1; id=$(date +%Y%m%d%H%M)\"" }] } },
    { "Action": "UPSERT", "ResourceRecordSet": { "Name": "_smtp._tls.$DOMAIN.", "Type": "TXT", "TTL": 300, "ResourceRecords": [{ "Value": "\"v=TLSRPTv1; rua=mailto:admin@$DOMAIN\"" }] } },
    { "Action": "UPSERT", "ResourceRecordSet": { "Name": "_autodiscover._tcp.$DOMAIN.", "Type": "SRV", "TTL": 300, "ResourceRecords": [{ "Value": "0 0 443 mail.$DOMAIN." }] } },
    { "Action": "UPSERT", "ResourceRecordSet": { "Name": "_visual_hash.$DOMAIN.", "Type": "TXT", "TTL": 300, "ResourceRecords": [{ "Value": "\"v=vh1; h=7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1f\"" }] } }
  ]
}
EOF

echo "🚀 Pushing records to Route 53 (dns-record-setup.sh v1.2)..."
aws route53 change-resource-record-sets --hosted-zone-id "$ZONE_ID" --change-batch file://dns_batch.json

if [ $? -eq 0 ]; then
    echo "✅ Successfully deployed all 13 security records."
    rm dns_batch.json
else
    echo "❌ Failed to update records. Check your AWS permissions or Zone ID."
fi
