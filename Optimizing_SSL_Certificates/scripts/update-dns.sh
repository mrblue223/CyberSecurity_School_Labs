#!/bin/bash

################################################################
#  ____  _            _____                      _             #
# |  _ \| |          |  __ \                    (_)            #
# | |_) | |_   _  ___| |  | |_ __  ___  ___  ___ _ _ __        #
# |  _ <| | | | |/ _ \ |  | | '_ \/ __|/ _ \/ __| | '_ \       #
# | |_) | | |_| |  __/ |__| | | | \__ \  __/ (__| | | | |      #
# |____/|_|\__,_|\___|_____/|_| |_|___/\___|\___|_|_| |_|      #
#                                                              #
# Author: mrblue                                               #
# Usage: Add to crontab via '@reboot' to auto-update Route 53  #
################################################################

echo "-------------------------------------------------------"
echo " Running DNS Update Script by mrblue"
echo " Updating record for gwallofchina.yulcyberhub.click"
echo "-------------------------------------------------------"

sleep 30
# Configuration
ZONE_ID="Z0433076DMIP84BGAZGN"
RECORD_NAME="gwallofchina.yulcyberhub.click"
TTL=300

# Get the current public IP via IMDSv2
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
PUBLIC_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/public-ipv4)

if [ -z "$PUBLIC_IP" ]; then
    echo "Error: Could not retrieve Public IP."
    exit 1
fi

echo "Current Public IP detected: $PUBLIC_IP"

# Create the JSON payload
cat <<EOF > /tmp/dns-update.json
{
  "Comment": "Auto-update DNS on boot - Authored by mrblue",
  "Changes": [
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "$RECORD_NAME",
        "Type": "A",
        "TTL": $TTL,
        "ResourceRecords": [{ "Value": "$PUBLIC_IP" }]
      }
    }
  ]
}
EOF

# Apply the update
aws route53 change-resource-record-sets --hosted-zone-id $ZONE_ID --change-batch file:///tmp/dns-update.json

if [ $? -eq 0 ]; then
    echo "DNS Update Submitted Successfully."
else
    echo "DNS Update Failed. Check IAM permissions."
fi
