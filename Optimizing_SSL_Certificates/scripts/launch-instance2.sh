#!/bin/bash
# 🛡️ Secure EC2 Deployment Script — MEQ7 Room 3
# Author: Paulo Borelli

# ── CONFIG ─────────────────────────────────────────────
AMI="ami-0c421724a94bba6d6"
INSTANCE_TYPE="t3.small"
KEY_NAME="thegreatfirewallofchina"
SECURITY_GROUP="sg-0c7a7efce68ce2773"
VM_NAME="CLI_Test"
COHORT="MEQ7"
TEAM="Room3"
PROFILE="meq7"
REGION="us-east-1"
# ───────────────────────────────────────────────────────

echo "🚀 Launching EC2 instance..."

aws ec2 run-instances \
  --region "$REGION" \
  --image-id "$AMI" \
  --instance-type "$INSTANCE_TYPE" \
  --key-name "$KEY_NAME" \
  --block-device-mappings '[
    {
      "DeviceName": "/dev/xvda",
      "Ebs": {
        "VolumeSize": 15,
        "VolumeType": "gp3",
        "DeleteOnTermination": true,
        "Encrypted": false,
        "Iops": 3000,
        "Throughput": 125
      }
    }
  ]' \
  --network-interfaces '[
    {
      "AssociatePublicIpAddress": true,
      "DeviceIndex": 0,
      "Groups": ["'"$SECURITY_GROUP"'"]
    }
  ]' \
  --tag-specifications '[
    {
      "ResourceType": "instance",
      "Tags": [
        {"Key": "Name", "Value": "'"$VM_NAME"'"},
        {"Key": "Cohort", "Value": "'"$COHORT"'"},
        {"Key": "Team", "Value": "'"$TEAM"'"}
      ]
    },
    {
      "ResourceType": "volume",
      "Tags": [
        {"Key": "Name", "Value": "'"$VM_NAME"'"},
        {"Key": "Cohort", "Value": "'"$COHORT"'"},
        {"Key": "Team", "Value": "'"$TEAM"'"}
      ]
    }
  ]' \
  --metadata-options '{
    "HttpEndpoint": "enabled",
    "HttpPutResponseHopLimit": 2,
    "HttpTokens": "required"
  }' \
  --private-dns-name-options '{
    "HostnameType": "ip-name",
    "EnableResourceNameDnsARecord": true,
    "EnableResourceNameDnsAAAARecord": false
  }' \
  --count 1 \
  --profile "$PROFILE"

echo "✅ Instance launched successfully!"
