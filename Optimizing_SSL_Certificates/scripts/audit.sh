#!/bin/bash
# AWS Security Audit Script for Great Wall Project
# By mrblue
REGION="us-east-1"
INSTANCE_ID="i-0b71d405f8ad5f73b"
SECURITY_GROUP_ID="sg-0c7a7efce68ce2773"
DOMAIN="gwallofchina.yulcyberhub.click"

echo "=========================================="
echo "GREAT WALL PROJECT - SECURITY AUDIT"
echo "Date: $(date)"
echo "=========================================="

echo -e "\n--- SECURITY GROUP INBOUND RULES ---"
aws ec2 describe-security-groups \
    --group-ids $SECURITY_GROUP_ID \
    --region $REGION \
    --query 'SecurityGroups[0].[GroupName, GroupId, IpPermissions]' \
    --output table

echo -e "\n--- EC2 INSTANCE ATTACHMENT ---"
aws ec2 describe-instances \
    --instance-ids $INSTANCE_ID \
    --region $REGION \
    --query 'Reservations[0].Instances[0].[InstanceId, State.Name, PublicIpAddress, SecurityGroups]' \
    --output table

echo -e "\n--- ROUTE 53 HOSTED ZONE ---"
aws route53 list-hosted-zones-by-name \
    --dns-name $DOMAIN \
    --region $REGION \
    --query 'HostedZones[0].[Id, Name, Config.PrivateZone]' \
    --output table

echo -e "\n=========================================="
echo "AUDIT COMPLETE"
echo "=========================================="
