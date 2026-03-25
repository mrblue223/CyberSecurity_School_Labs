# 🛡️ AWS CLI Setup Guide
> 🔐 SSO Authentication + EC2 Instance Deployment  
> **MEQ7 — Room 3 — Vanier College Cyber Defense 2026**

---

## 📚 Table of Contents
- [Part 1 — AWS SSO Configuration](#part-1--aws-sso-configuration)
  - [Prerequisites](#prerequisites)
  - [Step 1 — Clean Existing AWS Config](#step-1--clean-existing-aws-config)
  - [Step 2 — Run the SSO Configuration Wizard](#step-2--run-the-sso-configuration-wizard)
  - [Step 3 — Approve Browser Authentication](#step-3--approve-browser-authentication)
  - [Step 4 — Verify the Connection](#step-4--verify-the-connection)
  - [Daily Usage](#daily-usage)
- [Part 2 — EC2 Instance Launch Script](#part-2--ec2-instance-launch-script)
  - [Instance Configuration](#instance-configuration)
  - [Tags Applied](#tags-applied)
  - [The Script — launch-instance.sh](#the-script--launch-instancesh)
  - [How to Use](#how-to-use)
  - [Reusing for a Different Lab](#reusing-for-a-different-lab)
- [Quick Reference](#quick-reference)

---

## 🔑 Part 1 — AWS SSO Configuration

This section documents how to configure the AWS CLI to authenticate using IAM Identity Center (SSO). This only needs to be done once — credentials are cached and renewed automatically.

### ✅ Prerequisites

- AWS CLI v2 installed on your machine
- Access to the AWS SSO portal: `https://d-90660512c9.awsapps.com/start`
- SSO Start URL and SSO Region provided by the lab instructor

---

### 🧹 Step 1 — Clean Existing AWS Config

Remove any previous credentials that may conflict.

> ⚠️ **Why clean first?** Existing Access Key credentials conflict with SSO. A clean start prevents authentication errors.

```bash
# Remove all existing AWS configuration
rm -rf ~/.aws/credentials ~/.aws/config ~/.aws/sso

# Verify the directory is clean
ls ~/.aws/
```

---

### 🧙 Step 2 — Run the SSO Configuration Wizard

```bash
aws configure sso
```

Fill in the wizard with the following values:

| Prompt | Value to Enter |
|--------|---------------|
| SSO session name | `meq7` |
| SSO start URL | `https://d-90660512c9.awsapps.com/start` |
| SSO region | `us-east-1` |
| SSO registration scopes | `sso:account:access` |
| Default client Region | `us-east-1` |
| CLI default output format | `json` |
| Profile name | `meq7` |

---

### 🌐 Step 3 — Approve Browser Authentication

The CLI will automatically open your default browser with an AWS authorization page.

> ℹ️ Click **"Allow access"** when the page asks:  
> *"Allow botocore-client-meq7 to access your data?"*  
> This grants the CLI access to your AWS account.

The CLI will then automatically select:
- **Account:** `453875232433` (YulCyberClick Demo)
- **Role:** `MEQ7_RBAC_Room3`

---

### 🔍 Step 4 — Verify the Connection

```bash
aws sts get-caller-identity --profile meq7
```

Expected output:

```json
{
    "UserId": "AROAWTLISN2Y6EWMYGBGN:meq7_paulo",
    "Account": "453875232433",
    "Arn": "arn:aws:sts::453875232433:assumed-role/AWSReservedSSO_MEQ7_RBAC_Room3_.../meq7_paulo"
}
```

> ✅ **Success!** You are now authenticated. Temporary credentials are cached in `~/.aws/sso/cache/`

---

### 📅 Daily Usage

SSO credentials expire periodically. To renew them:

```bash
# Login / renew credentials
aws sso login --profile meq7

# Logout and clear cached credentials
aws sso logout

# Always append --profile meq7 to every command
aws sts get-caller-identity --profile meq7
aws ec2 describe-instances --profile meq7
```

---

## 🚀 Part 2 — EC2 Instance Launch Script

This section documents the `launch-instance.sh` script created to deploy an EC2 instance from the terminal using the AWS CLI, without touching the AWS Console.

### ⚙️ Instance Configuration

| Parameter | Value |
|-----------|-------|
| AMI | `ami-0c421724a94bba6d6` (Amazon Linux 2023) |
| Instance Type | `t3.small` (2 vCPU, 2GB RAM) |
| Key Pair | `thegreatfirewallofchina` (ED25519, .pem format) |
| Security Group | `sg-0c7a7efce68ce2773` (Meq7 - Room3 - The Real Deal) |
| VPC | `vpc-02a24edaa08acb420` (Default) |
| Public IP | Auto-assigned (enabled) |
| IMDSv2 | Required (`HttpTokens: required`) |
| Storage | 15 GB gp3 (3000 IOPS, 125 MB/s) |
| SSH User | `ec2-user` |

### 🏷️ Tags Applied

| Tag Key | Tag Value |
|---------|-----------|
| Name | `CLI_Test` |
| Cohort | `MEQ7` |
| Team | `Room3` |

---

### 📜 The Script — launch-instance.sh

The script uses variables defined at the top — to reuse for a different lab, only the `CONFIG` block needs to be updated. All values below are applied automatically.

```bash
#!/bin/bash
# Bash Script to create a VM on AWS straight from the PC Terminal
# Template — Change the values after the = to customize your instance
# By doing this, it will automatically update the entire script below

# ── CONFIG ─────────────────────────────────────────────
AMI="ami-0c421724a94bba6d6"
INSTANCE_TYPE="t3.small"
KEY_NAME="thegreatfirewallofchina"
SECURITY_GROUP="sg-0c7a7efce68ce2773"
VM_NAME="CLI_Test"
COHORT="MEQ7"
TEAM="Room3"
PROFILE="meq7"
# ────────────────────────────────────────────────────────

aws ec2 run-instances \
  --image-id "$AMI" \
  --instance-type "$INSTANCE_TYPE" \
  --key-name "$KEY_NAME" \
  --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"Encrypted":false,"DeleteOnTermination":true,"Iops":3000,"VolumeSize":15,"VolumeType":"gp3","Throughput":125}}]' \
  --network-interfaces '[{"AssociatePublicIpAddress":true,"DeviceIndex":0,"Groups":["'"$SECURITY_GROUP"'"]}]' \
  --tag-specifications \
    '{"ResourceType":"instance","Tags":[{"Key":"Name","Value":"'"$VM_NAME"'"},{"Key":"Cohort","Value":"'"$COHORT"'"},{"Key":"Team","Value":"'"$TEAM"'"}]}' \
    '{"ResourceType":"volume","Tags":[{"Key":"Name","Value":"'"$VM_NAME"'"},{"Key":"Cohort","Value":"'"$COHORT"'"},{"Key":"Team","Value":"'"$TEAM"'"}]}' \
  --metadata-options '{"HttpEndpoint":"enabled","HttpPutResponseHopLimit":2,"HttpTokens":"required"}' \
  --private-dns-name-options '{"HostnameType":"ip-name","EnableResourceNameDnsARecord":true,"EnableResourceNameDnsAAAARecord":false}' \
  --count '1' \
  --profile "$PROFILE"

# Run: chmod +x launch-instance.sh && ./launch-instance.sh
```

---

### 🛠️ How to Use

**Step 1 — 💾 Save the script**
```bash
nano launch-instance.sh
# Paste the script, save with Ctrl+O → Enter → Ctrl+X
```

**Step 2 — 🔓 Make it executable** *(only needed once)*
```bash
chmod +x launch-instance.sh
```

**Step 3 — 🔑 Login to AWS SSO**
```bash
aws sso login --profile meq7
```

**Step 4 — ▶️ Run the script**
```bash
./launch-instance.sh
```

**Step 5 — 🖥️ Connect via SSH**
```bash
# Fix key permissions (required by SSH)
chmod 400 thegreatfirewallofchina.pem

# Get the public IP
aws ec2 describe-instances \
  --filters 'Name=tag:Name,Values=CLI_Test' \
  --query 'Reservations[*].Instances[*].PublicIpAddress' \
  --output text \
  --profile meq7

# Connect (Amazon Linux 2023 default user = ec2-user)
ssh -i thegreatfirewallofchina.pem ec2-user@YOUR_PUBLIC_IP
```

---

### 🔄 Reusing for a Different Lab

To deploy a new instance for a different lab, only update the `CONFIG` block at the top:

```bash
# ── CONFIG — change only these values ────────────────
AMI="ami-XXXXXXXXX"          # New OS AMI
INSTANCE_TYPE="t3.medium"    # Different size if needed
KEY_NAME="NewKeyPair"        # Different key pair
SECURITY_GROUP="sg-XXXXXXX"  # Different security group
VM_NAME="WebServer"          # New instance name
COHORT="MEQ7"                # Keep same cohort
TEAM="Room3"                 # Keep same team
PROFILE="meq7"               # Keep same profile
# ────────────────────────────────────────────────────
```

> 💡 **Pro Tip:** Everything below the CONFIG block stays untouched. The variables (`$AMI`, `$VM_NAME`, etc.) are replaced automatically when the script runs.

---

## ⚡ Quick Reference

| Task | Command |
|------|---------|
| 🔑 Login to AWS SSO | `aws sso login --profile meq7` |
| 🔍 Verify identity | `aws sts get-caller-identity --profile meq7` |
| 🚪 Logout | `aws sso logout` |
| 🚀 Launch EC2 | `./launch-instance.sh` |
| 📋 List instances | `aws ec2 describe-instances --profile meq7` |
| 🖥️ SSH to instance | `ssh -i thegreatfirewallofchina.pem ec2-user@IP` |
| 🔒 Fix key permissions | `chmod 400 thegreatfirewallofchina.pem` |
| ⚙️ Make script executable | `chmod +x launch-instance.sh` |

---

*Vanier College — Cyber Defense Program — MEQ7 Room 3 — 2026*
