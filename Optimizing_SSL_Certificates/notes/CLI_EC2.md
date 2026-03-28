# 🛡️ AWS CLI Setup Guide

> 🔐 **SSO Authentication + EC2 Instance Deployment**
> 🎓 **Vanier College — Cyber Defense 2026**
> 👥 **Team:** MEQ7 — Room 3
> ✍️ **Author:** Paulo Borelli

---

## 📚 Table of Contents

* [🔑 Part 1 — AWS SSO Configuration](#-part-1--aws-sso-configuration)

  * [🛑 Security Warning](#-security-warning-static-vs-ephemeral-keys)
  * [✅ Prerequisites](#-prerequisites)
  * [🧹 Step 1 — Clean Existing AWS Config](#-step-1--clean-existing-aws-config)
  * [🧙 Step 2 — Configure SSO](#-step-2--run-the-sso-configuration-wizard)
  * [🌐 Step 3 — Browser Authentication](#-step-3--approve-browser-authentication)
  * [🔍 Step 4 — Verify Connection](#-step-4--verify-the-connection)
  * [📅 Daily Usage](#-daily-usage)
* [🚀 Part 2 — EC2 Instance Launch Script](#-part-2--ec2-instance-launch-script)
* [⚡ Quick Reference](#-quick-reference)

---

## 🔑 Part 1 — AWS SSO Configuration

### 🛑 Security Warning: Static vs. Ephemeral Keys

Running `aws configure` stores **long-lived credentials in plaintext** (`~/.aws/credentials`).

👉 If compromised:

* attacker gets persistent access
* no expiration
* high risk of account takeover

### 🛡️ Secure Alternatives

1. **AWS SSO (Primary)**
   → Short-lived credentials via browser authentication

2. **aws-vault (Alternative)**
   → Stores secrets in OS keystore + generates ephemeral sessions

---

## ✅ Prerequisites

* AWS CLI v2 installed
* Access to SSO portal:
  `https://d-90660512c9.awsapps.com/start`
* SSO region + access provided by instructor

---

## 🧹 Step 1 — Clean Existing AWS Config

```bash id="f8c2pq"
rm -rf ~/.aws/credentials ~/.aws/config ~/.aws/sso
ls ~/.aws/
```

---

## 🧙 Step 2 — Run the SSO Configuration Wizard

```bash id="3e8z1u"
aws configure sso
```

### Fill with:

| Prompt       | Value                                    |
| ------------ | ---------------------------------------- |
| Session name | `meq7`                                   |
| Start URL    | `https://d-90660512c9.awsapps.com/start` |
| Region       | `us-east-1`                              |
| Scope        | `sso:account:access`                     |
| Output       | `json`                                   |
| Profile      | `meq7`                                   |

---

## 🌐 Step 3 — Approve Browser Authentication

* Browser opens automatically
* Click **Allow access**

Selected:

* Account: `453875232433`
* Role: `MEQ7_RBAC_Room3`

---

## 🔍 Step 4 — Verify the Connection

```bash id="az8y0c"
aws sts get-caller-identity --profile meq7
```

Expected:

```json id="i8ozp9"
{
  "Account": "453875232433"
}
```

---

## 📅 Daily Usage

```bash id="w2hf5v"
aws sso login --profile meq7
aws sso logout
aws sts get-caller-identity --profile meq7
```

---

## 🚀 Part 2 — EC2 Instance Launch Script

### ⚙️ Configuration

| Parameter      | Value       |
| -------------- | ----------- |
| AMI            | Rocky Linux |
| Instance       | t3.small    |
| Storage        | 15GB gp3    |
| Security Group | Room3       |
| IMDSv2         | Required    |

---

### 📜 Script — `launch-instance.sh`

```bash id="p3t9xm"
#!/bin/bash

# CONFIG
AMI="ami-059807ea93f3306ee"
INSTANCE_TYPE="t3.small"
KEY_NAME="thegreatfirewallofchina"
SECURITY_GROUP="sg-0c7a7efce68ce2773"
VM_NAME="Web-Server-Server"
COHORT="MEQ7"
TEAM="Room3"
PROFILE="meq7"

aws ec2 run-instances \
  --image-id "$AMI" \
  --instance-type "$INSTANCE_TYPE" \
  --key-name "$KEY_NAME" \
  --network-interfaces '[{"AssociatePublicIpAddress":true,"DeviceIndex":0,"Groups":["'"$SECURITY_GROUP"'"]}]' \
  --tag-specifications \
    '{"ResourceType":"instance","Tags":[{"Key":"Name","Value":"'"$VM_NAME"'"}]}' \
  --metadata-options '{"HttpTokens":"required"}' \
  --count 1 \
  --profile "$PROFILE"
```

---

## 🛠️ How to Use

### 1. Save script

```bash id="tds8uy"
nano launch-instance.sh
```

### 2. Make executable

```bash id="c8r7vd"
chmod +x launch-instance.sh
```

### 3. Login

```bash id="6p9l1n"
aws sso login --profile meq7
```

### 4. Run

```bash id="y2gxj9"
./launch-instance.sh
```

---

## 🖥️ SSH Access

```bash id="mb3t2a"
chmod 400 thegreatfirewallofchina.pem
ssh -i thegreatfirewallofchina.pem ec2-user@YOUR_IP
```

---

## 🔄 Reuse for Other Labs

Update only:

```bash id="bz7j2q"
AMI="new-ami"
INSTANCE_TYPE="t3.medium"
KEY_NAME="new-key"
SECURITY_GROUP="sg-new"
```

---

## ⚡ Quick Reference

| Task   | Command                        |
| ------ | ------------------------------ |
| Login  | `aws sso login --profile meq7` |
| Verify | `aws sts get-caller-identity`  |
| Launch | `./launch-instance.sh`         |
| SSH    | `ssh -i key.pem ec2-user@IP`   |

---
