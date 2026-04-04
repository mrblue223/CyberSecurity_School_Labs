# Optimizing SSL/TLS Certificates for Nginx & Postfix

> **Author:** Sammy Roy · **Cohort:** MEQ7 · **Team:** Team 3
> **Domain:** `gwallofchina.yulcyberhub.click` · **Due:** April 2, 2026

---

## Team Contributions

| Team Member | Role | Key Contributions |
|---|---|---|
| **Sammy Roy** | Infrastructure Lead | SSL/TLS configuration (Nginx + Postfix/Dovecot) · DNSSEC implementation & setup (KMS CMK, KSK, zone signing) · DNS record architecture (18 records) · Certificate hardening · Security headers · Cipher suite selection · Automated verification scripts · Full documentation (60 screenshots) |
| **Paulo Borelli** | IAM & Automation Lead | AWS CLI setup documentation · AWS SSO authentication guide (eliminate static credentials) · IAM hardening policies (Instance-Based Access Control + Machine Identity profiles) · S3 anti-ransomware guardrails · `launch-instance.sh` EC2 launch automation script · IMDSv2 enforcement (`HttpTokens=required`) against SSRF |
| **Keeshon Bain** | Architecture & Consulting | Deployment-flow restructure (CLI → DNS → EC2 → Nginx → Postfix) · Technical consulting across all phases |
| **Marc-Olivier Hélie** | Documentation | Assignment reflection · Screenshot documentation |

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [Architecture Overview](#architecture-overview)
- [Phase 1 — AWS CLI & Credential Security](#phase-1--aws-cli--credential-security)
- [Phase 2 — DNS Infrastructure](#phase-2--dns-infrastructure)
- [Phase 3 — EC2 Instance & Security Groups](#phase-3--ec2-instance--security-groups)
- [Phase 4 — Nginx Web Server Hardening](#phase-4--nginx-web-server-hardening)
- [Phase 5 — Mail Server Hardening (Postfix & Dovecot)](#phase-5--mail-server-hardening-postfix--dovecot)
- [Phase 6 — Challenges & Trade-Offs](#phase-6--challenges--trade-offs)
- [References](#references)

---

## Executive Summary

This document is a comprehensive technical reflection on the **"Great Wall"** hardened SSL/TLS infrastructure project. The deployment follows a structured sequence: AWS credentials → DNS → EC2 → Nginx → Postfix/Dovecot. The project achieved **A+ ratings on SSL Labs for both web and mail services**, implementing zero-trust principles, modern cryptography, and defense-in-depth strategies across every layer.

| Component | Rating | Key Achievement |
|---|---|---|
| Web Server (Nginx) | A+ | TLS 1.3 · HSTS Preload · OCSP Stapling |
| Mail Server (Postfix/Dovecot) | A+ | SMTPS/IMAPS · SPF/DKIM/DMARC · MTA-STS |
| Certificate Score | 100/100 | Let's Encrypt SAN cert (ISRG Root X1) |
| Protocol Score | 100/100 | TLS 1.2 + 1.3 only; all legacy disabled |
| Key Exchange Score | 100/100 | ECDHE/DHE with 4096-bit DH params |
| Cipher Strength Score | 100/100 | AEAD-only suites (AES-GCM, ChaCha20) |

---

## Architecture Overview

```
Internet
    │
    ▼
Route 53 (DNS · MX → mail.gwallofchina.yulcyberhub.click)
    │
    ▼
AWS Security Group (Ports 25, 80, 443, 465, 587, 993)
    │
    ▼
EC2 Instance (Elastic IP: 54.226.198.180)
  ├── Nginx (Reverse Proxy — Port 443)
  │     ├── gwallofchina.yulcyberhub.click       → /var/www/html (castle page)
  │     ├── mail.gwallofchina.yulcyberhub.click  → Node.js :3000 (webmail)
  │     └── mta-sts.gwallofchina.yulcyberhub.click → /var/www/mta-sts (policy file)
  ├── Postfix (SMTP — Ports 25 inbound · 465 SMTPS · 587 submission)
  ├── OpenDKIM (DKIM milter — Port 8891 · signs all outbound mail)
  ├── Dovecot (IMAP — Port 993)
  ├── Node.js Webmail App (Internal — Port 3000)
  └── EBS Volume (/var/mail/vhosts)
    │
    ▼ (Inbound Mail — directly to Postfix port 25)
Sender MTA → MX lookup → mail.gwallofchina.yulcyberhub.click:25
    │
    ▼ (Outbound Mail — PRIMARY)
Direct SMTP to Recipient MX Servers (Port 25 · MX lookup · OpenDKIM signed)
    │
    ▼ (Outbound Mail — FALLBACK, activates only if direct delivery fails)
SendGrid Relay (Port 587 · STARTTLS)
    │
    ▼
Recipient Mail Servers
```

> **Note on inbound mail:** The MX record points directly to `mail.gwallofchina.yulcyberhub.click` (EC2 instance). Postfix receives inbound mail directly on port 25. Port 25 is open in the AWS security group and unblocked at the account level by Oracle (instructor).

> **Note on outbound mail:** Postfix is configured with an empty `relayhost` (direct delivery via MX lookup) as the **primary** path. All outbound mail is signed by OpenDKIM before leaving the server. `fallback_relay = [smtp.sendgrid.net]:587` activates automatically only when direct delivery fails.

---

## Phase 1 — AWS CLI & Credential Security

### 1.1 Threat Model

Running `aws configure` stores long-lived access keys in plaintext under `~/.aws/credentials`. If that file is compromised:

- The attacker gains **persistent** AWS access with no expiration
- No automatic revocation or detection
- High risk of full account takeover

Two complementary solutions were implemented to eliminate this attack surface entirely.

### 1.2 Secure Alternatives: SSO vs. aws-vault

| Approach | Mechanism | When Used |
|---|---|---|
| **AWS SSO** (primary) | Short-lived credentials via browser authentication | All lab CLI operations against the organizational account |
| **aws-vault** (alternative) | Stores secrets in OS keystore + generates ephemeral STS sessions | Workstation-level credential isolation for automation |

### 1.3 aws-vault — Encrypted Keyring Credentials

[aws-vault (ByteNess fork)](https://github.com/ByteNess/aws-vault) wraps the AWS CLI and stores the underlying access keys in the OS-level keyring (GNOME Keyring / KWallet / macOS Keychain) rather than plaintext on disk. It injects temporary STS credentials into a subshell, scoped to that process only.

```bash
# Store credentials in the encrypted OS keyring — never touches ~/.aws/credentials
aws-vault add meq7-secure-profile

# Execute any AWS CLI command inside a subshell with temporary STS tokens
aws-vault exec meq7-secure-profile -- aws s3 ls
```

**Security properties:**

| Property | Mechanism |
|---|---|
| Keys encrypted at rest | OS keyring (GNOME Keyring / KWallet / macOS Keychain) |
| No plaintext on disk | Credentials never written to `~/.aws/credentials` |
| Subshell isolation | Credential scope limited to the child process |
| Automatic memory clearing | Tokens purged on process termination |
| Short-lived tokens | STS `AssumeRole` generates time-limited credentials per call |

### 1.4 AWS SSO — Non-Persistent Sessions (Step-by-Step)

#### Prerequisites

- AWS CLI v2 installed
- Access to the SSO portal: `https://d-90660512c9.awsapps.com/start`
- SSO region and role access provided by the instructor

#### Step 1 — Clean Existing AWS Config

Before configuring SSO, any stale credentials, config files, or cached SSO tokens are removed to ensure a clean state and prevent conflicts with the new session:

```bash
rm -rf ~/.aws/credentials ~/.aws/config ~/.aws/sso
ls ~/.aws/
```

#### Step 2 — Run the SSO Configuration Wizard

```bash
aws configure sso
```

The wizard was filled in with the following values:

| Prompt | Value |
|---|---|
| Session name | `meq7` |
| SSO Start URL | `https://d-90660512c9.awsapps.com/start` |
| SSO Region | `us-east-1` |
| Scope | `sso:account:access` |
| Output format | `json` |
| Profile name | `meq7` |

#### Step 3 — Browser Authentication

The CLI opens a browser automatically. The team clicked **Allow access** and selected:

- **Account:** `453875232433` (YulCyberClick Demo)
- **Role:** `MEQ7_RBAC_Room3`

#### Step 4 — Verify the Connection

```bash
aws sts get-caller-identity --profile meq7
```

Expected output — confirms account access without permanent keys:

```json
{
  "Account": "453875232433"
}
```

The ARN format `arn:aws:sts::ACCOUNT:assumed-role/...` confirms a temporary STS assumed-role token, not a permanent IAM key.

#### Daily Usage

```bash
# Start of each session
aws sso login --profile meq7

# Verify active identity
aws sts get-caller-identity --profile meq7

# End of session
aws sso logout
```

**Why this matters:** If the Kali workstation were compromised, an attacker would find no extractable AWS keys in `~/.aws/credentials` — only encrypted keyring entries (aws-vault) or expired SSO cache tokens. This directly mitigates the most common AWS credential compromise vector: credential file theft.

---

## Phase 2 — DNS Infrastructure

### 2.1 Creating the Hosted Zone

A public Route 53 hosted zone was created as the DNS container for the domain. Once created, AWS auto-generated four name servers (NS records) which were provided to the Oracle (instructor) to establish delegation from the parent zone `yulcyberhub.click`.

```bash
aws route53 list-hosted-zones \
    --query 'HostedZones[?Name==`gwallofchina.yulcyberhub.click.`].[Id, Name, Config.PrivateZone]' \
    --output table
```

| Field | Value |
|---|---|
| Zone ID | `Z0433076DMIP84BGAZGN` |
| Domain | `gwallofchina.yulcyberhub.click.` |
| Type | Public (`PrivateZone: False`) |

### 2.2 DNS Record Architecture

The final hosted zone contains 23 records covering all required services and security mechanisms.

**Foundation Records:**

| Record | Type | Value | Purpose |
|---|---|---|---|
| `@` | A | 54.226.198.180 | IPv4 entry point |
| `@` | AAAA | `::0` | IPv6 placeholder (future) |
| `www` | CNAME | `gwallofchina.yulcyberhub.click` | Canonical alias |
| `mail` | A | 54.226.198.180 | Mail host (MX target) |
| `mta-sts` | A | 54.226.198.180 | MTA-STS policy file host |

**CA Authorization Records:**

```dns
@ CAA 0 issue "letsencrypt.org"
@ CAA 0 issue "amazonaws.com"
```

CAA records restrict certificate issuance to Let's Encrypt only — preventing rogue CA issuance and shadow IT certificate creation.

**Email Security Records:**

| Record | Type | Value | Mechanism |
|---|---|---|---|
| `@` | MX | `10 mail.gwallofchina.yulcyberhub.click` | Direct inbound mail to EC2 server |
| `@` | TXT | `v=spf1 ip4:54.226.198.180 include:sendgrid.net mx ~all` | SPF — authorizes EC2 IP + SendGrid fallback |
| `_dmarc` | TXT | `v=DMARC1; p=reject; ...` | Reject spoofed mail |
| `mail._domainkey` | TXT | `v=DKIM1; k=rsa; p=...` | Local DKIM signing via OpenDKIM (direct send) |
| `s1._domainkey` | CNAME | SendGrid DKIM endpoint | Auto-rotating DKIM (SendGrid fallback) |
| `s2._domainkey` | CNAME | SendGrid DKIM endpoint | Redundant DKIM (SendGrid fallback) |
| `_mta-sts` | TXT | `v=STSv1; id=20260403000000` | SMTP TLS enforcement |
| `_smtp._tls` | TXT | `v=TLSRPTv1; rua=...` | TLS failure reporting |

> **Critical:** The MX record points directly to `mail.gwallofchina.yulcyberhub.click` — inbound mail arrives at Postfix on port 25 without any third-party intermediary. **Outbound** mail is signed by OpenDKIM and sent directly via MX lookup. SendGrid acts as outbound fallback only.

### 2.3 DNSSEC Implementation

DNSSEC required a hierarchical chain of cryptographic signatures from the root (`.`) down to our zone. The critical dependency: our team could sign our own zone, but the parent zone (`yulcyberhub.click`) was controlled exclusively by the Oracle (instructor), who had to insert the DS record to complete the chain.

```
. (root)
└── .click  (TLD — TLD registry)
    └── yulcyberhub.click  (parent — Oracle / instructor)
        └── gwallofchina.yulcyberhub.click  (our zone — our team)
```

**Step 1 — Create the AWS KMS Customer Managed Key (CMK):**

Route 53 requires a CMK in AWS KMS to back the Key Signing Key. We created `GWALLkey` tagged with our cohort identifiers:

- CMK alias: `GWALLkey`
- ARN: `arn:aws:kms:us-east-1:453875232433:key/df174539-4815-420b-a6ce-64052f66d6eb`
- Status: Enabled
- Tags: `Cohort=MEQ7`, `Team=Room3`

**Step 2 — Enable DNSSEC Signing and Create the KSK:**

With the CMK in place, we navigated to Route 53 → DNSSEC signing → Enable. The KSK was named `GWALLkey` and linked to our CMK.

**Step 3 — First Attempt: KMS Permissions Error:**

The first attempt failed because the initial CMK key policy did not grant Route 53 the required actions: `DescribeKey`, `GetPublicKey`, and `Sign`. Resolution: updated the key policy to include `route53.amazonaws.com` as a permitted principal, then re-attempted.

**Step 4 — Signing Activation:**

After fixing the key policy, Route 53 began signing the zone.

**Step 5 — KSK Active, DS Record Ready for Oracle:**

DNSSEC signing was successfully enabled. KSK `GWALLkey` — Status: **Active**, created March 26 2026. The DS record hash was provided to the Oracle:

```
DS record: 11486 13 2 5D8E98E506AB70F3CF69286813298312235CA86318D376D221D964A26A2B98A7
Key tag: 11486
Digest algorithm: SHA-256
Signing algorithm: ECDSAP256SHA256 (type 13)
```

**Step 6 — Oracle Inserts DS Record → Chain Established:**

Once the Oracle inserted the DS record into the `yulcyberhub.click` parent zone, the full chain of trust activated. The `dig` command returned the `ad` (Authenticated Data) flag:

```bash
dig +dnssec MX gwallofchina.yulcyberhub.click
# flags: qr rd ra ad — confirms DNSSEC fully validated end-to-end

delv @1.1.1.1 gwallofchina.yulcyberhub.click
# ; fully validated
```

DNSViz confirmed all statuses as **Secure** across the complete chain: RRset status: Secure (6), DNSKEY/DS/NSEC status: Secure (14), Delegation status: Secure (3).

**Key Takeaway:** DNSSEC is a cooperative mechanism. A signed zone without a DS record in the parent is invisible to validating resolvers. The Oracle's action — inserting that single DS record — was the enabling step our team could not perform ourselves.

**Compensating controls while waiting for the Oracle:**
- CAA records restricted issuance to Let's Encrypt only
- Certificate Transparency monitoring for unauthorized issuance
- DANE/TLSA planned for future deployment

---

## Phase 3 — EC2 Instance & Security Groups

### 3.1 Instance Launch Script

Rather than manually clicking through the AWS console, a custom bash script (`launch-instance.sh`) was written to automate EC2 deployment reproducibly.

**Instance Parameters:**

| Parameter | Value |
|---|---|
| AMI | Rocky Linux (`ami-059807ea93f3306ee`) |
| Instance Type | `t3.small` |
| Storage | 15 GB gp3 |
| Key Pair | `thegreatfirewallofchina` |
| Security Group | `sg-0c7a7efce68ce2773` |
| IMDSv2 | Required (HttpTokens: required) |
| Name Tag | `Web-Server-Server` |

**`launch-instance.sh`:**

```bash
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

**How to deploy:**

```bash
# 1. Save the script
nano launch-instance.sh

# 2. Make it executable
chmod +x launch-instance.sh

# 3. Authenticate via SSO first
aws sso login --profile meq7

# 4. Run
./launch-instance.sh
```

**SSH access after launch:**

```bash
chmod 400 thegreatfirewallofchina.pem
ssh -i thegreatfirewallofchina.pem ec2-user@YOUR_IP
```

> **IMDSv2 enforcement:** The `--metadata-options '{"HttpTokens":"required"}'` flag forces Instance Metadata Service v2, which requires a session token for all metadata requests. This prevents SSRF attacks from reading instance metadata (including IAM role credentials) via a simple HTTP GET — a known attack vector against cloud workloads.

### 3.2 Deployed Instance Configuration

| Field | Value |
|---|---|
| Instance ID | `i-0b71d405f8ad5f73b` |
| Instance Type | `t4g.small` (ARM64 / Graviton2) |
| Public IP | `54.226.198.180` (Elastic IP — persistent across reboots) |
| OS | Rocky Linux 10 (aarch64) |
| Name Tag | `Web-Server-Server` |
| Security Group | `sg-0c7a7efce68ce2773` |

The instance is attached to a **single** security group — no additional groups — minimizing the attack surface. A dedicated EBS volume is mounted at `/var/mail` for mailbox storage, with an `/etc/fstab` entry ensuring it mounts automatically on reboot. The PTR (reverse DNS) record is set to `mail.gwallofchina.yulcyberhub.click` via EC2 → Elastic IPs → Update Reverse DNS.

### 3.3 Security Group Rules

**Security Group:** `Meq7 - Room 3 - The Real Deal` (`sg-0c7a7efce68ce2773`)

**Inbound Rules:**

| Port | Protocol | Source | Purpose |
|---|---|---|---|
| 25 | TCP | 0.0.0.0/0 | SMTP inbound (direct mail reception) |
| 80 | TCP | 0.0.0.0/0 | HTTP → HTTPS redirect |
| 443 | TCP | 0.0.0.0/0 | HTTPS (web + webmail + mta-sts) |
| 465 | TCP | 0.0.0.0/0 | SMTPS (implicit TLS) |
| 587 | TCP | 0.0.0.0/0 | SMTP submission / SendGrid fallback relay |
| 993 | TCP | 0.0.0.0/0 | IMAPS (implicit TLS) |
| 22 | TCP | 204.244.197.216/32 + 0.0.0.0/0 | SSH (team IP + open for lab) |

> **Note on port 22:** The open `0.0.0.0/0` rule is a documented lab concession for operational flexibility. Production environments must restrict SSH to bastion hosts or use EC2 Instance Connect with IAM-enforced OS user restrictions.

> **Note on port 25:** Port 25 is open in the security group and unblocked at the AWS account level (actioned by Oracle/instructor). Postfix listens on port 25 for both inbound SMTP reception and outbound direct sending via MX lookup.

**Quick Reference:**

| Task | Command |
|---|---|
| Login | `aws sso login --profile meq7` |
| Verify identity | `aws sts get-caller-identity --profile meq7` |
| Launch instance | `./launch-instance.sh` |
| SSH | `ssh -i thegreatfirewallofchina.pem ec2-user@IP` |

---

## Phase 4 — Nginx Web Server Hardening

### 4.1 SSL Certificate Choice

**Certificate Type:** Let's Encrypt Domain Validated (DV) with Subject Alternative Names (SAN)

A single certificate covers the web server, mail server, and webmail app, achieving a 100/100 certificate score on SSL Labs (EC 256 bits, SHA384withECDSA).

**Why Let's Encrypt?**

| Consideration | Rationale |
|---|---|
| **Cost** | Free — no commercial CA fees |
| **Trust** | ISRG Root X1 — trusted by all major browsers and mail clients |
| **Automation** | Certbot + systemd timer handles 90-day renewal |
| **Transparency** | All issuances logged in CT logs for monitoring |
| **Unified identity** | Single SAN cert shared across Nginx, Postfix, Dovecot, and the Node.js webmail app |

**Certificate provisioning:**

```bash
sudo certbot --nginx --expand \
  -d gwallofchina.yulcyberhub.click \
  -d mail.gwallofchina.yulcyberhub.click \
  -d mta-sts.gwallofchina.yulcyberhub.click
```

**Certificate chain:** `ISRG Root X1 → Let's Encrypt E8 → gwallofchina.yulcyberhub.click`

**Certificate path:** `/etc/letsencrypt/live/gwallofchina.yulcyberhub.click/fullchain.pem`
**SAN covers:** `gwallofchina.yulcyberhub.click`, `mail.gwallofchina.yulcyberhub.click`, `mta-sts.gwallofchina.yulcyberhub.click`
**Auto-renewal:** Managed by Certbot systemd timer
**Expiry:** 2026-07-02

### 4.2 Protocol Selection

| Protocol | Status | Reason |
|---|---|---|
| SSLv2 | Disabled | Cryptographic design broken (1995) |
| SSLv3 | Disabled | POODLE (CVE-2014-3566) |
| TLS 1.0 | Disabled | BEAST (CVE-2011-3389), RC4 dependency |
| TLS 1.1 | Disabled | No AEAD support; deprecated RFC 8996 (2021) |
| TLS 1.2 | Enabled | Industry baseline for ECDHE + AEAD |
| TLS 1.3 | Enabled | PFS built-in, encrypted handshake, reduced latency |

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
```

**Trade-off:** Disabling TLS 1.0/1.1 affects ≤2% of clients (IE11 on Windows 7 — end-of-support since 2020). Acceptable given the security posture requirement.

**HTTP → HTTPS redirect (301 Permanent):**

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name gwallofchina.yulcyberhub.click;
    return 301 https://$host$request_uri;
}
```

### 4.3 Cipher Suites

```nginx
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
```

**Selection criteria:** AEAD-only (AES-GCM or ChaCha20-Poly1305), ECDHE/DHE key exchange (PFS), SHA-2 MAC only (SHA-1 deprecated after SHAttered 2017).

| Priority | Cipher | Reason |
|---|---|---|
| 1 | `ECDHE-ECDSA-AES128-GCM-SHA256` | Best performance on AES-NI hardware |
| 2 | `ECDHE-RSA-AES128-GCM-SHA256` | Broad RSA cert compatibility |
| 3–4 | `ECDHE-*-AES256-GCM-SHA384` | Higher key strength variants |
| 5–6 | `ECDHE-*-CHACHA20-POLY1305` | ARM / mobile (no AES-NI) — t4g.small Graviton2 benefits here |
| 7–8 | `DHE-RSA-AES*-GCM-SHA*` | PFS fallback for non-ECDHE clients |

### 4.4 Perfect Forward Secrecy (PFS)

PFS ensures that compromise of the server's long-term private key cannot retroactively decrypt recorded past sessions. Every session generates an independent ephemeral key pair that is discarded afterward.

**All selected cipher suites use ECDHE or DHE** — making PFS mandatory on every connection.

**Logjam mitigation — 4096-bit DH parameters:**

```bash
# One-time generation (10–20 min on t4g.small)
sudo openssl dhparam -out /etc/nginx/ssl/dhparam.pem 4096
```

```nginx
ssl_dhparam /etc/nginx/ssl/dhparam.pem;
```

Default 1024-bit DH parameters are vulnerable to the Logjam attack (CVE-2015-4000). Custom 4096-bit parameters eliminate this. The same DH param file is reused by Postfix (`smtpd_tls_dh1024_param_file`) to ensure consistent Logjam mitigation across both services.

**Session ticket hardening:**

```nginx
ssl_session_tickets off;        # Disable ticket-based resumption (PFS risk)
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
```

**Live TLS 1.3 handshake confirmation:**

```
New, TLSv1.3, Cipher is TLS AES 256 GCM SHA384
Peer Temp Key: X25519, 253 bits — ephemeral ECDH key exchange confirming PFS is active
Verification: OK
```

### 4.5 HTTP Strict Transport Security (HSTS) & Security Headers

```nginx
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

HSTS instructs browsers to refuse any HTTP connection to this domain for **2 years** (63,072,000 seconds). The `preload` flag signals eligibility for browser vendor preload lists — protection from the **very first visit**, even before the first HTTPS handshake. This eliminates SSL stripping attacks.

**Trade-off:** HSTS preload is irreversible for the duration of `max-age`. Rolling back to HTTP requires waiting out the 2-year commitment across all browser preload lists.

**Full security header suite:**

```nginx
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()" always;
add_header Content-Security-Policy "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; upgrade-insecure-requests;" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Embedder-Policy "require-corp" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
add_header X-Permitted-Cross-Domain-Policies "none" always;
```

**Webmail-specific headers** (`/etc/nginx/conf.d/webmail.conf`):

```nginx
add_header Strict-Transport-Security "max-age=63072000" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "no-referrer" always;
```

**OCSP Stapling** — caches revocation status and serves it with the TLS handshake, eliminating client-side OCSP latency and CA privacy leakage:

```nginx
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
```

### 4.6 Service Hardening

**Rate Limiting (DDoS mitigation):**

```nginx
# Main site
limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;
limit_req zone=mylimit burst=20 nodelay;

# Webmail login endpoint
limit_req_zone $binary_remote_addr zone=webmail_limit:10m rate=5r/m;
```

**Nginx cache directory hardening:**

```bash
sudo mkdir -p /var/cache/nginx
sudo chown nginx:nginx /var/cache/nginx
sudo chmod 700 /var/cache/nginx
```

**systemd sandboxing** — kernel-level confinement applied via service override (`systemctl edit nginx.service`):

```ini
[Service]
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
```

### 4.7 Final Configurations

**1. The global WAF — `nginx.conf`**

The main configuration acts as a lightweight intrusion detection system (IDS) using nginx map directives.

- **Bot Mitigation:** The `blocked_agent` map identifies automated scanners (sqlmap, nikto, burpsuite, etc.) and drops the connection before information gathering can occur.
- **URI Filtering:** The `blocked_uri` map provides a light WAF by blocking common attack patterns like path traversal (`../`), SQL injection (`union select`), and remote code execution (`/bin/bash`).
- **Rate Limit Zones:** Pre-defined zones for global, login, and API allow different rate limits to be applied to different parts of the application.

**2. The Gateway — `gwallofchina.conf`**

This file handles the primary domain and enforces A+ Security rating standards.

- **HSTS Enforcement:** `add_header Strict-Transport-Security "max-age=63072000;..."` caches the HTTPS requirement in browsers for 2 years.
- **Logjam Protection:** `ssl_dhparam /etc/nginx/ssl/dhparam.pem` uses custom 4096-bit primes.
- **OCSP Stapling:** Provides the certificate validity proof directly from the server, so the client's browser does not need to query the CA.

```nginx
# --- Global Rate Limiting Zone ---
limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;

# --- HTTP (Port 80) - Force Redirect to HTTPS ---
server {
    listen 80;
    listen [::]:80;
    server_name gwallofchina.yulcyberhub.click;
    return 301 https://$host$request_uri;
}

# --- HTTPS (Port 443) - Secure Environment ---
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;

    server_name gwallofchina.yulcyberhub.click;

    ssl_certificate /etc/letsencrypt/live/gwallofchina.yulcyberhub.click/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/gwallofchina.yulcyberhub.click/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

    ssl_dhparam /etc/nginx/ssl/dhparam.pem;

    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header X-Permitted-Cross-Domain-Policies "none" always;
    add_header Content-Security-Policy "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; upgrade-insecure-requests;" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Embedder-Policy "require-corp" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;

    root /var/www/html;
    index index.html;

    access_log /var/log/nginx/gwallofchina.access.log;
    error_log /var/log/nginx/gwallofchina.error.log;

    location / {
        limit_req zone=mylimit burst=20 nodelay;
        try_files $uri $uri/ =404;
    }
}
```

**3. The Webmail Bridge — `webmail.conf`**

Acts as a reverse proxy between the internet and the Node.js app running on port 3000.

- **Targeted Rate Limiting:** The `/api/login` location limits authenticated attempts to 5 per minute per IP, making brute-force attacks mathematically unfeasible even if a bot bypasses the User-Agent check.
- **Header Passing:** The `proxy_set_header` directives ensure the Node.js app knows the real IP of the visitor, which is essential for accurate logging and security auditing.

```nginx
# Rate limiting zone
limit_req_zone $binary_remote_addr zone=webmail_limit:10m rate=5r/m;

# HTTP → HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name mail.gwallofchina.yulcyberhub.click;
    return 301 https://$host$request_uri;
}

# HTTPS → Node app
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name mail.gwallofchina.yulcyberhub.click;

    ssl_certificate     /etc/letsencrypt/live/gwallofchina.yulcyberhub.click/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/gwallofchina.yulcyberhub.click/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer" always;

    access_log /var/log/nginx/webmail.access.log;
    error_log  /var/log/nginx/webmail.error.log;

    location /api/login {
        limit_req zone=webmail_limit burst=5 nodelay;
        proxy_pass         http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header   Host            $host;
        proxy_set_header   X-Real-IP       $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location / {
        proxy_pass         http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   Upgrade           $http_upgrade;
        proxy_set_header   Connection        'upgrade';
    }
}
```

### 4.8 Verification

Automated `nginx_verify3.0.sh` output — all checks passed:

```
TLS 1.2       ✅ PASS
TLS 1.3       ✅ PASS
TLS 1.1       ✅ PASS (correctly rejected)
TLS 1.0       ✅ PASS (correctly rejected)
HTTP/2        ✅ PASS (active)
HTTP redirect ✅ PASS (301)
HTTPS         ✅ PASS (200 OK)
Security headers (11) ✅ PASS
Server version ✅ PASS (not disclosed)
```

---

## Phase 5 — Mail Server Hardening (Postfix & Dovecot)

### 5.1 SSL Certificate Choice

The **same unified Let's Encrypt SAN certificate** used by Nginx was extended to Postfix and Dovecot via a shared `ssl-cert` group, eliminating certificate/identity fragmentation:

```bash
sudo groupadd ssl-cert
sudo usermod -aG ssl-cert nginx
sudo usermod -aG ssl-cert postfix
sudo usermod -aG ssl-cert dovecot

sudo chgrp -R ssl-cert /etc/letsencrypt/live/ /etc/letsencrypt/archive/
sudo chmod -R 750 /etc/letsencrypt/live/ /etc/letsencrypt/archive/
sudo find /etc/letsencrypt/live/ -type d -exec chmod g+s {} +
```

### 5.2 Installation

```bash
sudo dnf install postfix cyrus-sasl-plain mailx -y
sudo systemctl enable --now postfix

sudo dnf install dovecot -y
sudo systemctl enable --now dovecot
```

Versions installed: `postfix-2:3.8.5-8.el10.aarch64`, `cyrus-sasl-plain-2.1.28-29.el10.aarch64`, `dovecot-1:2.3.21-16.el10.aarch64`

### 5.3 Protocol Selection

**Dovecot — `/etc/dovecot/conf.d/10-ssl.conf`:**

```ini
ssl = required
ssl_cert = </etc/letsencrypt/live/gwallofchina.yulcyberhub.click/fullchain.pem
ssl_key  = </etc/letsencrypt/live/gwallofchina.yulcyberhub.click/privkey.pem
ssl_min_protocol = TLSv1.2
```

**Disabling plaintext IMAP — `/etc/dovecot/conf.d/10-master.conf`:**

```ini
inet_listener imap { port = 0 }          # plaintext IMAP disabled
inet_listener imaps { port = 993; ssl = yes }  # encrypted IMAPS only
```

**Postfix outbound TLS:**

```bash
sudo postconf -e "smtp_use_tls = yes"
sudo postconf -e "smtp_tls_security_level = encrypt"
sudo postconf -e "smtp_tls_note_starttls_offer = yes"
sudo postconf -e "myhostname = mail.gwallofchina.yulcyberhub.click"
sudo postconf -e "mydomain = gwallofchina.yulcyberhub.click"
sudo postconf -e "myorigin = \$mydomain"
```

**Port allocation:**

| Port | Service | Protocol | Rationale |
|---|---|---|---|
| 25 | SMTP | Plaintext → STARTTLS | Inbound mail reception + outbound direct sending |
| 465 | SMTPS | Implicit TLS | No STARTTLS downgrade possible |
| 993 | IMAPS | Implicit TLS | No STARTTLS downgrade possible |
| 587 | SMTP Relay | STARTTLS | Used by SendGrid fallback relay (outbound only) |

### 5.4 Cipher Suites & Inbound TLS Hardening

```bash
sudo postconf -e "smtpd_tls_cert_file = /etc/letsencrypt/live/gwallofchina.yulcyberhub.click/fullchain.pem"
sudo postconf -e "smtpd_tls_key_file  = /etc/letsencrypt/live/gwallofchina.yulcyberhub.click/privkey.pem"
sudo postconf -e "smtpd_tls_security_level = may"
sudo postconf -e "smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
sudo postconf -e "smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
sudo postconf -e "smtpd_tls_dh1024_param_file = /etc/nginx/ssl/dhparam.pem"
```

### 5.5 SMTP Authentication — The Secret Pipe

Postfix is configured to send mail **directly** via SMTP MX lookup as the primary delivery path. SendGrid is configured exclusively as a **fallback relay**, activating automatically only when direct delivery fails.

This dual-path architecture is reflected in `main.cf`:

```ini
relayhost =
fallback_relay = [smtp.sendgrid.net]:587

smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = lmdb:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_use_tls = yes
smtp_tls_security_level = may
smtp_tls_loglevel = 1
```

> **Why this design?** Direct sending preserves full control over mail headers and avoids SendGrid rate limits on the free tier. The fallback ensures delivery continuity if direct port 25 access is restricted at the AWS account level.

### 5.5.1 OpenDKIM — Local DKIM Signing

Direct sending requires a **local DKIM milter** because SendGrid's DKIM selectors (`s1._domainkey`, `s2._domainkey`) only sign mail routed through SendGrid's infrastructure. Mail sent directly via port 25 arrives unsigned at the destination — failing DMARC's `adkim=s` strict alignment and being rejected by Gmail.

**Solution:** OpenDKIM runs as a Postfix milter, signing every outbound message before it leaves the server with a locally generated key published at `mail._domainkey.gwallofchina.yulcyberhub.click`.

**Installation:**

```bash
sudo dnf install opendkim opendkim-tools -y
```

**Key generation:**

```bash
sudo mkdir -p /etc/opendkim/keys/gwallofchina.yulcyberhub.click

sudo opendkim-genkey -b 2048 \
  -d gwallofchina.yulcyberhub.click \
  -D /etc/opendkim/keys/gwallofchina.yulcyberhub.click \
  -s mail -v

sudo chown -R opendkim:opendkim /etc/opendkim/
```

**`/etc/opendkim.conf`:**

```ini
Mode                    sv
Syslog                  yes
SyslogSuccess           yes
LogWhy                  yes
Canonicalization        relaxed/relaxed
Domain                  gwallofchina.yulcyberhub.click
Selector                mail
Socket                  inet:8891@localhost
PidFile                 /run/opendkim/opendkim.pid
UserID                  opendkim
UMask                   007
OversignHeaders         From
SigningTable            refile:/etc/opendkim/SigningTable
KeyTable                /etc/opendkim/KeyTable
InternalHosts           /etc/opendkim/TrustedHosts
```

> **Rocky Linux 10 note:** The `TrustAnchorFile` directive must be omitted — `/usr/share/opendkim/effective.trust.anchors` does not exist on Rocky Linux 10 and causes exit code 78 on startup.

**`/etc/opendkim/SigningTable`:**

```
*@gwallofchina.yulcyberhub.click    mail._domainkey.gwallofchina.yulcyberhub.click
```

**`/etc/opendkim/KeyTable`:**

```
mail._domainkey.gwallofchina.yulcyberhub.click    gwallofchina.yulcyberhub.click:mail:/etc/opendkim/keys/gwallofchina.yulcyberhub.click/mail.private
```

**`/etc/opendkim/TrustedHosts`:**

```
127.0.0.1
localhost
54.226.198.180
gwallofchina.yulcyberhub.click
mail.gwallofchina.yulcyberhub.click
```

**Wire OpenDKIM into Postfix:**

```bash
sudo postconf -e "milter_default_action = accept"
sudo postconf -e "milter_protocol = 6"
sudo postconf -e "smtpd_milters = inet:localhost:8891"
sudo postconf -e "non_smtpd_milters = inet:localhost:8891"
sudo systemctl enable --now opendkim
sudo systemctl restart postfix
```

**Verify socket is listening:**

```bash
ss -tlnp | grep 8891
# Expected: LISTEN 0 4096 127.0.0.1:8891
```

**DNS record — push to Route 53:**

The public key is split across 3 chunks to stay under the 255-character DNS TXT limit:

```bash
aws route53 change-resource-record-sets \
  --hosted-zone-id Z0433076DMIP84BGAZGN \
  --profile MEQ7_RBAC_Room3-453875232433 \
  --change-batch '{
    "Changes": [{
      "Action": "CREATE",
      "ResourceRecordSet": {
        "Name": "mail._domainkey.gwallofchina.yulcyberhub.click",
        "Type": "TXT",
        "TTL": 300,
        "ResourceRecords": [{
          "Value": "\"v=DKIM1; k=rsa; p=MIIBIjAN...chunk1\" \"chunk2\" \"chunk3\""
        }]
      }
    }]
  }'
```

**Verify key is resolvable:**

```bash
sudo opendkim-testkey -d gwallofchina.yulcyberhub.click -s mail -vvv
# Expected: key OK
```

**Confirm signing in mail logs:**

```
opendkim[357754]: 70AA1181F800: DKIM-Signature field added (s=mail, d=gwallofchina.yulcyberhub.click)
postfix/smtp[358515]: 70AA1181F800: relay=gmail-smtp-in.l.google.com[:25], status=sent (250 2.0.0 OK)
```

**Postfix ↔ Dovecot SASL Integration:**

```bash
sudo postconf -e "smtpd_sasl_type = dovecot"
sudo postconf -e "smtpd_sasl_path = private/auth"
sudo postconf -e "smtpd_sasl_auth_enable = yes"
sudo systemctl restart postfix
```

**Dovecot SASL socket configuration — `/etc/dovecot/conf.d/10-master.conf`:**

```ini
unix_listener /var/spool/postfix/private/auth {
  mode = 0666
  user = postfix
  group = postfix
}
```

Mode `0666` is required because Postfix cannot use `0600` — it runs as its own user and must have socket access. `0777` would allow all users — `0666` restricts to explicit socket connections.

**`/etc/postfix/master.cf` — key services:**

```
# SMTP port 25 — inbound reception + outbound direct sending
smtp      inet  n       -       n       -       -       smtpd

# Submission port 587 — authenticated client relay
submission inet n       -       n       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=yes
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject

# SMTPS port 465 — implicit TLS (no STARTTLS downgrade possible)
smtps     inet  n       -       n       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
```

**SendGrid fallback relay credentials — `/etc/postfix/sasl_passwd`:**

```bash
echo "[smtp.sendgrid.net]:587 apikey:SG.YOUR_KEY_HERE" \
  | sudo tee /etc/postfix/sasl_passwd

sudo postmap lmdb:/etc/postfix/sasl_passwd
sudo chmod 0600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.lmdb
```

**Full relay and database configuration:**

```bash
sudo postconf -e "relayhost ="
sudo postconf -e "fallback_relay = [smtp.sendgrid.net]:587"
sudo postconf -e "smtp_sasl_auth_enable = yes"
sudo postconf -e "smtp_sasl_password_maps = lmdb:/etc/postfix/sasl_passwd"
sudo postconf -e "smtp_sasl_security_options = noanonymous"
sudo postconf -e "default_database_type = lmdb"
sudo postconf -e "alias_database = lmdb:/etc/aliases"
sudo postconf -e "alias_maps = lmdb:/etc/aliases"
```

> **Rocky Linux compatibility:** Rocky Linux 9/10 removed Berkeley DB — all `hash:` map types fail with `unsupported dictionary type: hash`. Migrating everything to `lmdb:` resolved this.

### 5.6 Virtual Mailbox Configuration

**Key parameters in `/etc/postfix/main.cf`:**

```ini
virtual_mailbox_domains = gwallofchina.yulcyberhub.click
virtual_mailbox_maps    = lmdb:/etc/postfix/vmailbox
virtual_mailbox_base    = /var/mail/vhosts
virtual_uid_maps        = static:5000
virtual_gid_maps        = static:5000

# CRITICAL: Domain must NOT appear in both mydestination and virtual_mailbox_domains
mydestination = $myhostname, localhost.$mydomain, localhost
```

> **Critical fix:** Removing `$mydomain` from `mydestination` was essential. A domain cannot exist in both `mydestination` and `virtual_mailbox_domains` — Postfix will reject delivery with a configuration error if both are set simultaneously.

**Virtual mailbox map — `/etc/postfix/vmailbox`:**

```
pborelli@gwallofchina.yulcyberhub.click   gwallofchina.yulcyberhub.click/pborelli/Maildir/
kbain@gwallofchina.yulcyberhub.click      gwallofchina.yulcyberhub.click/kbain/Maildir/
molivier@gwallofchina.yulcyberhub.click   gwallofchina.yulcyberhub.click/molivier/Maildir/
sroy@gwallofchina.yulcyberhub.click       gwallofchina.yulcyberhub.click/sroy/Maildir/
```

After any edit, always recompile:

```bash
sudo postmap lmdb:/etc/postfix/vmailbox
```

**Maildir provisioning:**

```bash
sudo mkdir -p /var/mail/vhosts/gwallofchina.yulcyberhub.click/USER/Maildir/{cur,new,tmp}
sudo chown -R vmail:vmail /var/mail/vhosts/
sudo chmod -R 700 /var/mail/vhosts/
sudo chmod 755 /var/mail
sudo chmod 755 /var/mail/vhosts
```

**Required directory permission chain:**

| Path | Owner | Permissions |
|---|---|---|
| `/var/mail` | root:mail | 755 |
| `/var/mail/vhosts` | vmail:vmail | 755 |
| `/var/mail/vhosts/domain/` | vmail:vmail | 700 |
| `/var/mail/vhosts/domain/user/` | vmail:vmail | 700 |
| `/var/mail/vhosts/domain/user/Maildir/` | vmail:vmail | 700 |
| `/var/mail/vhosts/domain/user/Maildir/new/` | vmail:vmail | 700 |

**Dovecot mail location — `/etc/dovecot/conf.d/10-mail.conf`:**

```ini
mail_location = maildir:/var/mail/vhosts/%d/%n/Maildir
```

**Dovecot authentication — `/etc/dovecot/conf.d/auth-passwdfile.conf.ext`:**

```ini
passdb {
  driver = passwd-file
  args   = scheme=SHA512-CRYPT /etc/dovecot/users
}

userdb {
  driver = static
  args   = uid=vmail gid=vmail home=/var/mail/vhosts/%d/%n
}
```

In `/etc/dovecot/conf.d/10-auth.conf`:

```ini
!include auth-passwdfile.conf.ext   # uncommented
#!include auth-system.conf.ext      # commented out — conflicts with passwd-file
```

**Dovecot user database — `/etc/dovecot/users`:**

```
user@domain:{SHA512-CRYPT}HASH:5000:5000::/var/mail/vhosts/domain/user
```

Generate a password hash with:

```bash
doveadm pw -s SHA512-CRYPT
```

### 5.7 Inbound Mail — Direct SMTP Reception

**Inbound mail flow:**

```
Sender MTA
    │
    ▼ (DNS MX lookup)
mail.gwallofchina.yulcyberhub.click:25
    │
    ▼
Postfix (smtpd) → virtual transport → Dovecot LMTP
    │
    ▼
/var/mail/vhosts/gwallofchina.yulcyberhub.click/user/Maildir/
    │
    ▼
Dovecot IMAP → Webmail or mail client
```

**Verify Postfix is listening for inbound mail:**

```bash
sudo ss -tlnp | grep :25
# Expected: LISTEN 0 100 0.0.0.0:25
```

```bash
sudo tail -f /var/log/maillog
```

### 5.8 Webmail Application

A custom Node.js webmail application is deployed at `https://mail.gwallofchina.yulcyberhub.click`, providing browser-based mail access authenticated against Dovecot credentials.

**Stack:**

| Component | Technology |
|---|---|
| Runtime | Node.js 20 |
| Framework | Express |
| IMAP client | imapflow |
| SMTP send | Nodemailer (via Postfix localhost:25) |
| Mail parsing | mailparser |
| File upload / webhook | multer |
| Process manager | PM2 (runs as root) |

**File structure:**

```
/opt/webmail/
├── server.js          ← Express backend
├── package.json       ← Dependencies
├── node_modules/      ← Auto-generated by npm install
└── public/
    └── index.html     ← Frontend UI
```

**Installation:**

```bash
sudo dnf module enable nodejs:20 -y
sudo dnf install nodejs -y

cd /opt/webmail
npm install

sudo npm install -g pm2
sudo /usr/local/bin/pm2 start /opt/webmail/server.js --name webmail
sudo /usr/local/bin/pm2 save
sudo /usr/local/bin/pm2 startup
```

> **PM2 must run as root** because the Node.js process needs write access to `/var/mail/vhosts/` (owned by `vmail`, uid 5000). Non-root PM2 instances will fail silently on inbound delivery.

**Features:** Login via Dovecot IMAP credentials · Read, send, reply, forward, delete email · Folder switching (Inbox, Sent, Drafts, Trash, Spam) · Unread badge count · Client-side search · Sessions persist 8 hours with random session secret.

### 5.9 SPF / DKIM / DMARC / MTA-STS

**SPF:**

```dns
@ TXT "v=spf1 ip4:54.226.198.180 include:sendgrid.net mx ~all"
```

`ip4:54.226.198.180` authorizes direct sending from the EC2 server. `include:sendgrid.net` authorizes SendGrid when the fallback relay activates. `~all` is a soft fail — stricter than nothing but allows DMARC to make the final enforcement decision via `p=reject`.

**DKIM — Two signing paths:**

Local signing via OpenDKIM (direct send — primary):

```dns
mail._domainkey  TXT  "v=DKIM1; k=rsa; p=<public key>"
```

CNAME delegation to SendGrid (fallback relay):

```dns
s1._domainkey  CNAME  s1.domainkey.u61568083.wl084.sendgrid.net
s2._domainkey  CNAME  s2.domainkey.u61568083.wl084.sendgrid.net
em5287         CNAME  u61568083.wl084.sendgrid.net
```

**DMARC — Strict reject policy:**

```dns
_dmarc TXT "v=DMARC1; p=reject; rua=mailto:admin@gwallofchina.yulcyberhub.click; ruf=mailto:admin@gwallofchina.yulcyberhub.click; sp=reject; adkim=s; aspf=s"
```

| Parameter | Effect |
|---|---|
| `p=reject` | Failed messages dropped at gateway — no quarantine |
| `sp=reject` | Subdomains inherit the same reject policy |
| `adkim=s` | DKIM `d=` must exactly match `From:` domain |
| `aspf=s` | SPF envelope sender must exactly match `From:` domain |
| `rua` + `ruf` | Aggregate + forensic failure reports to admin |

**MTA-STS & TLS-RPT:**

```dns
_mta-sts  TXT  "v=STSv1; id=20260403000000"
_smtp._tls TXT  "v=TLSRPTv1; rua=mailto:admin@gwallofchina.yulcyberhub.click"
```

**MTA-STS policy file** — served at `https://mta-sts.gwallofchina.yulcyberhub.click/.well-known/mta-sts.txt`:

```
version: STSv1
mode: enforce
mx: mail.gwallofchina.yulcyberhub.click
max_age: 86400
```

**Nginx virtual host** (`/etc/nginx/conf.d/mta-sts.conf`):

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name mta-sts.gwallofchina.yulcyberhub.click;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name mta-sts.gwallofchina.yulcyberhub.click;

    ssl_certificate     /etc/letsencrypt/live/gwallofchina.yulcyberhub.click/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/gwallofchina.yulcyberhub.click/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    root /var/www/mta-sts;

    location = /.well-known/mta-sts.txt {
        default_type text/plain;
        try_files $uri =404;
    }

    location / {
        return 404;
    }
}
```

**Verify:**

```bash
curl https://mta-sts.gwallofchina.yulcyberhub.click/.well-known/mta-sts.txt
```

### 5.10 Adding a New User

```bash
# 1. Add to Postfix virtual mailbox map
echo "user@gwallofchina.yulcyberhub.click  gwallofchina.yulcyberhub.click/user/Maildir/" \
  | sudo tee -a /etc/postfix/vmailbox

# 2. Recompile the map
sudo postmap lmdb:/etc/postfix/vmailbox

# 3. Create the Maildir structure
sudo mkdir -p /var/mail/vhosts/gwallofchina.yulcyberhub.click/user/Maildir/{cur,new,tmp}
sudo chown -R vmail:vmail /var/mail/vhosts/
sudo chmod -R 700 /var/mail/vhosts/
sudo chmod 755 /var/mail && sudo chmod 755 /var/mail/vhosts

# 4. Generate password hash and add to Dovecot
doveadm pw -s SHA512-CRYPT
echo "user@gwallofchina.yulcyberhub.click:{SHA512-CRYPT}HASH:5000:5000::/var/mail/vhosts/gwallofchina.yulcyberhub.click/user" \
  | sudo tee -a /etc/dovecot/users

# 5. Reload services
sudo systemctl reload postfix dovecot

# 6. Automation (can be found in scripts)
sudo ./mail-admin.sh add <user>
```

### 5.11 Client Mail App Settings

| Setting | Value |
|---|---|
| IMAP Server | `mail.gwallofchina.yulcyberhub.click` |
| IMAP Port | `993` (SSL/TLS) |
| SMTP Server | `mail.gwallofchina.yulcyberhub.click` |
| SMTP Port | `587` (STARTTLS) |
| Username | Full email address (e.g. `user@gwallofchina.yulcyberhub.click`) |
| Password | Set with `doveadm pw` |

### 5.12 SendGrid Fallback, Webmail Interactions, and Final Configuration Files

**How the fallback works:**

1. **Step 1 (Direct):** When you send an email, Postfix looks up the **MX record** of the recipient (e.g., Gmail) and attempts to connect to their server on **port 25**.
2. **Step 2 (The Trigger):** If port 25 is blocked by the ISP, AWS, or if the recipient server is down, Postfix triggers the **fallback_relay**.
3. **Step 3 (The Handshake):** Postfix connects to **smtp.sendgrid.net** on **port 587** and presents the API key stored in `/etc/postfix/sasl_passwd`.
4. **Step 4 (Delivery):** SendGrid accepts the mail and delivers it on your behalf.

**Webmail Interactions — the "Secret Pipe":**

The webmail app does not talk to the mailbox files directly — it talks to **Dovecot** via the **IMAPS** protocol.

When a user logs in: the webmail sends credentials to Dovecot → Dovecot checks `/etc/dovecot/users` → compares against the **SHA512-CRYPT** hash → grants or denies access.

**Configuration in `auth-passwdfile.conf.ext`:**

```ini
passdb {
  driver = passwd-file
  args = scheme=CRYPT username_format=%u /etc/dovecot/users
}

userdb {
  driver = passwd-file
  args = username_format=%u /etc/dovecot/users
}
```

**Final `/etc/postfix/main.cf`:**

```ini
# --- Hostname and Domain Settings ---
myhostname = mail.gwallofchina.yulcyberhub.click
mydomain = gwallofchina.yulcyberhub.click
myorigin = $mydomain
inet_interfaces = all
inet_protocols = ipv4

# --- Destination and Relay ---
mydestination = $myhostname, localhost.$mydomain, localhost
relayhost =
fallback_relay = [smtp.sendgrid.net]:587

# SendGrid Auth
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = lmdb:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_use_tls = yes
smtp_tls_security_level = may
smtp_tls_loglevel = 1

# Transport map
transport_maps = lmdb:/etc/postfix/transport

# --- Rate Limiting (1 email/min) ---
smtp_destination_rate_delay = 60s
default_destination_rate_delay = 60s
smtp_destination_concurrency_limit = 1
default_destination_concurrency_limit = 1
smtp_extra_recipient_limit = 1
minimal_backoff_time = 60s
maximal_backoff_time = 120s

# --- Virtual Mailbox Settings ---
virtual_mailbox_domains = gwallofchina.yulcyberhub.click
virtual_mailbox_base = /var/mail/vhosts
virtual_mailbox_maps = lmdb:/etc/postfix/vmailbox
virtual_transport = lmtp:unix:private/dovecot-lmtp
virtual_minimum_uid = 100
virtual_uid_maps = static:5000
virtual_gid_maps = static:5000

# --- SSL/TLS Settings ---
smtpd_tls_cert_file = /etc/letsencrypt/live/gwallofchina.yulcyberhub.click/fullchain.pem
smtpd_tls_key_file = /etc/letsencrypt/live/gwallofchina.yulcyberhub.click/privkey.pem
smtpd_tls_security_level = may
smtpd_tls_auth_only = yes
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
tls_preempt_cipherlist = yes

# --- Dovecot SASL Authentication ---
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination
mynetworks = 127.0.0.0/8 54.226.198.180/32

# --- Database Types ---
default_database_type = lmdb
compatibility_level = 3.6
milter_default_action = accept
milter_protocol = 6
smtpd_milters = inet:localhost:8891
non_smtpd_milters = inet:localhost:8891
alias_maps = lmdb:/etc/aliases
alias_database = lmdb:/etc/aliases
```

**Final `/etc/postfix/master.cf`:**

```
smtp      inet  n       -       n       -       -       smtpd

submission inet n       -       n       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=yes
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject

smtps     inet  n       -       n       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject

pickup    unix  n       -       n       60      1       pickup
cleanup   unix  n       -       n       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
tlsmgr    unix  -       -       n       1000?   1       tlsmgr
rewrite   unix  -       -       n       -       -       trivial-rewrite
bounce    unix  -       -       n       -       0       bounce
defer     unix  -       -       n       -       0       bounce
trace     unix  -       -       n       -       0       bounce
verify    unix  -       -       n       -       1       verify
flush     unix  n       -       n       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       n       -       -       smtp
relay     unix  -       -       n       -       -       smtp
        -o syslog_name=postfix/$service_name
showq     unix  n       -       n       -       -       showq
error     unix  -       -       n       -       -       error
retry     unix  -       -       n       -       -       error
discard   unix  -       -       n       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       n       -       -       lmtp
anvil     unix  -       -       n       -       1       anvil
scache    unix  -       -       n       -       1       scache
postlog   unix-dgram n  -       n       -       1       postlogd

# ====================================================================
# Custom transports — Direct sending + SendGrid relay
# ====================================================================
direct-smtp  unix  -  -  n  -  1  smtp
    -o smtp_destination_rate_delay=60s
    -o smtp_destination_concurrency_limit=1
    -o smtp_extra_recipient_limit=1

sendgrid     unix  -  -  n  -  1  smtp
    -o smtp_destination_rate_delay=60s
    -o smtp_destination_concurrency_limit=1
    -o smtp_extra_recipient_limit=1
    -o smtp_sasl_auth_enable=yes
    -o relayhost=[smtp.sendgrid.net]:587
    -o smtp_sasl_password_maps=lmdb:/etc/postfix/sasl_passwd
    -o smtp_sasl_security_options=noanonymous
```

**Final Dovecot configuration (from `doveconf -n`):**

```ini
# /etc/dovecot/dovecot.conf — Dovecot 2.3.21
# OS: Linux 6.12.0-124.8.1.el10_1.aarch64 aarch64 Rocky Linux release 10.1

auth_mechanisms = plain login
first_valid_uid = 5000
mail_location = maildir:~/Maildir
mbox_write_locks = fcntl

namespace inbox {
  inbox = yes
  mailbox Drafts { special_use = \Drafts }
  mailbox Junk   { special_use = \Junk }
  mailbox Sent   { special_use = \Sent }
  mailbox "Sent Messages" { special_use = \Sent }
  mailbox Trash  { special_use = \Trash }
}

passdb {
  args = scheme=SHA512-CRYPT username_format=%u /etc/dovecot/users
  driver = passwd-file
}

service auth {
  unix_listener /var/spool/postfix/private/auth {
    group = postfix
    mode = 0660
    user = postfix
  }
  unix_listener auth-client { mode = 0660 }
  unix_listener auth-userdb {
    group = vmail
    mode = 0660
    user = vmail
  }
}

service auth-worker { user = root }

service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    group = postfix
    mode = 0660
    user = postfix
  }
}

ssl = required
ssl_cert = </etc/pki/dovecot/certs/dovecot.pem
ssl_cipher_list = PROFILE=SYSTEM
ssl_key = # hidden

userdb {
  args = username_format=%u /etc/dovecot/users
  driver = passwd-file
}
```

**`/etc/postfix/sasl_passwd`:**

This file contains the SendGrid API key used only when `fallback_relay` activates. It must contain:

```
[smtp.sendgrid.net]:587 apikey:SG.<REDACTED>
```

It must be compiled to LMDB format after every change:

```bash
sudo postmap lmdb:/etc/postfix/sasl_passwd
sudo chmod 0600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.lmdb
```

The file is omitted from this document due to the information disclosure risk of exposing a live API key.

### 5.13 Verification

**Port listening verification:**

```bash
sudo ss -tulpn | grep -E ':(465|587|993|25)'
# Expected: 0.0.0.0:25, 0.0.0.0:465, 0.0.0.0:587, 0.0.0.0:993 (and IPv6 equivalents)
```

**IMAPS (Port 993):**

```bash
openssl s_client -connect mail.gwallofchina.yulcyberhub.click:993 -quiet
# Expected: full chain ISRG Root X1 → E8 → domain, "* OK [...] Dovecot ready."
```

**SMTPS (Port 465):**

```bash
openssl s_client -connect mail.gwallofchina.yulcyberhub.click:465 -quiet
# Expected: full chain, "220 mail.gwallofchina.yulcyberhub.click ESMTP Postfix"
```

**Mailbox verification commands:**

| Task | Command |
|---|---|
| Check Postfix mapping | `postmap -q user@domain lmdb:/etc/postfix/vmailbox` |
| Test Dovecot auth | `sudo doveadm auth test user@domain 'password'` |
| Check Dovecot user | `sudo doveadm user user@domain` |
| Watch live mail logs | `sudo tail -f /var/log/maillog` |
| Check PM2 processes | `sudo /usr/local/bin/pm2 list` |
| Check Node app logs | `sudo /usr/local/bin/pm2 logs webmail` |
| Check MX record | `dig MX gwallofchina.yulcyberhub.click` |
| Verify relay config | `postconf relayhost fallback_relay` |
| Verify OpenDKIM | `sudo opendkim-testkey -d gwallofchina.yulcyberhub.click -s mail -vvv` |
| MTA-STS policy | `curl https://mta-sts.gwallofchina.yulcyberhub.click/.well-known/mta-sts.txt` |

**Final Deployment Status:**

| Component | Status |
|---|---|
| Outbound mail — direct SMTP (primary) | Working (`relayhost =` empty · OpenDKIM signs · port 25 open) |
| Outbound mail — SendGrid relay (fallback) | Configured (`fallback_relay = [smtp.sendgrid.net]:587`) |
| Inbound mail — direct SMTP (port 25) | Working (MX → `mail.gwallofchina.yulcyberhub.click:25`) |
| OpenDKIM local DKIM signing | Active (`s=mail` · `DKIM-Signature field added` confirmed in logs) |
| SPF | Pass (`ip4:54.226.198.180 include:sendgrid.net mx ~all`) |
| DKIM | Pass (direct: OpenDKIM `mail._domainkey` · fallback: SendGrid `s1/s2._domainkey`) |
| DMARC | Pass (`p=reject` · both paths satisfy alignment) |
| MTA-STS | Policy file live at `https://mta-sts.gwallofchina.yulcyberhub.click/.well-known/mta-sts.txt` |
| Port 25 (SMTP) | Listening — inbound + outbound |
| Port 465 (SMTPS) | Listening — implicit TLS |
| Port 587 (Submission) | Listening — STARTTLS |
| Port 993 (IMAPS) | Listening — implicit TLS |
| Dovecot IMAP | Working |
| Webmail app | Live at `https://mail.gwallofchina.yulcyberhub.click` |
| SSL certificate | Valid until 2026-07-02 (SAN: main + mail + mta-sts) |
| Main website | Live at `https://gwallofchina.yulcyberhub.click` |
| User mailboxes | pborelli, kbain, molivier, sroy |
| DNSSEC | Fully validated (chain established · `ad` flag confirmed) |

**SSL Labs Final Summary:**

| Domain | Overall | Certificate | Protocol | Key Exchange | Cipher |
|---|---|---|---|---|---|
| `gwallofchina.yulcyberhub.click` | **A+** | 100 | 100 | 100 | 100 |
| `mail.gwallofchina.yulcyberhub.click` | **A+** | 100 | 100 | ~90 | ~90 |

---

## Phase 6 — Challenges & Trade-Offs

### 6.1 Security vs. Compatibility

**Disabling TLS 1.0 / 1.1** impacts ≤2% of clients (IE11 on Windows 7, unsupported since 2020). Accepted because the affected population runs unpatched software that presents greater ecosystem risk than the accessibility loss.

**CSP `unsafe-inline`** is required by the current page architecture. Planned migration to nonce-based CSP (`'nonce-{random}'`) will address this without breaking inline functionality.

**SSH Port 22** is open to `0.0.0.0/0` alongside the team IP for lab operational flexibility. Explicitly documented as a known limitation — production requires bastion-only restriction.

### 6.2 Performance Considerations

**DH Parameter Generation:** 4096-bit DH parameter generation takes 10–20 minutes on t4g.small — one-time cost, not per-connection. Security gain (Logjam mitigation) far outweighs the delay.

**TLS Session Cache:** 10MB shared cache (~40,000 sessions) reduces handshake overhead on returning clients while `ssl_session_tickets off` preserves PFS.

**HTTP/2:** HPACK header compression and multiplexed requests reduce page load latency without security trade-offs.

**ChaCha20-Poly1305:** Included specifically for the ARM64 Graviton2 processor — on hardware without AES-NI, ChaCha20 outperforms AES-GCM in software.

### 6.3 Testing & Troubleshooting

| Issue | Root Cause | Resolution |
|---|---|---|
| `unsupported dictionary type: hash` | Rocky Linux 9/10 removed Berkeley DB | Migrated all `hash:` maps to `lmdb:` |
| Lynis download redirect failure | Vendor CDN issue in Rocky 10 | Used GitHub tar.gz with `curl -L` |
| DNSSEC — no `ad` flag | Oracle had not yet inserted DS record into parent zone | Waited for Oracle; CAA + CT as interim controls |
| DNSSEC — KMS permissions error | Initial CMK policy did not grant Route 53 `DescribeKey`, `GetPublicKey`, `Sign` | Updated key policy to include `route53.amazonaws.com` as principal |
| Certificate permission denied (Postfix/Dovecot) | `/etc/letsencrypt` root-owned only | `ssl-cert` group + `chmod 750` + `g+s` sticky bit |
| Nginx zombie processes on restart | Improper restart sequence | `pkill -9 nginx` before `systemctl start nginx` |
| Webmail showing castle page | `gwallofchina.conf` catching all traffic | Separate `server_name` per Nginx config file |
| Certbot failing on webmail | `webmail.conf` had wrong cert path | Updated to use shared SAN cert path |
| SendGrid webhook returning 404 | `express.json()` consuming body before `multer` | Moved `/api/inbound` route before all middleware |
| Maildir not found | Folders not created automatically by Postfix | `mkdir -p .../Maildir/{cur,new,tmp}` |
| Permission denied writing mail | PM2 running as `rocky` user, not root | Switched to `sudo /usr/local/bin/pm2` |
| Dovecot permission denied on `/var/mail` | `/var/mail` set to 700 | `chmod 755 /var/mail && chmod 755 /var/mail/vhosts` |
| `mydestination` + `virtual_mailbox_domains` conflict | Domain listed in both directives | Removed `$mydomain` from `mydestination` |
| Direct send rejected by Gmail (`5.7.26 DMARC`) | Mail sent without DKIM signature — SendGrid DKIM only covers SendGrid-relayed mail | Installed OpenDKIM milter for local signing |
| OpenDKIM exit code 78 on startup | `TrustAnchorFile` path does not exist on Rocky Linux 10 | Removed `TrustAnchorFile` line from `opendkim.conf` |
| `signing table references unknown key` | KeyTable file was empty — `tee` wrote entry to SigningTable instead | Rewrote both SigningTable and KeyTable with correct single-line entries |
| `multiple DNS replies` for DKIM key | DNS record stored as 3 separate ResourceRecords instead of one value with quoted chunks | Deleted and recreated record as single value with space-separated quoted chunks |
| `CharacterStringTooLong` when adding DKIM TXT | Full key exceeds 255-char DNS TXT string limit | Split key into multiple quoted chunks within a single ResourceRecord value |
| SPF fail on direct-sent mail | Two conflicting SPF records | Deleted `v=spf1 -all` record; kept correct record |
| Port 465 (SMTPS) not listening | `smtps` service missing from `master.cf` | Added `smtps inet n - n - - smtpd` block with `-o smtpd_tls_wrappermode=yes` |
| `master.cf` sed corrupted submission block | `sed -i` merged multi-line block into one line | Rewrote `master.cf` manually with correct indentation for each `-o` option |
| MTA-STS policy file missing | Policy file not created on server | Created `/var/www/mta-sts/.well-known/mta-sts.txt` and added Nginx virtual host |
| MTA-STS subdomain no certificate | `mta-sts.gwallofchina.yulcyberhub.click` not in SAN cert | Expanded cert with `certbot --expand -d mta-sts.gwallofchina.yulcyberhub.click` |

**Full validation command set:**

```bash
# 1. HTTP → HTTPS redirect
curl -I http://gwallofchina.yulcyberhub.click

# 2. TLS handshake + certificate chain
openssl s_client -connect gwallofchina.yulcyberhub.click:443 \
  -servername gwallofchina.yulcyberhub.click | head -20

# 3. Legacy protocol rejection
openssl s_client -connect gwallofchina.yulcyberhub.click:443 -tls1_1
# Expected: handshake failure

# 4. IMAPS
openssl s_client -connect mail.gwallofchina.yulcyberhub.click:993 -quiet

# 5. SMTPS
openssl s_client -connect mail.gwallofchina.yulcyberhub.click:465 -quiet

# 6. DNSSEC
dig +dnssec MX gwallofchina.yulcyberhub.click
delv @1.1.1.1 gwallofchina.yulcyberhub.click
# Look for: 'ad' flag + '; fully validated'

# 7. End-to-end mail
echo "Build Complete" | mail -s "AEC Final Audit" \
  -r admin@gwallofchina.yulcyberhub.click recipient@example.com

# 8. Automated Nginx verification
sudo ./nginx_verify3.0.sh

# 9. Postfix virtual mailbox lookup
postmap -q sroy@gwallofchina.yulcyberhub.click lmdb:/etc/postfix/vmailbox

# 10. Dovecot auth test
sudo doveadm auth test sroy@gwallofchina.yulcyberhub.click 'password'

# 11. Check webmail process
sudo /usr/local/bin/pm2 list

# 12. Verify outbound relay configuration
postconf relayhost fallback_relay
# Expected: relayhost = (empty)   fallback_relay = [smtp.sendgrid.net]:587

# 13. Verify OpenDKIM is running and wired to Postfix
sudo systemctl status opendkim
ss -tlnp | grep 8891
postconf smtpd_milters non_smtpd_milters

# 14. Verify DKIM key in DNS
sudo opendkim-testkey -d gwallofchina.yulcyberhub.click -s mail -vvv
# Expected: key OK

# 15. Full auth verification (port25 auto-reply)
echo "auth test" | mail -s "auth test" check-auth@verifier.port25.com

# 16. MTA-STS policy file
curl https://mta-sts.gwallofchina.yulcyberhub.click/.well-known/mta-sts.txt

# 17. All ports listening
sudo ss -tlnp | grep -E ':(25|465|587|993)'
```

---

## References

| # | Author(s) | Title | Type | Year | URL |
|---|-----------|-------|------|------|-----|
| [1] | Mozilla Foundation | Mozilla SSL Configuration Generator | Tool | 2024 | https://ssl-config.mozilla.org |
| [2] | Qualys, Inc. | SSL Labs Server Test | Tool | 2024 | https://www.ssllabs.com/ssltest/ |
| [3] | E. Rescorla | The Transport Layer Security (TLS) Protocol Version 1.3 — RFC 8446 | RFC | 2018 | https://datatracker.ietf.org/doc/html/rfc8446 |
| [4] | K. Moriarty and S. Farrell | Deprecating TLS 1.0 and TLS 1.1 — RFC 8996 | RFC | 2021 | https://datatracker.ietf.org/doc/html/rfc8996 |
| [5] | M. Kucherawy and E. Zwicky | Domain-based Message Authentication, Reporting, and Conformance (DMARC) — RFC 7489 | RFC | 2015 | https://datatracker.ietf.org/doc/html/rfc7489 |
| [6] | D. Margolis et al. | SMTP Service Extension for Strict Transport Security (MTA-STS) — RFC 8461 | RFC | 2018 | https://datatracker.ietf.org/doc/html/rfc8461 |
| [7] | P. Hallam-Baker et al. | DNS Certification Authority Authorization (CAA) Resource Record — RFC 8659 | RFC | 2019 | https://datatracker.ietf.org/doc/html/rfc8659 |
| [8] | R. Arends et al. | DNS Security Introduction and Requirements — RFC 4033 | RFC | 2005 | https://datatracker.ietf.org/doc/html/rfc4033 |
| [9] | Let's Encrypt | Let's Encrypt Documentation | Docs | 2024 | https://letsencrypt.org/docs/ |
| [10] | Electronic Frontier Foundation | Certbot Documentation | Docs | 2024 | https://certbot.eff.org/docs/ |
| [11] | K. McKay et al. | Guidelines for the Selection, Configuration, and Use of TLS Implementations — NIST SP 800-52 Rev. 2 | Standard | 2019 | https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final |
| [12] | D. Adrian et al. | Imperfect Forward Secrecy: How Diffie-Hellman Fails in Practice (Logjam Attack) | Research | 2015 | https://weakdh.org |
| [13] | B. Möller, T. Duong, and K. Kotowicz | This POODLE Bites: Exploiting The SSL 3.0 Fallback | Research | 2014 | https://www.openssl.org/~bodo/ssl-poodle.pdf |
| [14] | T. Duong and J. Rizzo | Here Come The ⊕ Ninjas (BEAST Attack) | Research | 2011 | https://nvd.nist.gov/vuln/detail/CVE-2011-3389 |
| [15] | Chromium Project | HSTS Preload List Submission | Web | 2024 | https://hstspreload.org |
| [16] | CISofy | Lynis Security Auditing Tool | Tool | 2024 | https://github.com/CISofy/lynis |
| [17] | ByteNess | aws-vault | Tool | 2024 | https://github.com/ByteNess/aws-vault |
| [18] | Sandia National Laboratories | DNSViz DNSSEC Visualizer | Tool | 2024 | https://dnsviz.net |
| [19] | S. Roy, P. Vorperian | Project Scripts Repository | Code | 2024 | https://github.com/mrblue223/CyberSecurity_School_Labs/tree/main/Optimizing_SSL_Certificates/scripts |
| [20] | Nginx | Module ngx_http_ssl_module | Docs | 2024 | https://nginx.org/en/docs/http/ngx_http_ssl_module.html |
| [21] | W. Venema | Postfix TLS Support | Docs | 2024 | https://www.postfix.org/TLS_README.html |
| [22] | Dovecot | Dovecot SSL Configuration | Docs | 2024 | https://doc.dovecot.org/configuration_manual/dovecot_ssl_configuration/ |
| [23] | Twilio SendGrid | DKIM Records | Docs | 2024 | https://docs.sendgrid.com/ui/account-and-settings/dkim-records |
| [24] | Amazon Web Services | Configuring DNSSEC signing in Amazon Route 53 | Docs | 2024 | https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-configuring-dnssec.html |
| [25] | Amazon Web Services | Key policies in AWS KMS | Docs | 2024 | https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html |
| [26] | Node.js Foundation | Node.js 20 Documentation | Docs | 2024 | https://nodejs.org/en/docs/ |
| [27] | PM2 | PM2 Process Manager Documentation | Docs | 2024 | https://pm2.keystone.io/docs/ |
| [28] | Twilio SendGrid | Inbound Parse Webhook | Docs | 2024 | https://docs.sendgrid.com/for-developers/parsing-email/inbound-email |
| [29] | W. Venema | Postfix Virtual Mailbox Hosting | Docs | 2024 | https://www.postfix.org/VIRTUAL_README.html |
| [30] | The OpenDKIM Project | OpenDKIM Documentation | Docs | 2024 | http://www.opendkim.org/docs.html |
| [31] | The OpenDKIM Project | opendkim.conf(5) man page | Docs | 2024 | http://www.opendkim.org/opendkim.conf.5.html |
| [32] | IETF | MTA-STS Policy File Specification — RFC 8461 | RFC | 2018 | https://datatracker.ietf.org/doc/html/rfc8461 |

---

*Next Review: 2026-06-25 (Quarterly Security Assessment)*
*Distribution: Cyber Defense Team · Operations Center · Compliance Office*
