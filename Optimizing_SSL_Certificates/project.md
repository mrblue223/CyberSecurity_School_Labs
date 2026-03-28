# 🔐 Optimizing SSL/TLS Certificates for Nginx & Postfix

> **Author:** Sammy Roy · **Cohort:** MEQ7 · **Team:** Team 3  
> **Domain:** `gwallofchina.yulcyberhub.click` · **Due:** April 2, 2026

![SSL Labs](https://img.shields.io/badge/SSL%20Labs-A%2B-brightgreen?style=for-the-badge&logo=letsencrypt)
![TLS](https://img.shields.io/badge/TLS-1.3-blue?style=for-the-badge&logo=openssl)
![Let's Encrypt](https://img.shields.io/badge/Certificate-Let's%20Encrypt-orange?style=for-the-badge&logo=letsencrypt)
![AWS](https://img.shields.io/badge/DNS-AWS%20Route%2053-FF9900?style=for-the-badge&logo=amazonaws)
![Rocky Linux](https://img.shields.io/badge/OS-Rocky%20Linux-10B981?style=for-the-badge&logo=rockylinux)
![DNSSEC](https://img.shields.io/badge/DNSSEC-Chain%20Established-purple?style=for-the-badge)
![DMARC](https://img.shields.io/badge/DMARC-p%3Dreject-red?style=for-the-badge)
![License](https://img.shields.io/badge/Classification-Internal%20Technical%20Doc-lightgrey?style=for-the-badge)

---

## 📋 Table of Contents

- [Executive Summary](#executive-summary)
- [Phase 1 — AWS CLI & Credential Security](#phase-1--aws-cli--credential-security)
  - [1.1 Threat Model](#11-threat-model)
  - [1.2 Secure Alternatives: SSO vs. aws-vault](#12-secure-alternatives-sso-vs-aws-vault)
  - [1.3 aws-vault — Encrypted Keyring Credentials](#13-aws-vault--encrypted-keyring-credentials)
  - [1.4 AWS SSO — Non-Persistent Sessions (Step-by-Step)](#14-aws-sso--non-persistent-sessions-step-by-step)
- [Phase 2 — DNS Infrastructure](#phase-2--dns-infrastructure)
  - [2.1 Creating the Hosted Zone](#21-creating-the-hosted-zone)
  - [2.2 DNS Record Architecture](#22-dns-record-architecture)
  - [2.3 DNSSEC Implementation](#23-dnssec-implementation)
- [Phase 3 — EC2 Instance & Security Groups](#phase-3--ec2-instance--security-groups)
  - [3.1 Instance Launch Script](#31-instance-launch-script)
  - [3.2 Deployed Instance Configuration](#32-deployed-instance-configuration)
  - [3.3 Security Group Rules](#33-security-group-rules)
- [Phase 4 — Nginx Web Server Hardening](#phase-4--nginx-web-server-hardening)
  - [4.1 SSL Certificate Choice](#41-ssl-certificate-choice)
  - [4.2 Protocol Selection](#42-protocol-selection)
  - [4.3 Cipher Suites](#43-cipher-suites)
  - [4.4 Perfect Forward Secrecy (PFS)](#44-perfect-forward-secrecy-pfs)
  - [4.5 HTTP Strict Transport Security (HSTS) & Security Headers](#45-http-strict-transport-security-hsts--security-headers)
  - [4.6 Service Hardening](#46-service-hardening)
  - [4.7 Verification](#47-verification)
- [Phase 5 — Mail Server Hardening (Postfix & Dovecot)](#phase-5--mail-server-hardening-postfix--dovecot)
  - [5.1 SSL Certificate Choice](#51-ssl-certificate-choice)
  - [5.2 Installation](#52-installation)
  - [5.3 Protocol Selection](#53-protocol-selection)
  - [5.4 Cipher Suites & Inbound TLS Hardening](#54-cipher-suites--inbound-tls-hardening)
  - [5.5 SMTP Authentication — The Secret Pipe](#55-smtp-authentication--the-secret-pipe)
  - [5.6 SPF / DKIM / DMARC / MTA-STS](#56-spf--dkim--dmarc--mta-sts)
  - [5.7 Verification](#57-verification)
- [Phase 6 — Challenges & Trade-Offs](#phase-6--challenges--trade-offs)
  - [6.1 Security vs. Compatibility](#61-security-vs-compatibility)
  - [6.2 Performance Considerations](#62-performance-considerations)
  - [6.3 Testing & Troubleshooting](#63-testing--troubleshooting)
- [References](#references)

---

## Executive Summary

This document is a comprehensive technical reflection on the **"Great Wall"** hardened SSL/TLS infrastructure project. The deployment follows a structured sequence: AWS credentials → DNS → EC2 → Nginx → Postfix/Dovecot. The project achieved **A+ ratings on SSL Labs for both web and mail services**, implementing zero-trust principles, modern cryptography, and defense-in-depth strategies across every layer.

| Component | Rating | Key Achievement |
|---|---|---|
| Web Server (Nginx) | ![A+](https://img.shields.io/badge/-A%2B-brightgreen) | TLS 1.3 · HSTS Preload · OCSP Stapling |
| Mail Server (Postfix/Dovecot) | ![A+](https://img.shields.io/badge/-A%2B-brightgreen) | SMTPS/IMAPS · SPF/DKIM/DMARC · MTA-STS |
| Certificate Score | 100/100 | Let's Encrypt SAN cert (ISRG Root X1) |
| Protocol Score | 100/100 | TLS 1.2 + 1.3 only; all legacy disabled |
| Key Exchange Score | 100/100 | ECDHE/DHE with 4096-bit DH params |
| Cipher Strength Score | 100/100 | AEAD-only suites (AES-GCM, ChaCha20) |

![Nginx Landing Page](images/image14.png)
*The "Great Wall" live Nginx landing page — Team 3, NGINX Division. SSL / TLS · A+ Rated · Secure Connection.*

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

![AWS SSO Configure](images/image18.png)
*`aws configure sso` — SSO session name "meq7", region `us-east-1`. The CLI automatically detected the single available account (`YulCyberClick Demo`, 453875232433) and role (`MEQ7_RBAC_Room3`). SSO URL redacted.*

![AWS SSO Access Portal](images/image17.png)
*AWS Access Portal — `YulCyberClick Demo` account under `MEQ7_RBAC_Room3`. The **"Access keys"** link generates temporary STS credentials on demand — no permanent IAM user keys exist at any point.*

![AWS SSO Login Success](images/image11.png)
*`aws sso login --profile meq7` — successful browser-based SSO authentication. Profile name and SSO URL redacted for operational security.*

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

![AWS STS Caller Identity](images/image15.png)
*`aws sts get-caller-identity --profile meq7` — confirms the active session is a temporary STS assumed-role token, not a permanent IAM key. The ARN format `arn:aws:sts::ACCOUNT:assumed-role/...` is the proof — a permanent key would return `arn:aws:iam::ACCOUNT:user/USERNAME`. UserId, Account, and ARN redacted.*

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

![Route 53 Hosted Zone Created](images/image46.png)
*Green success banner: **"gwallofchina.yulcyberhub.click was successfully created."** The zone starts with 2 records (NS + SOA). The four AWS name servers visible (`ns-144.awsdns-18.com`, `ns-689.awsdns-22.net`, `ns-1306.awsdns-35.org`, `ns-1584.awsdns-06.co.uk`) were handed to the Oracle to complete DNS delegation.*

![Route 53 Hosted Zone Creation Form](images/image9.png)
*AWS Route 53 "Create hosted zone" form — domain `gwallofchina.yulcyberhub.click`, type: **Public Hosted Zone**, tags: Cohort=MEQ7, Team=Team3.*

![Hosted Zone CLI Verification](images/image16.png)
*`aws route53 list-hosted-zones` — confirms Zone ID `Z0433076DMIP84BGAZGN`, domain `gwallofchina.yulcyberhub.click.`, `PrivateZone: False` — publicly resolvable on the internet.*

---

### 2.2 DNS Record Architecture

The final hosted zone contains 18 records covering all required services and security mechanisms.

![Route 53 All 18 Records](images/image19.png)
*AWS Route 53 hosted zone — all 18 DNS records visible: A, AAAA, CAA, MX, NS, SOA, TXT (SPF, DMARC, DKIM, MTA-STS), SRV, and CNAME records.*

![Route 53 Detailed Record Values](images/image35.png)
*Full record list with values: A (`54.226.198.180`), CAA (`letsencrypt.org` + `amazonaws.com`), MX (`10 mail.*`), NS (four AWS servers), SPF (`v=spf1 ip4:54.226.198.180 mx -all`), DMARC (`p=reject`), DKIM, MTA-STS, `_smtp._tls`, `_visual_hash`, `_autodiscover._tcp` SRV, `mail.` A record, and `www.` CNAME.*

**Foundation Records:**

| Record | Type | Value | Purpose |
|---|---|---|---|
| `@` | A | 54.226.198.180 | IPv4 entry point |
| `@` | AAAA | `::0` | IPv6 placeholder (future) |
| `www` | CNAME | `gwallofchina.yulcyberhub.click` | Canonical alias |
| `mail` | A | 54.226.198.180 | Mail host |

**CA Authorization Records:**

```dns
@ CAA 0 issue "letsencrypt.org"
@ CAA 0 issue "amazonaws.com"
```

CAA records restrict certificate issuance to Let's Encrypt only — preventing rogue CA issuance and shadow IT certificate creation.

**Email Security Records:**

| Record | Type | Value | Mechanism |
|---|---|---|---|
| `@` | MX | `10 mail.gwallofchina.yulcyberhub.click` | Mail routing |
| `@` | TXT | `v=spf1 ip4:54.226.198.180 mx -all` | SPF hard fail |
| `_dmarc` | TXT | `v=DMARC1; p=reject; ...` | Reject spoofed mail |
| `s1._domainkey` | CNAME | SendGrid DKIM endpoint | Auto-rotating DKIM |
| `s2._domainkey` | CNAME | SendGrid DKIM endpoint | Redundant DKIM |
| `_mta-sts` | TXT | `v=STSv1; id=20240101...` | SMTP TLS enforcement |
| `_smtp._tls` | TXT | `v=TLSRPTv1; rua=...` | TLS failure reporting |

The SendGrid DNS records (CNAME-based DKIM) were generated directly from the SendGrid Sender Authentication dashboard:

![SendGrid DKIM Records](images/image34.png)
*SendGrid Sender Authentication — "Add all of these records to your host's DNS section." Provides the three CNAME records for DKIM (`em5287`, `s1._domainkey`, `s2._domainkey`) and the DMARC TXT record with `p=reject; adkim=s; aspf=s`. These were applied to Route 53 via the AWS CLI.*

---

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

![AWS KMS CMK Details](images/image32.png)
*AWS KMS — CMK alias: `GWALLkey`, ARN: `arn:aws:kms:us-east-1:453875232433:key/df174539-4815-420b-a6ce-64052f66d6eb`, Status: **Enabled**, Created: Mar 26 2026 19:54 EDT, Single Region. Tags: Cohort=MEQ7, Team=Room3.*

![AWS KMS Tags Updated](images/image47.png)
*KMS "Add or edit tags" — green banner: **"Tags updated"**. Tag keys `Cohort = MEQ7` and `Team = Room3` saved. These tags ensure the key is attributable to our cohort for billing and access auditing.*

**Step 2 — Enable DNSSEC Signing and Create the KSK:**

With the CMK in place, we navigated to Route 53 → DNSSEC signing → Enable. The KSK was named `GWALLkey` and linked to our CMK:

![Route 53 DNSSEC Tab](images/image54.png)
*Route 53 hosted zone with all 18 records — the **"DNSSEC signing"** tab (highlighted) is where the KSK was created to begin zone signing.*

![DNSSEC KSK Creation Form](images/image28.png)
*Route 53 "Enable DNSSEC signing" — KSK name: `GWALLkey`, "Create customer managed CMK" selected, alias `GWALLkey`. **"Create KSK and enable signing"** clicked to initiate the process.*

**Step 3 — First Attempt: KMS Permissions Error:**

The first attempt failed because the initial CMK key policy did not grant Route 53 the required actions:

![DNSSEC KMS Permissions Error](images/image38.png)
*Route 53 error: "The customer managed KMS key does not grant all the required permissions for DNSSEC usage... verify that you and Route 53 have permissions for: `DescribeKey`, `GetPublicKey`, and `Sign`." Resolution: updated the key policy to include `route53.amazonaws.com` as a permitted principal, then re-attempted.*

**Step 4 — Signing Activation:**

After fixing the key policy, Route 53 began signing the zone:

![DNSSEC Signing in Progress](images/image37.png)
*Blue banner: **"Enabling DNSSEC signing for the hosted zone gwallofchina.yulcyberhub.click. This can take a moment."** The CMK ARN is confirmed. Route 53 generates DNSKEY records and signs all zone records.*

**Step 5 — KSK Active, DS Record Ready for Oracle:**

![DNSSEC Signing Successfully Enabled](images/image55.png)
*Green banner: **"DNSSEC signing was successfully enabled."** DNSSEC signing status: **Signing**. KSK `GWALLkey` — Status: **Active**, created March 26 2026. The **"View information to create DS record"** button (highlighted) provides the DS record hash for the Oracle.*

![DNSSEC Signing Active — Full View](images/image56.png)
*Confirmation view — the "Establish chain of trust for DNSSEC" info box remains until the Oracle completes the DS record delegation. This was the state handed to the instructor.*

![GWALLkey Chain of Trust Details](images/image21.png)
*GWALLkey details — **DS record provided to Oracle**: `11486 13 2 5D8E98E506AB70F3CF69286813298312235CA86318D376D221D964A26A2B98A7`. Key tag: `11486`, Digest algorithm: SHA-256, Signing algorithm: ECDSAP256SHA256 (type 13). CMK `alias/GWALLkey` status: **Enabled**.*

**Step 6 — Oracle Inserts DS Record → Chain Established:**

Once the Oracle inserted the DS record into the `yulcyberhub.click` parent zone, the full chain of trust activated. The `dig` command returned the `ad` (Authenticated Data) flag:

![DNSSEC dig Validation](images/image3.png)
*`dig +dnssec MX gwallofchina.yulcyberhub.click` — `flags: qr rd ra **ad**`. The `ad` flag confirms DNSSEC is fully validated end-to-end via Cloudflare's 1.1.1.1 resolver. The RRSIG record is visible in the answer section.*

`delv` provided independent resolver-level confirmation with an explicit **"fully validated"** verdict:

![delv Fully Validated](images/image58.png)
*`delv @1.1.1.1 gwallofchina.yulcyberhub.click` — `; fully validated`. The A record `54.226.198.180` and its RRSIG (ECDSA P-256, valid until Mar 28 2026) are returned. "Fully validated" is the strongest possible DNSSEC confirmation from a validating resolver.*

DNSViz confirmed all statuses as **Secure** across the complete chain:

![DNSViz Full Secure Status](images/image45.png)
*DNSViz — **RRset status: Secure (6)**, **DNSKEY/DS/NSEC status: Secure (14)**, **Delegation status: Secure (3)**. All indicators green. Full DNSKEY hierarchy: root → `.click` TLD → `yulcyberhub.click` → our zone.*

![DNSViz Chain — TLD and Parent](images/image13.png)
*DNSViz upper levels — `.click` TLD and `yulcyberhub.click` parent: DNSKEY and DS records visible. The Oracle's DS record linking to our zone is present and verified.*

![DNSViz Chain — Our Zone](images/image12.png)
*DNSViz — `gwallofchina.yulcyberhub.click`: DNSKEY records (KSK and ZSK) signing all record types. No broken links, no red warnings.*

**Key Takeaway:** DNSSEC is a cooperative mechanism. A signed zone without a DS record in the parent is invisible to validating resolvers. The Oracle's action — inserting that single DS record — was the enabling step our team could not perform ourselves.

**Compensating controls while waiting for the Oracle:**
- CAA records restricted issuance to Let's Encrypt only
- Certificate Transparency monitoring for unauthorized issuance
- DANE/TLSA planned for future deployment

---

## Phase 3 — EC2 Instance & Security Groups

### 3.1 Instance Launch Script

Rather than manually clicking through the AWS console, a custom bash script (`launch-instance.sh`) was written to automate EC2 deployment reproducibly. This ensures consistent configuration across deployments and eliminates human error during instance provisioning.

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

**Reusing for other labs** — only these four variables need changing:

```bash
AMI="new-ami"
INSTANCE_TYPE="t3.medium"
KEY_NAME="new-key"
SECURITY_GROUP="sg-new"
```

> **IMDSv2 enforcement:** The `--metadata-options '{"HttpTokens":"required"}'` flag forces Instance Metadata Service v2, which requires a session token for all metadata requests. This prevents SSRF attacks from reading instance metadata (including IAM role credentials) via a simple HTTP GET — a known attack vector against cloud workloads.

### 3.2 Deployed Instance Configuration

After running the script, the resulting instance was verified:

| Field | Value |
|---|---|
| Instance ID | `i-0b71d405f8ad5f73b` |
| Instance Type | `t4g.small` (ARM64 / Graviton2) |
| Public IP | `54.226.198.180` |
| OS | Rocky Linux 10 (aarch64) |
| Name Tag | `Web-Server-Server` |
| Security Group | `sg-0c7a7efce68ce2773` |

The instance is attached to a **single** security group — no additional groups — minimizing the attack surface.

### 3.3 Security Group Rules

**Security Group:** `Meq7 - Room 3 - The Real Deal` (`sg-0c7a7efce68ce2773`)

**Inbound Rules:**

| Port | Protocol | Source | Purpose |
|---|---|---|---|
| 80 | TCP | 0.0.0.0/0 | HTTP → HTTPS redirect |
| 443 | TCP | 0.0.0.0/0 | HTTPS (web) |
| 465 | TCP | 0.0.0.0/0 | SMTPS (implicit TLS) |
| 993 | TCP | 0.0.0.0/0 | IMAPS (implicit TLS) |
| 22 | TCP | 204.244.197.216/32 + 0.0.0.0/0 | SSH (team IP + open for lab) |

> **Note on port 22:** The open `0.0.0.0/0` rule is a documented lab concession for operational flexibility. Production environments must restrict SSH to bastion hosts or use EC2 Instance Connect with IAM-enforced OS user restrictions.

![Security Group Table Output](images/image7.png)
*`aws ec2 describe-security-groups --output table` — all inbound rules confirmed. Tags: Team=Room3, Cohort=MEQ7.*

![Security Group JSON Output](images/image10.png)
*`aws ec2 describe-security-groups --output json` — machine-readable confirmation of all IpPermissions, including dual CIDR entries for port 22.*

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

A single certificate covers both the web and mail services, verified by SSL Labs:

![SSL Labs A+ Web Server](images/image27.png)
*Qualys SSL Labs — `gwallofchina.yulcyberhub.click` at IP `54.226.198.180`: **A+** in 53.92 seconds. Assessed Wed, 25 Mar 2026.*

![SSL Labs Detailed Certificate](images/image60.png)
*SSL Labs certificate detail — **EC 256 bits (SHA384withECDSA)**. SAN covers both `gwallofchina.yulcyberhub.click` **and** `mail.gwallofchina.yulcyberhub.click` — one cert, two services. Valid Mar 25 → Jun 23 2026. Issuer: Let's Encrypt E8. **Certificate Transparency: Yes**. Revocation: Good (not revoked). Weak key: No.*

**Why Let's Encrypt?**

| Consideration | Rationale |
|---|---|
| **Cost** | Free — no commercial CA fees |
| **Trust** | ISRG Root X1 — trusted by all major browsers and mail clients |
| **Automation** | Certbot + systemd timer handles 90-day renewal |
| **Transparency** | All issuances logged in CT logs for monitoring |
| **Unified identity** | Single SAN cert shared across Nginx, Postfix, Dovecot |

**Certificate chain:**

```
ISRG Root X1 → Let's Encrypt E8 → gwallofchina.yulcyberhub.click
```

![HTTPS Certificate Chain from Kali](images/image26.png)
*`openssl s_client -connect gwallofchina.yulcyberhub.click:443` from Kali — depth=2 ISRG Root X1 → depth=1 Let's Encrypt E8 → depth=0 domain. EC (prime256v1) key, ecdsa-with-SHA384. Valid Mar 25 → Jun 23 2026.*

![HTTPS Certificate Chain from Rocky](images/image33.png)
*Same command from Rocky Linux — `CONNECTED(00000003)`, `New, TLSv1.3, Cipher is TLS AES 256 GCM SHA384`. Peer Temp Key: X25519 (253-bit). Verification: OK.*

---

### 4.2 Protocol Selection

| Protocol | Status | Reason |
|---|---|---|
| SSLv2 | ❌ Disabled | Cryptographic design broken (1995) |
| SSLv3 | ❌ Disabled | POODLE (CVE-2014-3566) |
| TLS 1.0 | ❌ Disabled | BEAST (CVE-2011-3389), RC4 dependency |
| TLS 1.1 | ❌ Disabled | No AEAD support; deprecated RFC 8996 (2021) |
| TLS 1.2 | ✅ Enabled | Industry baseline for ECDHE + AEAD |
| TLS 1.3 | ✅ Enabled | PFS built-in, encrypted handshake, reduced latency |

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

![HTTP 301 Redirect](images/image24.png)
*`curl -I http://gwallofchina.yulcyberhub.click` — `HTTP/1.1 301 Moved Permanently`, `Location: https://gwallofchina.yulcyberhub.click/`. Server header: `nginx` with no version disclosed.*

![HTTP 301 — Early Verification](images/image43.png)
*Second `curl -I` from Kali at 02:33 UTC — same 301 response. Confirms the redirect was live from initial deployment, not just at final testing time.*

---

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

---

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

Default 1024-bit DH parameters are vulnerable to the Logjam attack (CVE-2015-4000). Custom 4096-bit parameters eliminate this.

**Session ticket hardening:**

```nginx
ssl_session_tickets off;        # Disable ticket-based resumption (PFS risk)
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
```

**Live TLS 1.3 handshake proof:**

![TLS 1.3 Handshake — PFS Confirmed](images/image36.png)
*`New, TLSv1.3, Cipher is TLS AES 256 GCM SHA384`. Peer signature: `ecdsa_secp256r1_sha256`. Peer Temp Key: **X25519, 253 bits** — ephemeral ECDH key exchange confirming PFS is active on every session. Verification: OK. SSL handshake: 2711 bytes read.*

---

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

**OCSP Stapling** — caches revocation status and serves it with the TLS handshake, eliminating client-side OCSP latency and CA privacy leakage:

```nginx
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
```

---

### 4.6 Service Hardening

**Rate Limiting (DDoS mitigation):**

```nginx
limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;
limit_req zone=mylimit burst=20 nodelay;
```

**Nginx cache directory hardening:**

```bash
sudo mkdir -p /var/cache/nginx
sudo chown nginx:nginx /var/cache/nginx
sudo chmod 700 /var/cache/nginx
```

![Nginx Cache Hardening](images/image4.png)
*`mkdir -p /var/cache/nginx`, `chown nginx:nginx`, `chmod 700` — cache directory owned exclusively by the nginx process user. No other user or group has access.*

**systemd sandboxing** — kernel-level confinement applied via service override:

![Nginx systemd Sandboxing](images/image22.png)
*`systemctl edit nginx.service` — `PrivateDevices=yes` (no raw device access), `ProtectSystem=strict` (filesystem read-only except /run and /tmp), `ProtectHome=yes` (home directories inaccessible), `NoNewPrivileges=yes` (blocks setuid/setgid escalation). Mandatory access control at the process level.*

---

### 4.7 Verification

![Nginx Verify Script](images/image2.png)
*`nginx_verify3.0.sh` automated output — all checks passed: TLS 1.2 ✅, TLS 1.3 ✅, TLS 1.1 correctly rejected ✅, TLS 1.0 correctly rejected ✅, HTTP/2 active ✅, HTTP redirect 301 ✅, HTTPS 200 OK ✅, all 11 security headers present ✅, server version not disclosed ✅.*

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

The Dovecot certificate paths were configured to point directly to the Let's Encrypt live directory:

![Dovecot SSL Certificate Config](images/image42.png)
*`/etc/dovecot/conf.d/10-ssl.conf` — `ssl_cert = </etc/letsencrypt/live/gwallofchina.yulcyberhub.click/fullchain.pem` and `ssl_key = </etc/letsencrypt/live/gwallofchina.yulcyberhub.click/privkey.pem`. The `<` operator reads the file content. This is the same SAN certificate covering both web and mail.*

---

### 5.2 Installation

Postfix and Dovecot were installed from the Rocky Linux AppStream repository and enabled to start on boot:

```bash
sudo dnf install postfix cyrus-sasl-plain mailx -y
sudo systemctl enable --now postfix

sudo dnf install dovecot -y
sudo systemctl enable --now dovecot
```

![Postfix Already Installed](images/image53.png)
*`sudo dnf install postfix cyrus-sasl-plain -y` — both packages already present (`postfix-2:3.8.5-8.el10.aarch64`, `cyrus-sasl-plain-2.1.28-29.el10.aarch64`). `sudo systemctl enable --now postfix` enables the service. The annotation confirms idempotent installation.*

![Full Dovecot Installation](images/image29.png)
*Full `dnf install dovecot` output — version `1:2.3.21-16.el10.aarch64`, 4.8 MB from AppStream. `sudo systemctl enable --now dovecot` creates the systemd symlink. Both services pinned to start on boot.*

---

### 5.3 Protocol Selection

**Dovecot minimum protocol — `/etc/dovecot/conf.d/10-ssl.conf`:**

![Dovecot ssl_min_protocol](images/image40.png)
*`ssl_min_protocol = TLSv1.2` — Dovecot recognises `SSLv3`, `TLSv1`, `TLSv1.1`, `TLSv1.2`, `TLSv1.3`, `ANY`, and `LATEST`. Setting `TLSv1.2` enforces the same minimum as Nginx — all pre-TLS-1.2 connections rejected at the daemon level.*

**Disabling plaintext IMAP — `/etc/dovecot/conf.d/10-master.conf`:**

![Dovecot imap-login Port Config](images/image44.png)
*`inet_listener imap { port = 0 }` — plaintext IMAP disabled (no listener bound). `inet_listener imaps { port = 993; ssl = yes }` — only encrypted IMAPS accepted. Plaintext login is architecturally impossible.*

**Full Dovecot SSL block:**

```ini
ssl = required
ssl_cert = </etc/letsencrypt/live/gwallofchina.yulcyberhub.click/fullchain.pem
ssl_key  = </etc/letsencrypt/live/gwallofchina.yulcyberhub.click/privkey.pem
ssl_min_protocol = TLSv1.2
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

**Hostname verification:**

![Postfix myhostname](images/image23.png)
*`postconf myhostname` → `myhostname = mail.gwallofchina.yulcyberhub.click`. This is what Postfix presents in HELO/EHLO banners and what receiving servers validate against the PTR/MX record.*

**Port allocation:**

| Port | Service | Protocol | Rationale |
|---|---|---|---|
| 465 | SMTPS | Implicit TLS | No STARTTLS downgrade possible |
| 993 | IMAPS | Implicit TLS | No STARTTLS downgrade possible |
| 587 | SMTP Relay | STARTTLS (outbound to SendGrid only) | AWS port 25 blocked |

**Port listening verification:**

![Mail Ports Listening](images/image31.png)
*`sudo ss -tulpn | grep -E ':(465|587|993)'` — all six entries confirmed: `0.0.0.0:587`, `0.0.0.0:993`, `0.0.0.0:465` and their `[::]` IPv6 equivalents. Postfix and Dovecot bound on all interfaces.*

---

### 5.4 Cipher Suites & Inbound TLS Hardening

Postfix was hardened for both inbound (smtpd) and outbound (smtp) TLS, reusing the same 4096-bit DH parameters generated for Nginx:

```bash
sudo postconf -e "smtpd_tls_cert_file = /etc/letsencrypt/live/gwallofchina.yulcyberhub.click/fullchain.pem"
sudo postconf -e "smtpd_tls_key_file  = /etc/letsencrypt/live/gwallofchina.yulcyberhub.click/privkey.pem"
sudo postconf -e "smtpd_tls_security_level = may"
sudo postconf -e "smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
sudo postconf -e "smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
sudo postconf -e "smtpd_tls_dh1024_param_file = /etc/nginx/ssl/dhparam.pem"
```

![Postfix SMTPD TLS Configuration](images/image52.png)
*All `postconf -e` commands applied to Rocky Linux: cert/key paths, `security_level = may` (opportunistic inbound TLS), legacy protocols explicitly excluded (`!SSLv2, !SSLv3, !TLSv1, !TLSv1.1`), and the 4096-bit DH param file shared from the Nginx configuration — Logjam mitigation applied consistently across both services.*

---

### 5.5 SMTP Authentication — The Secret Pipe

AWS blocks outbound port 25 on EC2 by default. All outbound mail is routed through **SendGrid** as an authenticated relay on port 587 (STARTTLS), bypassing this restriction while maintaining a legitimate DKIM-signed identity.

**Postfix ↔ Dovecot SASL Integration:**

Authentication is delegated from Postfix to Dovecot via a Unix socket, avoiding the need for a separate SASL daemon:

```bash
sudo postconf -e "smtpd_sasl_type = dovecot"
sudo postconf -e "smtpd_sasl_path = private/auth"
sudo postconf -e "smtpd_sasl_auth_enable = yes"
sudo systemctl restart postfix
```

![Postfix SASL Dovecot Integration](images/image41.png)
*`smtpd_sasl_type = dovecot`, `smtpd_sasl_path = private/auth`, `smtpd_sasl_auth_enable = yes`. Postfix now delegates all SASL authentication decisions to Dovecot's auth daemon via the Unix socket at `private/auth` (relative to Postfix's chroot queue directory).*

**Dovecot SASL socket configuration — `/etc/dovecot/conf.d/10-master.conf`:**

![Dovecot unix_listener Config](images/image49.png)
*`unix_listener /var/spool/postfix/private/auth { mode = 0666; user = postfix; group = postfix }`. Mode `0666` is required because Postfix cannot use `0600` — it runs as its own user and must have socket access. Owner and group are `postfix`, keeping the socket boundary correct. `0777` would allow all users — `0666` restricts to explicit socket connections.*

**Postfix auth socket permissions verified:**

![Postfix Auth Socket](images/image20.png)
*`/var/spool/postfix/private/auth` — `srw-rw----` (660). Socket accessible to Postfix and `mail` group only — no world-readable exposure of the SASL channel.*

**SendGrid relay credentials — `/etc/postfix/sasl_passwd`:**

```bash
# Store credential (never in plaintext on disk long-term)
echo "[smtp.sendgrid.net]:587 apikey:SG.YOUR_KEY_HERE" \
  | sudo tee /etc/postfix/sasl_passwd

# Compile to LMDB (Rocky Linux — Berkeley DB removed)
sudo postmap lmdb:/etc/postfix/sasl_passwd

# Lock down — credential file must never be world-readable
sudo chmod 0600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.lmdb
```

**Full relay and database configuration:**

```bash
sudo postconf -e "relayhost = [smtp.sendgrid.net]:587"
sudo postconf -e "smtp_sasl_auth_enable = yes"
sudo postconf -e "smtp_sasl_password_maps = lmdb:/etc/postfix/sasl_passwd"
sudo postconf -e "smtp_sasl_security_options = noanonymous"
sudo postconf -e "default_database_type = lmdb"
sudo postconf -e "alias_database = lmdb:/etc/aliases"
sudo postconf -e "alias_maps = lmdb:/etc/aliases"
```

> **Rocky Linux compatibility:** Rocky Linux 9/10 removed Berkeley DB — all `hash:` map types fail with `unsupported dictionary type: hash`. Migrating everything to `lmdb:` resolved this.

**STARTTLS local verification:**

![STARTTLS localhost Test](images/image50.png)
*`openssl s_client -starttls smtp -connect localhost:25` — confirms Postfix correctly advertises and negotiates STARTTLS on the local SMTP port. The full inbound TLS pipeline is verified on the server itself.*

---

### 5.6 SPF / DKIM / DMARC / MTA-STS

**SPF — Hard Fail:**

```dns
@ TXT "v=spf1 ip4:54.226.198.180 mx -all"
```

`-all` instructs receiving servers to **reject** (not just mark) any message from an unauthorized source.

**DKIM — CNAME delegation to SendGrid:**

```dns
s1._domainkey  CNAME  s1.domainkey.u61568083.wl084.sendgrid.net
s2._domainkey  CNAME  s2.domainkey.u61568083.wl084.sendgrid.net
em5287         CNAME  u61568083.wl084.sendgrid.net
```

CNAME-based DKIM allows SendGrid to rotate 2048-bit RSA keys automatically without requiring manual DNS updates.

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
_mta-sts  TXT  "v=STSv1; id=20240101000000"
_smtp._tls TXT  "v=TLSRPTv1; rua=mailto:admin@gwallofchina.yulcyberhub.click"
```

MTA-STS prevents SMTP MitM downgrade attacks by requiring TLS with a valid certificate. TLS-RPT reports any encryption failures or downgrade attempts.

---

### 5.7 Verification

**IMAPS (Port 993):**

![IMAPS from Rocky Linux](images/image30.png)
*`openssl s_client -connect mail.gwallofchina.yulcyberhub.click:993 -quiet` from Rocky Linux — full chain ISRG Root X1 → E8 → domain. `* OK [...] Dovecot ready.`*

![IMAPS from Kali](images/image6.png)
*Same command from Kali — identical chain and Dovecot IMAP4rev1 banner. Cross-platform validation.*

**SMTPS (Port 465):**

![SMTPS Port 465 from Rocky](images/image57.png)
*`openssl s_client -connect mail.gwallofchina.yulcyberhub.click:465 -quiet` from Rocky Linux — full chain verified. `220 mail.gwallofchina.yulcyberhub.click ESMTP Postfix` banner.*

![SMTPS Port 465 from Kali](images/image59.png)
*Same from Kali — identical chain and `220 ESMTP Postfix` banner. Confirms port 465 serves correct implicit TLS from any external client.*

**End-to-End Mail Delivery:**

![AEC Final Audit Email](images/image1.png)
*Gmail inbox — "AEC Final Audit" received from `admin@gwallofchina.yulcyberhub.click`. Confirms the full SendGrid relay chain is operational and the domain identity is trusted by Google's mail infrastructure.*

![Local Mail Delivery](images/image5.png)
*Local delivery test: three messages in `/var/spool/mail/root`, `From: Cloud User <rocky@mail.gwallofchina.yulcyberhub.click>`. Postfix local transport confirmed.*

**SSL Labs A+ — Mail Server:**

![SSL Labs A+ Mail Server](images/image39.png)
*Qualys SSL Labs — `mail.gwallofchina.yulcyberhub.click` (54.226.198.180): **A+**. TLS 1.3, HSTS long-duration, CAA policy found. Certificate: EC 256 bits, SHA384withECDSA.*

![SSL Labs A+ Mail — Detailed](images/image48.png)
*Detailed SSL Labs mail report — identical A+ rating. Certificate fingerprint and SAN confirm shared cert with main domain. Certificate Transparency: Yes.*

---

## Phase 6 — Challenges & Trade-Offs

### 6.1 Security vs. Compatibility

**Disabling TLS 1.0 / 1.1**

Disabling legacy protocols impacts ≤2% of clients (IE11 on Windows 7, unsupported since 2020). Accepted because the affected population runs unpatched software that presents greater ecosystem risk than the accessibility loss.

**CSP `unsafe-inline`**

`style-src` and `script-src` include `'unsafe-inline'` — required by the current page architecture. Planned migration to nonce-based CSP (`'nonce-{random}'`) will address this without breaking inline functionality.

**SSH Port 22**

Open to `0.0.0.0/0` alongside the team IP for lab operational flexibility. Explicitly documented as a known limitation — production requires bastion-only restriction.

---

### 6.2 Performance Considerations

**DH Parameter Generation:**  
4096-bit DH parameter generation takes 10–20 minutes on t4g.small — one-time cost, not per-connection. Security gain (Logjam mitigation) far outweighs the delay.

**TLS Session Cache:**  
10MB shared cache (~40,000 sessions) reduces handshake overhead on returning clients while `ssl_session_tickets off` preserves PFS.

**HTTP/2:**  
HPACK header compression and multiplexed requests reduce page load latency without security trade-offs. Confirmed: `[PASS] HTTP/2: active`.

**ChaCha20-Poly1305:**  
Included specifically for the ARM64 Graviton2 processor — on hardware without AES-NI, ChaCha20 outperforms AES-GCM in software. Both Nginx and Postfix benefit from this cipher being in the priority list.

---

### 6.3 Testing & Troubleshooting

**Issues Encountered and Resolutions:**

| Issue | Root Cause | Resolution |
|---|---|---|
| `unsupported dictionary type: hash` | Rocky Linux 9/10 removed Berkeley DB | Migrated all `hash:` maps to `lmdb:` |
| Lynis download redirect failure | Vendor CDN issue in Rocky 10 | Used GitHub tar.gz with `curl -L` |
| DNSSEC — no `ad` flag | Oracle had not yet inserted DS record into parent zone | Waited for Oracle; CAA + CT as interim controls |
| DNSSEC — KMS permissions error | Initial CMK policy did not grant Route 53 `DescribeKey`, `GetPublicKey`, `Sign` | Updated key policy to include `route53.amazonaws.com` as principal |
| Certificate permission denied (Postfix/Dovecot) | `/etc/letsencrypt` root-owned only | `ssl-cert` group + `chmod 750` + `g+s` sticky bit |
| Nginx zombie processes on restart | Improper restart sequence | `pkill -9 nginx` before `systemctl start nginx` |

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
```

**Final SSL Labs Summary:**

| Domain | Overall | Certificate | Protocol | Key Exchange | Cipher |
|---|---|---|---|---|---|
| `gwallofchina.yulcyberhub.click` | **A+** | 100 | 100 | 100 | 100 |
| `mail.gwallofchina.yulcyberhub.click` | **A+** | 100 | 100 | ~90 | ~90 |

---

## References

| Resource | URL |
|---|---|
| Mozilla SSL Configuration Generator | https://ssl-config.mozilla.org |
| Qualys SSL Labs Server Test | https://www.ssllabs.com/ssltest/ |
| RFC 8446 — TLS 1.3 | https://datatracker.ietf.org/doc/html/rfc8446 |
| RFC 8996 — Deprecating TLS 1.0 & 1.1 | https://datatracker.ietf.org/doc/html/rfc8996 |
| RFC 7489 — DMARC | https://datatracker.ietf.org/doc/html/rfc7489 |
| RFC 8461 — MTA-STS | https://datatracker.ietf.org/doc/html/rfc8461 |
| RFC 8659 — CAA Records | https://datatracker.ietf.org/doc/html/rfc8659 |
| RFC 4033/4034/4035 — DNSSEC | https://datatracker.ietf.org/doc/html/rfc4033 |
| Let's Encrypt Documentation | https://letsencrypt.org/docs/ |
| Certbot Documentation | https://certbot.eff.org/docs/ |
| NIST SP 800-52 Rev. 2 — TLS Guidelines | https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final |
| Logjam Attack (CVE-2015-4000) | https://weakdh.org |
| POODLE Attack (CVE-2014-3566) | https://www.openssl.org/~bodo/ssl-poodle.pdf |
| BEAST Attack (CVE-2011-3389) | https://nvd.nist.gov/vuln/detail/CVE-2011-3389 |
| HSTS Preload List | https://hstspreload.org |
| Lynis Security Auditing Tool | https://github.com/CISofy/lynis |
| aws-vault (ByteNess fork) | https://github.com/ByteNess/aws-vault |
| DNSViz DNSSEC Visualizer | https://dnsviz.net |
| Project Scripts Repository | https://github.com/mrblue223/CyberSecurity_School_Labs/tree/main/Optimizing_SSL_Certificates/scripts |
| Nginx SSL/TLS Documentation | https://nginx.org/en/docs/http/ngx_http_ssl_module.html |
| Postfix TLS README | https://www.postfix.org/TLS_README.html |
| Dovecot SSL Configuration | https://doc.dovecot.org/configuration_manual/dovecot_ssl_configuration/ |
| SendGrid DKIM Authentication | https://docs.sendgrid.com/ui/account-and-settings/dkim-records |
| AWS Route 53 DNSSEC | https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-configuring-dnssec.html |
| AWS KMS Key Policies | https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html |

---

<div align="center">

**Document Control**

| Version | Date | Author | Changes |
|---|---|---|---|
| 3.0 | 2026-02-25 | Sammy Roy | Initial hardened infrastructure documentation |
| 3.1 | 2026-03-28 | Sammy Roy | Assignment reflection + 40 screenshots + DNSSEC step-by-step |
| 3.2 | 2026-03-28 | Sammy Roy | +20 screenshots: Dovecot, Postfix SASL, SMTPS, delv, DNSViz |
| 3.3 | 2026-03-28 | Sammy Roy | Full restructure: deployment-flow order (CLI → DNS → EC2 → Nginx → Postfix) |
| 3.4 | 2026-03-28 | Paulo Borelli  | Added SSO step-by-step, EC2 launch script (`launch-instance.sh`), IMDSv2 hardening |

*Next Review: 2026-06-25 (Quarterly Security Assessment)*  
*Distribution: Cyber Defense Team · Operations Center · Compliance Office*

---

![Built with](https://img.shields.io/badge/Built%20with-Rocky%20Linux-10B981?style=flat-square&logo=rockylinux)
![Secured by](https://img.shields.io/badge/Secured%20by-Let's%20Encrypt-FF7700?style=flat-square&logo=letsencrypt)
![Hosted on](https://img.shields.io/badge/Hosted%20on-AWS%20EC2-FF9900?style=flat-square&logo=amazonaws)
![Audited by](https://img.shields.io/badge/Audited%20by-Lynis%203.1.2-blue?style=flat-square)
![DNSSEC](https://img.shields.io/badge/DNSSEC-Fully%20Validated-purple?style=flat-square)
![Screenshots](https://img.shields.io/badge/Screenshots-60%20embedded-lightgrey?style=flat-square)

*"Security is not a product, but a process."* — Bruce Schneier

</div>

---

> **📁 Image Setup for GitHub:**  
> Create an `images/` folder at the root of your repository alongside this `README.md`.  
> **Batch 1:** `image1.png` – `image20.png` · **Batch 2:** `image21.png` – `image40.png` · **Batch 3:** `image41.png` – `image60.png`
