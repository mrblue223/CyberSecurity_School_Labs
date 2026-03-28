# 🏯 The Great Wall — Hardened SSL/TLS Infrastructure

> **Project:** Secure Cloud Infrastructure & DNS Hardening  
> **Course:** Winter 2026 Cyber Defense — Assignment 1  
> **Author:** Sammy Roy  
> **Domain:** `gwallofchina.yulcyberhub.click`  
> **Infrastructure:** AWS Route 53 | Oracle Cloud | Rocky Linux (ARM64/Graviton2)  
> **Final SSL Rating:** A+ (Qualys SSL Labs — Web & Mail)

![SSL Labs A+ Badge](screenshots/ssllabs_aplus_badge.png)

---

## 📋 Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Overview](#2-architecture-overview)
3. [Cloud Security — Credential Management](#3-cloud-security--credential-management)
   - [The Threat: `aws configure`](#31-the-threat-aws-configure)
   - [Solution A: `aws-vault`](#32-solution-a-aws-vault)
   - [Solution B: SSO Non-Persistent Sessions](#33-solution-b-sso-non-persistent-sessions)
4. [AWS Infrastructure Setup](#4-aws-infrastructure-setup)
   - [EC2 Instance & Security Groups](#41-ec2-instance--security-groups)
5. [DNS Architecture & Hardening](#5-dns-architecture--hardening)
   - [Hosted Zone Creation](#51-hosted-zone-creation)
   - [DNS Record Architecture](#52-dns-record-architecture)
   - [DNSSEC — The Oracle Intervention](#53-dnssec--the-oracle-intervention)
6. [Web Server Hardening (Nginx)](#6-web-server-hardening-nginx)
   - [SSL Certificate Choice](#61-ssl-certificate-choice)
   - [Protocol Selection](#62-protocol-selection)
   - [Cipher Suite Configuration](#63-cipher-suite-configuration)
   - [Perfect Forward Secrecy (PFS)](#64-perfect-forward-secrecy-pfs)
   - [HTTP Strict Transport Security (HSTS)](#65-http-strict-transport-security-hsts)
   - [Security Headers (Zero Trust)](#66-security-headers-zero-trust)
   - [Rate Limiting](#67-rate-limiting)
   - [OCSP Stapling](#68-ocsp-stapling)
   - [Full Nginx Config](#69-full-nginx-configuration)
7. [Mail Infrastructure Hardening (Postfix + Dovecot + SendGrid)](#7-mail-infrastructure-hardening-postfix--dovecot--sendgrid)
   - [SendGrid Relay Setup](#71-sendgrid-relay-setup)
   - [Postfix Configuration](#72-postfix-configuration)
   - [Dovecot (IMAP) Configuration](#73-dovecot-imap-configuration)
   - [Certificate Permissions via `setfacl`](#74-certificate-permissions-via-setfacl)
   - [Email Security Stack — SPF/DKIM/DMARC](#75-email-security-stack--spfdkimdmarc)
8. [Security vs. Compatibility Analysis](#8-security-vs-compatibility-analysis)
9. [Security Validation & Testing](#9-security-validation--testing)
10. [Operational Procedures](#10-operational-procedures)
11. [Known Limitations & Mitigations](#11-known-limitations--mitigations)
12. [Automation Scripts](#12-automation-scripts)
13. [References](#13-references)

---

## 1. Executive Summary

This project documents the design, implementation, and hardening of the **"Great Wall"** — a defense-in-depth cloud infrastructure built on AWS and Oracle Cloud. The objective was to achieve a **Qualys SSL Labs A+ rating** for both the web server (Nginx) and mail server (Postfix/Dovecot), while implementing zero-trust credential management and a fully hardened DNS record architecture.

### Key Security Achievements

| Achievement | Status |
|---|---|
| SSL Labs A+ — Web (`gwallofchina.yulcyberhub.click`) | ✅ |
| SSL Labs A+ — Mail (`mail.gwallofchina.yulcyberhub.click`) | ✅ |
| TLS 1.3 enforcement with Perfect Forward Secrecy | ✅ |
| Unified Let's Encrypt SAN certificate (web + mail) | ✅ |
| DNSSEC signing (with Chain of Trust established) | ✅ |
| Zero-hardcoded-credential architecture (`aws-vault` / SSO) | ✅ |
| Full email authentication stack (SPF, DKIM, DMARC `p=reject`) | ✅ |
| HSTS with 2-year `max-age`, `includeSubDomains`, and `preload` | ✅ |

---

## 2. Architecture Overview

```
Internet
    │
    ▼
┌──────────────────────────────────────────┐
│            AWS Route 53 (DNS)            │
│      gwallofchina.yulcyberhub.click      │
│  A, AAAA, MX, CAA, SPF, DKIM, DMARC,   │
│       MTA-STS, CNAME, NS, SOA           │
└──────────────────────┬───────────────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  AWS EC2 t4g.small│
              │  Rocky Linux     │
              │  54.226.198.180  │
              │  (ARM64/Graviton2│
              └────────┬────────┘
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
    ┌──────────┐ ┌──────────┐ ┌──────────┐
    │  Nginx   │ │  Postfix │ │ Dovecot  │
    │ Port 443 │ │ Port 465 │ │ Port 993 │
    │  (HTTPS) │ │  (SMTPS) │ │  (IMAPS) │
    └──────────┘ └──────────┘ └──────────┘
          │            │
          └────────────┘
                │
        Let's Encrypt (ISRG Root X1)
        Unified SAN Certificate
```

**Security Group Inbound Rules (sg-0c7a7efce68ce2773):**

| Port | Protocol | Source | Purpose |
|------|----------|--------|---------|
| 80 | TCP | 0.0.0.0/0 | HTTP → HTTPS redirect only |
| 443 | TCP | 0.0.0.0/0 | HTTPS web traffic |
| 465 | TCP | 0.0.0.0/0 | SMTPS (implicit TLS) |
| 587 | TCP | 0.0.0.0/0 | SMTP Submission |
| 993 | TCP | 0.0.0.0/0 | IMAPS (implicit TLS) |
| 22 | TCP | 204.244.197.216/32 | SSH (team IP) |

---

## 3. Cloud Security — Credential Management

### 3.1 The Threat: `aws configure`

The default AWS credential method stores long-lived access keys in a plaintext file at `~/.aws/credentials`. This is a critical vulnerability — a malicious script, compromised process, or privilege escalation attack can silently read this file. Credentials are persistent, so a leak today means a breach that lasts until manually rotated.

### 3.2 Solution A: `aws-vault`

`aws-vault` eliminates plaintext credentials by encrypting them in the OS keyring (GNOME Keyring / KWallet / macOS Keychain). We used the actively maintained fork: [`ByteNess/aws-vault`](https://github.com/ByteNess/aws-vault).

```bash
# Add credentials (encrypts into OS keyring — plaintext file is never created)
aws-vault add meq7-secure-profile

# Execute commands via a temporary STS subshell
aws-vault exec meq7-secure-profile -- aws s3 ls
```

After running with `aws-vault exec`, we can confirm identity without exposing any permanent credentials:

![aws sts get-caller-identity output (redacted)](screenshots/awsvault_exec_output.png)

**Security properties:**

| Property | Benefit |
|---|---|
| OS-level keyring encryption | Keys are never on disk in plaintext |
| STS temporary token injection | Credentials scoped to a single subshell |
| Automatic memory clearing | No credential residue after process exit |
| No `~/.aws/credentials` file | Eliminates the #1 static credential attack vector |

### 3.3 Solution B: SSO Non-Persistent Sessions

For maximum security, `aws configure sso` is the gold standard. No permanent access keys exist at any point.

```bash
aws configure sso
# SSO Start URL: https://[REDACTED].awsapps.com/start/#
# SSO Region: us-east-1
# Output format: json
```

![AWS Access Portal showing account and Access keys button](screenshots/aws_access_portal_sso.png)

The SSO wizard walks through selecting the account and role. All sensitive values were redacted in screenshots:

![aws configure sso terminal wizard](screenshots/aws_configure_sso_terminal.png)

**Re-authentication when the token expires:**

```bash
aws sso login --profile Lab
```

![aws sso login terminal — Success](screenshots/aws_sso_login_terminal.png)

Temporary tokens are cached in `~/.aws/sso/cache` and expire automatically. No permanent secret key ever touches disk.

---

## 4. AWS Infrastructure Setup

### 4.1 EC2 Instance & Security Groups

**Instance details:**

| Parameter | Value |
|---|---|
| Instance ID | `i-0b71d405f8ad5f73b` |
| Instance Type | `t4g.small` (ARM64 / Graviton2) |
| OS | Rocky Linux 10 (aarch64) |
| Public IP | `54.226.198.180` |
| Security Group | `sg-0c7a7efce68ce2773` (Meq7 - Room 3 - The Real Deal) |

**Verify the security group via CLI (table format):**

```bash
aws ec2 describe-security-groups \
  --group-ids sg-0c7a7efce68ce2773 \
  --region us-east-1 \
  --output table
```

![Security group CLI table output showing all inbound rules](screenshots/security_group_table_output.png)

**JSON verification of all inbound rules:**

```bash
aws ec2 describe-security-groups \
  --group-ids sg-0c7a7efce68ce2773 \
  --region us-east-1 \
  --query 'SecurityGroups[0].IpPermissions' \
  --output json
```

![Security group JSON output](screenshots/security_group_json_output.png)

**Connect to the instance:**

```bash
ssh -i thegreatfirewallofchina.pem rocky@54.226.198.180
```

---

## 5. DNS Architecture & Hardening

### 5.1 Hosted Zone Creation

A **public hosted zone** was created in AWS Route 53 as the authoritative DNS container for the domain.

![Create hosted zone form — domain name, public type, tags MEQ7/Team3](screenshots/hosted_zone_creation_console.png)

After creation, AWS generates the initial NS and SOA records only. The zone must be delegated before it becomes live:

![Hosted zone successfully created — NS and SOA records visible](screenshots/hosted_zone_ns_records.png)

```bash
# Verify hosted zone exists and is public
aws route53 list-hosted-zones \
  --query 'HostedZones[?Name==`gwallofchina.yulcyberhub.click.`].[Id, Name, Config.PrivateZone]' \
  --output table
```

![aws route53 list-hosted-zones CLI output](screenshots/hosted_zone_cli_verify.png)

### 5.2 DNS Record Architecture

The DNS record set was designed in three logical layers:

#### Layer 1 — Foundation & Identity

| Record | Type | Value | TTL | Purpose |
|--------|------|-------|-----|---------|
| `@` | A | `54.226.198.180` | 300 | IPv4 entry point |
| `@` | AAAA | `::0` | 300 | IPv6 placeholder |
| `www` | CNAME | `gwallofchina.yulcyberhub.click` | 300 | Canonical alias |
| `mail` | A | `54.226.198.180` | 300 | Dedicated mail host |
| `@` | MX | `10 mail.gwallofchina.yulcyberhub.click` | 300 | Mail routing |

#### Layer 2 — Email Anti-Spoofing Stack

| Record | Type | Value | Security Function |
|--------|------|-------|-------------------|
| `@` | TXT | `v=spf1 ip4:54.226.198.180 mx -all` | SPF hard-fail |
| `s1._domainkey` | CNAME | `s1.domainkey.u61568083.wl084.sendgrid.net` | DKIM Key 1 |
| `s2._domainkey` | CNAME | `s2.domainkey.u61568083.wl084.sendgrid.net` | DKIM Key 2 |
| `_dmarc` | TXT | `v=DMARC1; p=reject; rua=mailto:admin@...` | DMARC enforcer |

#### Layer 3 — Web & Transport Security

| Record | Type | Value | Security Function |
|--------|------|-------|-------------------|
| `@` | CAA | `0 issue "letsencrypt.org"` | CA Pinning |
| `_mta-sts` | TXT | `v=STSv1; id=20240101...` | MTA-STS |
| `_smtp._tls` | TXT | `v=TLSRPTv1; rua=mailto:admin@...` | TLS-RPT |

**All 18 DNS records as seen in Route 53:**

![Route 53 showing all 18 DNS records](screenshots/all_dns_records_route53.png)

### 5.3 DNSSEC — The Oracle Intervention

DNSSEC adds cryptographic signatures to DNS responses, preventing cache poisoning. It requires a **Chain of Trust** from root (`.`) → TLD (`.click`) → our domain.

**Step 1 — Enable DNSSEC signing in Route 53:**

Route 53 shows the DNSSEC signing tab with the option to enable it:

![Route 53 DNSSEC signing tab — Enable DNSSEC signing button highlighted](screenshots/dnssec_enable_button.png)

**Step 2 — Create the Key Signing Key (KSK):**

The KSK name `GWALLkey` was provided, and Route 53 was directed to create a customer-managed CMK in AWS KMS:

![Enable DNSSEC signing — KSK creation form with GWALLkey name](screenshots/dnssec_ksk_creation_form.png)

During the process, the existing CMK ARN was selected to link the key:

![DNSSEC enabling with CMK ARN selected](screenshots/dnssec_enabling_cmk.png)

**Step 3 — The KSK details and DS record:**

Once created, the GWALLkey KSK page shows the DS record values needed to establish the chain of trust in the parent zone:

![GWALLkey KSK details — DS record, digest, signing algorithm, KMS CMK](screenshots/dnssec_ksk_kms_details.png)

The KMS key was tagged with the required Oracle tracking metadata:

![KMS key tags — Cohort: MEQ7, Team: Room3](screenshots/kms_tags_meq7.png)

**Step 4 — The Oracle Intervention (The Critical Chain-of-Trust Step):**

The DS record shown in the GWALLkey page had to be added to the **parent zone** (`yulcyberhub.click`) by the instructor (the Oracle). This step cannot be performed by the student. After the instructor added the DS record, the full DNSSEC chain of trust was established.

> **Note on the KMS permissions error:** During the process, an intermediate error occurred when Route 53 could not access the KMS key due to missing IAM permissions (`DescribeKey`, `GetPublicKey`, `Sign`). This was resolved by correcting the key policy before re-attempting.

![DNSSEC KMS permissions error message](screenshots/dnssec_kms_error.png)

**Step 5 — Verification:**

```bash
# DNSSEC-aware lookup — confirms full validation
delv @1.1.1.1 gwallofchina.yulcyberhub.click
# ; fully validated

# Verify DNSSEC signatures on MX record
dig +dnssec MX gwallofchina.yulcyberhub.click
```

![dig +dnssec MX output showing RRSIG record](screenshots/dnssec_dig_mx.png)

**DNSViz visualization of the chain of trust:**

![DNSViz lower zone — gwallofchina.yulcyberhub.click DNSKEY records](screenshots/dnsviz_lower_zone.png)

![DNSViz upper chain — DS delegation from yulcyberhub.click](screenshots/dnsviz_upper_chain.png)

![DNSViz full secure chain — Secure (6) RRset status](screenshots/dnsviz_full_secure.png)

---

## 6. Web Server Hardening (Nginx)

### 6.1 SSL Certificate Choice

**Type:** Let's Encrypt Domain Validated (DV) with Subject Alternative Name (SAN)

A unified SAN certificate covers both `gwallofchina.yulcyberhub.click` and `mail.gwallofchina.yulcyberhub.click`, signed by ISRG Root X1 via Let's Encrypt E8.

**Certificate issuance (with port conflict resolution):**

```bash
# Temporarily stop Nginx to free port 80 for the ACME challenge
sudo systemctl stop nginx

sudo certbot certonly --standalone \
  -d gwallofchina.yulcyberhub.click \
  -d mail.gwallofchina.yulcyberhub.click \
  --email samr03257@gmail.com \
  --agree-tos --no-eff-email

sudo systemctl start nginx
```

### 6.2 Protocol Selection

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
```

| Protocol | Status | Reason |
|---|---|---|
| SSLv2 | Disabled | Cryptographically broken (1995) |
| SSLv3 | Disabled | POODLE vulnerability (2014) |
| TLS 1.0 | Disabled | BEAST attack, legacy ciphers |
| TLS 1.1 | Disabled | No AEAD support; RFC 8996 deprecated |
| TLS 1.2 | ✅ Enabled | Baseline modern compatibility |
| TLS 1.3 | ✅ Enabled | Built-in PFS, reduced handshake latency |

### 6.3 Cipher Suite Configuration

Only AEAD ciphers are permitted:

```nginx
ssl_ciphers
ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

ssl_prefer_server_ciphers on;
```

### 6.4 Perfect Forward Secrecy (PFS)

All selected ciphers use ECDHE or DHE key exchange, providing PFS natively. Custom 4096-bit DH parameters were generated to mitigate the Logjam attack:

```bash
sudo openssl dhparam -out /etc/nginx/ssl/dhparam.pem 4096
```

```nginx
ssl_dhparam /etc/nginx/ssl/dhparam.pem;
ssl_session_tickets off;  # Disabling tickets enforces fresh key negotiation per session
```

### 6.5 HTTP Strict Transport Security (HSTS)

```nginx
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

HSTS instructs browsers to always use HTTPS, defeating SSL stripping attacks. The `preload` directive signals intent to submit to the browser preload list.

**Verifying the 301 redirect:**

```bash
curl -I http://gwallofchina.yulcyberhub.click
```

![curl -I showing HTTP/1.1 301 Moved Permanently to HTTPS](screenshots/curl_301_redirect_kali.png)

### 6.6 Security Headers (Zero Trust)

```nginx
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
```

### 6.7 Rate Limiting

```nginx
limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;

location / {
    limit_req zone=mylimit burst=20 nodelay;
    try_files $uri $uri/ =404;
}
```

### 6.8 OCSP Stapling

```nginx
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
```

### 6.9 Full Nginx Configuration

```nginx
# /etc/nginx/conf.d/gwallofchina.conf

limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;

server {
    listen 80;
    listen [::]:80;
    server_name gwallofchina.yulcyberhub.click;
    return 301 https://$host$request_uri;
}

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

**Nginx systemd sandboxing (jailing the process):**

```bash
sudo systemctl edit nginx.service
```

![Nginx systemd sandboxing config — PrivateDevices, ProtectSystem=strict, NoNewPrivileges](screenshots/nginx_systemd_sandbox.png)

**Service verification:**

```bash
sudo nginx -t
sudo systemctl stop nginx && sudo pkill -9 nginx && sudo systemctl start nginx
sudo systemctl enable nginx
sudo ss -tulpn | grep -E ':(80|443)'
```

**Automated hardening verification — all checks passing:**

![Nginx Verify script v1.0.0 — all PASS including TLS, headers, CSP, cross-origin policies](screenshots/nginx_verify_script_pass.png)

**The live website served over A+ TLS:**

![Live website — NGINX castle page with SSL/TLS A+ Rated badge](screenshots/website_live_screenshot.png)

**SSL Labs result for the web server:**

![SSL Labs A+ rating for gwallofchina.yulcyberhub.click — server 54.226.198.180](screenshots/ssllabs_aplus_badge.png)

---

## 7. Mail Infrastructure Hardening (Postfix + Dovecot + SendGrid)

### 7.1 SendGrid Relay Setup

AWS blocks outbound port 25 by default. Postfix relays through SendGrid via authenticated port 587. SendGrid requires DNS records to authenticate the domain:

![SendGrid DNS records to add — em5287 CNAME, s1/s2 DKIM CNAMEs, DMARC TXT](screenshots/sendgrid_dns_records.png)

### 7.2 Postfix Configuration

**Install:**

```bash
sudo dnf install postfix cyrus-sasl-plain mailx -y
sudo systemctl enable --now postfix
```

![Postfix and Dovecot dnf install output](screenshots/postfix_dovecot_install.png)

**Configure relay, TLS, and LMDB:**

```bash
sudo postconf -e "myhostname = mail.gwallofchina.yulcyberhub.click"
sudo postconf -e "mydomain = gwallofchina.yulcyberhub.click"
sudo postconf -e "relayhost = [smtp.sendgrid.net]:587"
sudo postconf -e "smtp_sasl_auth_enable = yes"
sudo postconf -e "smtp_sasl_password_maps = lmdb:/etc/postfix/sasl_passwd"
sudo postconf -e "smtp_sasl_security_options = noanonymous"
sudo postconf -e "smtp_use_tls = yes"
sudo postconf -e "smtp_tls_security_level = encrypt"
sudo postconf -e 'smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1'
sudo postconf -e 'smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1'
sudo postconf -e "smtpd_tls_cert_file = /etc/letsencrypt/live/gwallofchina.yulcyberhub.click/fullchain.pem"
sudo postconf -e "smtpd_tls_key_file = /etc/letsencrypt/live/gwallofchina.yulcyberhub.click/privkey.pem"
sudo postconf -e "smtpd_tls_dh1024_param_file = /etc/nginx/ssl/dhparam.pem"
sudo postconf -e "default_database_type = lmdb"
sudo postconf -e "alias_database = lmdb:/etc/aliases"
sudo postconf -e "alias_maps = lmdb:/etc/aliases"
```

**Point Postfix to the Dovecot authentication socket:**

```bash
sudo postconf -e "smtpd_sasl_type = dovecot"
sudo postconf -e "smtpd_sasl_path = private/auth"
sudo postconf -e "smtpd_sasl_auth_enable = yes"
sudo systemctl restart postfix
```

![postconf Dovecot socket commands executing](screenshots/postfix_dovecot_socket_cmds.png)

**Verify the server hostname:**

```bash
postconf myhostname
```

![postconf myhostname = mail.gwallofchina.yulcyberhub.click](screenshots/postfix_hostname_verify.png)

### 7.3 Dovecot (IMAP) Configuration

**Install:**

```bash
sudo dnf install dovecot -y
sudo systemctl enable --now dovecot
```

**SSL configuration (`/etc/dovecot/conf.d/10-ssl.conf`):**

```
ssl = required
ssl_cert = </etc/letsencrypt/live/gwallofchina.yulcyberhub.click/fullchain.pem
ssl_key = </etc/letsencrypt/live/gwallofchina.yulcyberhub.click/privkey.pem
ssl_min_protocol = TLSv1.2
ssl_prefer_server_ciphers = yes
```

![Dovecot ssl_cert and ssl_key config lines](screenshots/dovecot_cert_config.png)

![Dovecot ssl_min_protocol = TLSv1.2 config line](screenshots/dovecot_ssl_min_protocol.png)

**Disable insecure IMAP (143), enforce IMAPS (993) in `/etc/dovecot/conf.d/10-master.conf`:**

![Dovecot service imap-login block — port 0 for IMAP, port 993 ssl=yes for IMAPS](screenshots/dovecot_imap_port_config.png)

**Verify the Dovecot auth socket exists and is owned by postfix:**

```bash
sudo ls -l /var/spool/postfix/private/auth
```

![ls -l showing postfix socket ownership](screenshots/dovecot_socket_verify.png)

### 7.4 Certificate Permissions via `setfacl`

Let's Encrypt directories are locked to `root`. Rather than opening them world-readable with `chmod`, we grant only the required service users access:

```bash
sudo setfacl -R -m u:postfix:rx /etc/letsencrypt/live/
sudo setfacl -R -m u:postfix:rx /etc/letsencrypt/archive/
sudo setfacl -R -m u:dovecot:rx /etc/letsencrypt/live/
sudo setfacl -R -m u:dovecot:rx /etc/letsencrypt/archive/
```

| Method | Effect |
|---|---|
| `chmod 644 privkey.pem` | Readable by **every user** on the system — security risk |
| `setfacl -m u:postfix:rx` | Readable **only by postfix** — all others retain zero access |

### 7.5 Email Security Stack — SPF/DKIM/DMARC

**SPF** (`-all` hard fail): Any server not listed is instructed to reject, not just mark as spam.

**DKIM**: Migrated from a static TXT key to SendGrid's CNAME-based rotation — keys rotate automatically without DNS updates.

**DMARC** (`p=reject`): All unauthenticated mail is destroyed at the receiving gateway. Aggregate reports are sent to `admin@gwallofchina.yulcyberhub.click`.

**Verify mail delivery end-to-end:**

```bash
echo "Build Complete" | mail -s "AEC Final Audit" \
  -r admin@gwallofchina.yulcyberhub.click \
  samr03257@gmail.com
```

![Local mail test showing 3 messages delivered to root](screenshots/maillog_sent_250ok.png)

![Gmail inbox showing "AEC Final Audit" received from admin@gwallofchina.yulcyberhub.click](screenshots/gmail_received_email.png)

**Port verification — 465, 587, 993 all listening:**

```bash
sudo ss -tulpn | grep -E ':(465|587|993)'
```

![ss -tulpn output showing Postfix on 465/587 and Dovecot on 993](screenshots/port_verification_ss.png)

**Mail client configuration:**

| Setting | Value |
|---|---|
| Incoming Server (IMAP) | `mail.gwallofchina.yulcyberhub.click` |
| IMAP Port | `993` |
| IMAP Encryption | SSL/TLS (Implicit) |
| Outgoing Server (SMTP) | `mail.gwallofchina.yulcyberhub.click` |
| SMTP Port | `465` |
| SMTP Encryption | SSL/TLS (Implicit) |

**SSL Labs A+ for the mail server:**

![SSL Labs A+ for mail.gwallofchina.yulcyberhub.click — TLS 1.3, HSTS, CAA all green](screenshots/ssllabs_mail_aplus.png)

---

## 8. Security vs. Compatibility Analysis

### 8.1 TLS Protocol Choices

| Decision | Security Benefit | Compatibility Impact |
|---|---|---|
| Disable TLS 1.0 and 1.1 | Eliminates BEAST, POODLE-variant, legacy cipher vulnerabilities | Breaks IE 11 on Windows 7 (~2% of global traffic) |
| Enforce TLS 1.2 minimum | Strong AEAD ciphers, modern MACs | No impact on any browser released after 2014 |
| Enable TLS 1.3 | Built-in PFS, 1-RTT handshake | Fully supported in all modern browsers |

**Verdict:** The ~2% compatibility loss is acceptable for a security posture project. In a production e-commerce context, one would monitor legacy browser usage metrics before removing TLS 1.1.

### 8.2 SPF Hard Fail (`-all`) vs. Soft Fail (`~all`)

| Setting | Security | Risk |
|---|---|---|
| `-all` (hard fail) | Receiving servers **reject** unauthorized mail | Legitimate forwarded mail from mailing lists may be rejected |
| `~all` (soft fail) | Unauthorized mail marked as spam, not rejected | Spoofed emails reach spam folder — not destroyed |

**Decision:** `-all` was chosen because this is a controlled infrastructure with no mailing list forwarding. The higher security posture outweighs the forwarding compatibility risk.

### 8.3 HSTS Preload

| Benefit | Risk |
|---|---|
| Browser enforces HTTPS before any request — defeats SSL stripping completely | Commitment is irreversible for 2 years via the preload list |
| Subdomain protection via `includeSubDomains` | If HTTPS is ever broken, users are locked out |

**Decision:** Preload was enabled because the infrastructure is dedicated to HTTPS permanently.

### 8.4 `p=reject` DMARC Policy

Before setting `p=reject`, the configuration was staged: `p=none` → `p=quarantine` → `p=reject`. DMARC aggregate reports confirmed all legitimate mail was passing SPF and DKIM before the strictest policy was applied.

### 8.5 DNSSEC — The TLD Constraint

An initial attempt to enable DNSSEC was blocked because the `.click` TLD did not have the chain of trust established at the parent level. This is a fundamental architectural constraint — no server-side change can work around a missing parent DS record. The Oracle (instructor) resolved this. Risk mitigations applied while awaiting resolution: CAA records, Certificate Transparency monitoring, and MTA-STS.

### 8.6 CSP `unsafe-inline`

The CSP includes `'unsafe-inline'` for style/script sources due to the current static HTML architecture. Migration to nonce-based CSP is documented as a future improvement.

---

## 9. Security Validation & Testing

### Web Server

```bash
# 1. HTTP to HTTPS redirect
curl -I http://gwallofchina.yulcyberhub.click
```

![curl -I 301 redirect output](screenshots/curl_301_redirect.png)

```bash
# 2. Full TLS handshake and certificate chain
openssl s_client -connect gwallofchina.yulcyberhub.click:443 \
  -servername gwallofchina.yulcyberhub.click | head -n 20
```

![openssl s_client port 443 — ISRG Root X1 chain, TLSv1.3, AES-256-GCM](screenshots/openssl_handshake_web.png)

```bash
# 3. Automated hardening verification
sudo ./nginx_verify3.0.sh
```

![Nginx verify script — all PASS](screenshots/nginx_verify_script_pass.png)

### Mail Server

```bash
# SMTPS (Port 465)
openssl s_client -connect mail.gwallofchina.yulcyberhub.click:465 -quiet
# Expected: 220 mail.gwallofchina.yulcyberhub.click ESMTP Postfix

# IMAPS (Port 993)
openssl s_client -connect mail.gwallofchina.yulcyberhub.click:993 -quiet
# Expected: * OK [...] Dovecot ready.
```

![openssl s_client port 993 — ISRG Root X1 chain, Dovecot ready banner](screenshots/openssl_imaps_993.png)

**Cryptographic validation results:**

| Check | Result |
|---|---|
| Trust Chain | ISRG Root X1 → Let's Encrypt E8 → `gwallofchina.yulcyberhub.click` |
| Handshake Protocol | TLS v1.3 |
| Cipher | AES-256-GCM |
| PFS | ✅ (ECDHE) |
| Verify Return Code | `0 (ok)` |

### Lynis System Audit

```bash
cd ~/lynis-3.1.2
sudo ./lynis audit system --quick
```

The cache directory was prepared before running the audit:

![Lynis mkdir/chown/chmod nginx cache directory](screenshots/lynis_audit_results.png)

### SSL Labs Final Scores

**Web server — gwallofchina.yulcyberhub.click:**

![SSL Labs A+ — 54.226.198.180, Certificate 100, Protocol Support 100, Key Exchange 100, Cipher Strength 100](screenshots/ssllabs_aplus_badge.png)

**Mail server — mail.gwallofchina.yulcyberhub.click:**

![SSL Labs A+ mail — TLS 1.3, HSTS long duration, CAA policy found](screenshots/ssllabs_mail_aplus_full.png)

---

## 10. Operational Procedures

### Certificate Renewal

```bash
sudo systemctl stop nginx
sudo certbot certonly --standalone \
  -d gwallofchina.yulcyberhub.click \
  -d mail.gwallofchina.yulcyberhub.click
sudo systemctl start nginx
```

### Security Monitoring

| Log | Location | What to Watch |
|---|---|---|
| Nginx Access | `/var/log/nginx/gwallofchina.access.log` | Rate limit triggers, 4xx/5xx spikes |
| Nginx Error | `/var/log/nginx/gwallofchina.error.log` | TLS handshake failures |
| Postfix | `/var/log/maillog` | `status=sent`, relay failures, auth errors |
| Dovecot | `/var/log/dovecot.log` | IMAP auth failures, TLS errors |
| DMARC Reports | `admin@gwallofchina.yulcyberhub.click` | Aggregate failure reports (daily) |

---

## 11. Known Limitations & Mitigations

| Limitation | Root Cause | Mitigation |
|---|---|---|
| DNSSEC initially failed | `.click` TLD lacked parent DS record | Oracle added DS record; verified with `delv` |
| IPv6 AAAA is placeholder (`::0`) | No IPv6 assigned to EC2 instance | Record exists for future-proofing |
| CSP `unsafe-inline` present | Current static HTML uses inline styles | Future: nonce-based CSP migration |
| SSH port 22 open to `0.0.0.0/0` | Lab accessibility requirement | Production: restrict to bastion host only |
| SendGrid relay required | AWS blocks outbound port 25 | Outbound mail via SendGrid with full SPF/DKIM |

---

## 12. Automation Scripts

All scripts are available under [`scripts/`](scripts/).

| Script | Purpose |
|---|---|
| `dns-record-setup.sh` | Automated DNS record creation via AWS CLI |
| `launch-instance.sh` | EC2 instance provisioning |
| `script_harden_nginx_final.sh` | Full Nginx hardening deployment |
| `nginx_verify3.0.sh` | Automated Nginx security verification |
| `post_fix_harden.sh` | Postfix hardening configuration |
| `postfix_verify.sh` | Automated Postfix security verification |
| `ssl_renew.sh` | Certificate renewal automation |

```bash
# Run DNS setup
chmod +x scripts/dns-record-setup.sh
./scripts/dns-record-setup.sh Z0433076DMIP84BGAZGN

# Deploy and verify Nginx (run on the Rocky Linux server)
scp -i thegreatfirewallofchina.pem \
  scripts/script_harden_nginx_final.sh \
  scripts/nginx_verify3.0.sh \
  rocky@54.226.198.180:/home/rocky/

sudo ./script_harden_nginx_final.sh
sudo ./nginx_verify3.0.sh
```

> ⚠️ **Before running:** Update `DOMAIN`, `STAGING_IP`, and `STAGING_IPV6` variables at the top of each script to match your environment.

---

## 13. References

| Resource | URL |
|---|---|
| Qualys SSL Labs | https://www.ssllabs.com/ssltest/ |
| Mozilla SSL Configuration Generator | https://ssl-config.mozilla.org/ |
| Let's Encrypt Documentation | https://letsencrypt.org/docs/ |
| AWS Route 53 DNSSEC | https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-configuring-dnssec.html |
| HSTS Preload List | https://hstspreload.org/ |
| DNSViz — DNSSEC Visualizer | https://dnsviz.net/ |
| SendGrid Domain Authentication | https://docs.sendgrid.com/ui/account-and-settings/how-to-set-up-domain-authentication |
| RFC 8996 — Deprecating TLS 1.0/1.1 | https://datatracker.ietf.org/doc/html/rfc8996 |
| NIST SP 800-52 Rev 2 — TLS Guidelines | https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final |
| Postfix TLS Support | https://www.postfix.org/TLS_README.html |
| Lynis Security Auditing Tool | https://github.com/CISofy/lynis |
| aws-vault (ByteNess fork) | https://github.com/ByteNess/aws-vault |
| Project Scripts Repository | https://github.com/mrblue223/CyberSecurity_School_Labs/tree/main/Optimizing_SSL_Certificates/scripts |

---

<div align="center">

**The Great Wall — Hardened SSL/TLS Infrastructure**  
*Winter 2026 Cyber Defense — Assignment 1*  
**Sammy Roy** | `gwallofchina.yulcyberhub.click`

![Live website — NGINX castle serving A+ TLS](screenshots/website_live_screenshot.png)

</div>
