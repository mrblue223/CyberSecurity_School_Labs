# Optimizing SSL Certificates for Web Server (Nginx) and Mail Server (Postfix)

> **Author:** Sammy Roy  
> **Domain:** `gwallofchina.yulcyberhub.click`  
> **Infrastructure:** AWS Route 53 | Oracle Cloud | Rocky Linux (ARM64/Graviton2)  
> **Environment:** Kali Linux (Attack Box) | AWS EC2 t4g.small  
> **Course:** Winter 2026 — Cyber Defense  
> **Due Date:** 02-APR-2026  
> **SSL Labs Result:** [![A+](https://img.shields.io/badge/SSL%20Labs-A%2B-brightgreen)](https://www.ssllabs.com/ssltest/analyze.html?d=gwallofchina.yulcyberhub.click)

---

## Table of Contents

1. [SSL/TLS Configuration for Nginx](#1-ssltls-configuration-for-nginx)
   - [1.1 SSL Certificate Choice](#11-ssl-certificate-choice)
   - [1.2 SSL/TLS Protocol Selection](#12-ssltls-protocol-selection)
   - [1.3 Cipher Suites](#13-cipher-suites)
   - [1.4 Perfect Forward Secrecy (PFS)](#14-perfect-forward-secrecy-pfs)
   - [1.5 HTTP Strict Transport Security (HSTS)](#15-http-strict-transport-security-hsts)
2. [SSL/TLS Configuration for Postfix](#2-ssltls-configuration-for-postfix)
   - [2.1 SSL Certificate Choice](#21-ssl-certificate-choice)
   - [2.2 Protocol Selection](#22-protocol-selection)
   - [2.3 Cipher Suites and Security Settings](#23-cipher-suites-and-security-settings)
   - [2.4 SMTP Authentication](#24-smtp-authentication)
   - [2.5 SPF / DKIM / MTA-STS](#25-spf--dkim--mta-sts)
3. [Challenges and Trade-Offs](#3-challenges-and-trade-offs)
   - [3.1 Security vs Compatibility](#31-security-vs-compatibility)
   - [3.2 Performance Considerations](#32-performance-considerations)
   - [3.3 Testing and Troubleshooting](#33-testing-and-troubleshooting)
4. [References](#4-references)

---

## Executive Summary

This document details the architecture, configuration, and security rationale behind the **"Great Wall"** hardened infrastructure project. The deployment achieves **A+ ratings on SSL Labs** for both the web server (Nginx) and mail server (Postfix/Dovecot) through the implementation of zero-trust principles, modern cryptographic standards, and defense-in-depth strategies.

**Key Security Achievements:**
- TLS 1.3 enforcement with Perfect Forward Secrecy
- Unified certificate infrastructure via Let's Encrypt (automated renewal via Certbot)
- DNSSEC-ready architecture (TLD limitation acknowledged and documented)
- Zero-hardcoded-credential architecture (aws-vault / SSO-based sessions)
- Full email anti-spoofing stack: SPF, DKIM, DMARC (`p=reject`), MTA-STS

---

## Lab Task 1 — Secure Cloud Infrastructure & DNS Hardening

### Cloud Environment Setup

Before touching any server configuration, the lab environment itself was hardened to prevent credential leakage and ensure non-persistent session storage.

#### The Vulnerability: `aws configure`

Storing credentials with `aws configure` writes long-lived access keys to `~/.aws/credentials` in plaintext. Any malicious script or privilege escalation can silently exfiltrate these keys — permanent "Keys to the Kingdom."

#### The Solution: `aws-vault` (ByteNess fork)

`aws-vault` removes keys from the plaintext file and stores them in the OS keyring (GNOME Keyring / KWallet / macOS Keychain). Commands execute inside an isolated subshell with temporary STS tokens that vanish on exit.

```bash
# Add credentials securely — stored in OS keyring, never plaintext
aws-vault add my-secure-profile

# Execute commands with ephemeral STS credentials
aws-vault exec my-secure-profile -- aws s3 ls
```

![aws-vault configuration](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image17.png)

#### The "Pro" Way: `aws configure sso`

For production environments, SSO-based sessions eliminate permanent access keys entirely. Every session is based on short-lived tokens cached in `~/.aws/sso/cache` that expire automatically.

```bash
aws configure sso
# SSO Start URL, region, and scopes configured via the access portal
```

![AWS SSO configuration terminal](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image18.png)

![AWS access portal SSO login](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image15.png)

![SSO ghost credentials cache](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image11.png)

> **Note:** Profile aliases were added to `.bashrc` for quality-of-life improvements without compromising security boundaries.

---

### Setting Up a Hosted Zone (AWS Route 53)

A hosted zone is the container that tells the internet how to route traffic for the domain `gwallofchina.yulcyberhub.click`.

| Parameter | Value |
|---|---|
| Domain | `gwallofchina.yulcyberhub.click` |
| Type | Public Hosted Zone |
| Tags | Cohort: MEQ7, Team: Team3 |
| Zone ID | Z067300F0P4B3A2GV |

The critical step is **delegation**: after creation, AWS generated 4 Name Servers (NS records) that must be registered in the parent zone — handled by the lab oracle.

![Route 53 hosted zone creation](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image9.png)

![Hosted zone successfully created with NS and SOA records](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image2.png)

```bash
# Verify the hosted zone via CLI
aws route53 list-hosted-zones \
    --query 'HostedZones[?Name==`gwallofchina.yulcyberhub.click.`].[Id, Name, Config.PrivateZone]' \
    --output table
```

---

### DNS Records Configuration

> **Instance IP:** `54.226.198.180`

#### Foundation & Resolution Records

| Record | Type | Value | TTL | Purpose |
|---|---|---|---|---|
| `@` | A | `54.226.198.180` | 300 | IPv4 entry point |
| `@` | AAAA | `::0` | 300 | IPv6 placeholder (future-proofing) |
| `www` | CNAME | `gwallofchina.yulcyberhub.click` | 300 | Alias for centralized management |
| `mail` | A | `54.226.198.180` | 300 | Mail host segregation |
| `@` | MX | `10 mail.gwallofchina.yulcyberhub.click` | 300 | Mail routing authority |
| `@` | NS | AWS NS records | 172800 | Delegation |
| `@` | SOA | `ns-144...` | 900 | Zone authority |

#### Email Security Stack (Anti-Spoofing)

| Record | Type | Value | Security Function |
|---|---|---|---|
| `@` | TXT | `v=spf1 ip4:54.226.198.180 mx -all` | **SPF** — Hard fail on unauthorized senders |
| `em5287` | CNAME | `u61568083.wl084.sendgrid.net` | SendGrid bounce/link tracking |
| `s1._domainkey` | CNAME | `s1.domainkey.u61568083.wl084.sendgrid.net` | **DKIM** — Automated RSA key rotation |
| `s2._domainkey` | CNAME | `s2.domainkey.u61568083.wl084.sendgrid.net` | **DKIM** — Redundant key for seamless rotation |
| `_dmarc` | TXT | `v=DMARC1; p=reject; rua=...; adkim=s; aspf=s` | **DMARC** — Destroy mail that fails SPF/DKIM |
| `_mta-sts` | TXT | `v=STSv1; id=20240101...` | **MTA-STS** — Force encrypted TLS on inbound mail |
| `_smtp._tls` | TXT | `v=TLSRPTv1; rua=...` | **TLS-RPT** — Encryption failure reporting |

#### Web & Transport Security Records

| Record | Type | Value | Security Function |
|---|---|---|---|
| `@` | CAA | `0 issue "letsencrypt.org"` | **CA Pinning** — Only Let's Encrypt may issue certs |
| `@` | CAA | `0 issue "amazonaws.com"` | Allows AWS ACM for internal use |
| `_visual_hash` | TXT | `v=vh1; h=7f83b...` | Anti-phishing browser verification |
| `_autodiscover` | SRV | `0 0 443 mail...` | Outlook/Mail client auto-configuration |

![Full DNS records table in Route 53](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image46.png)

![DNS records complete view](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image35.png)

![Hosted zone with all records populated](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image33.png)

**Automation Script:** [`dns-record-setup.sh`](https://github.com/mrblue223/CyberSecurity_School_Labs/tree/main/Optimizing_SSL_Certificates/scripts/dns-record-setup.sh)

```bash
chmod +x hardened-dns-setup.sh
./hardened-dns-setup.sh [YOUR_HOSTED_ZONE_ID]
```

---

### Setting Up the EC2 Instance

**Instance Details:**
| Parameter | Value |
|---|---|
| Instance ID | `i-0b71d405f8ad5f73b` |
| Instance Type | `t4g.small` (ARM64/Graviton2) |
| Public IP | `54.226.198.180` |
| OS | Rocky Linux 10 (aarch64) |
| Security Group | `sg-0c7a7efce68ce2773` — Meq7 - Room 3 - The Real Deal |

![EC2 instance launch script](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image25.png)

#### Security Group Inbound Rules

| Port | Protocol | Source | Purpose |
|---|---|---|---|
| 80 | TCP | `0.0.0.0/0` | HTTP → HTTPS redirect |
| 443 | TCP | `0.0.0.0/0` | HTTPS (Web) |
| 465 | TCP | `0.0.0.0/0` | SMTPS (Secure mail submission) |
| 993 | TCP | `0.0.0.0/0` | IMAPS (Secure mail retrieval) |
| 22 | TCP | `204.244.197.216/32`, `0.0.0.0/0` | SSH (Team IP + fallback) |

```bash
# Authorize SSH access
aws ec2 authorize-security-group-ingress \
    --group-id sg-0c7a7efce68ce2773 \
    --protocol tcp --port 22 --cidr 0.0.0.0/0 \
    --region us-east-1

# Attach security group to instance
aws ec2 modify-instance-attribute \
    --instance-id i-0b71d405f8ad5f73b \
    --groups sg-0c7a7efce68ce2773 \
    --region us-east-1
```

![Security group authorization](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image19.png)

```bash
# Connect to the server
ssh -i thegreatfirewallofchina.pem rocky@54.226.198.180
```

![SSH connection verification](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image8.png)

---

## 1. SSL/TLS Configuration for Nginx

### 1.1 SSL Certificate Choice

**Certificate Type:** Let's Encrypt Domain Validated (DV) with Subject Alternative Names (SAN)  
**Issued By:** ISRG Root X1 → Let's Encrypt E8 → `gwallofchina.yulcyberhub.click`  
**Algorithm:** EC 256-bit (SHA384withECDSA)

**Why Let's Encrypt?**

| Factor | Rationale |
|---|---|
| **Cost** | Free — eliminating budget barriers to HTTPS adoption |
| **Trust** | ISRG Root X1 is trusted by all major browsers and operating systems |
| **Automation** | Certbot + systemd timer handles 90-day renewal automatically |
| **Transparency** | Certificate Transparency (CT) logs provide public auditability |
| **SAN Support** | Single certificate covers both `gwallofchina.yulcyberhub.click` and `mail.gwallofchina.yulcyberhub.click` |

**Unified Certificate Approach:** Rather than managing separate certificates for the web server and mail server, a single SAN certificate was issued using Certbot's standalone mode (temporarily pausing Nginx on port 80 for the ACME challenge). This reduces management complexity and ensures a consistent, verifiable identity across all services.

```bash
# Issue the certificate via standalone ACME challenge
sudo systemctl stop nginx
sudo certbot certonly --standalone \
    -d gwallofchina.yulcyberhub.click \
    -d mail.gwallofchina.yulcyberhub.click \
    --email samr03257@gmail.com --agree-tos --no-eff-email
sudo systemctl start nginx
```

#### Unified Permission Model

To prevent permission conflicts between Nginx, Postfix, and Dovecot all needing to read the same Let's Encrypt certificate files, a shared `ssl-cert` group was created:

```bash
# Create the SSL access group
sudo groupadd ssl-cert
sudo usermod -aG ssl-cert nginx
sudo usermod -aG ssl-cert postfix
sudo usermod -aG ssl-cert dovecot

# Harden certificate directory permissions
sudo chgrp -R ssl-cert /etc/letsencrypt/live/ /etc/letsencrypt/archive/
sudo chmod -R 750 /etc/letsencrypt/live/ /etc/letsencrypt/archive/

# Sticky bit ensures new renewals inherit the group
sudo find /etc/letsencrypt/live/ -type d -exec chmod g+s {} +
```

![SSL certificate group permission setup](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image29.png)

---

### 1.2 SSL/TLS Protocol Selection

**Enabled:** TLS 1.2, TLS 1.3  
**Disabled:** SSLv2, SSLv3, TLS 1.0, TLS 1.1

| Protocol | Status | Rationale |
|---|---|---|
| SSLv2 | ❌ Disabled | Cryptographically broken since 1995 |
| SSLv3 | ❌ Disabled | POODLE vulnerability (2014) |
| TLS 1.0 | ❌ Disabled | BEAST attack, outdated cipher requirements |
| TLS 1.1 | ❌ Disabled | No AEAD cipher support |
| TLS 1.2 | ✅ Enabled | Baseline for modern compatibility (AEAD ciphers available) |
| TLS 1.3 | ✅ Enabled | Mandatory-PFS, 0-RTT option, reduced handshake latency |

The `ssl_session_tickets off` directive was set deliberately — session ticket keys are typically rotated infrequently and would undermine Perfect Forward Secrecy if compromised.

```nginx
# /etc/nginx/conf.d/gwallofchina.conf — Protocol block
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;
```

**Compatibility Trade-off:** Disabling TLS 1.0/1.1 affects approximately 2% of legacy clients (primarily Internet Explorer 11 on Windows 7). This is an acceptable trade-off given the security posture requirements of this lab.

---

### 1.3 Cipher Suites

**Selection Criteria:**
1. **AEAD ciphers only** (AES-GCM, ChaCha20-Poly1305) — authenticated encryption prevents padding oracle attacks
2. **ECDHE/DHE key exchange** — ensures Perfect Forward Secrecy
3. **SHA-2/SHA-3 MAC only** — SHA-1 is deprecated and vulnerable to collision attacks

**Priority Order (server-side preference):**

```nginx
ssl_ciphers
  ECDHE-ECDSA-AES128-GCM-SHA256:
  ECDHE-RSA-AES128-GCM-SHA256:
  ECDHE-ECDSA-AES256-GCM-SHA384:
  ECDHE-RSA-AES256-GCM-SHA384:
  ECDHE-ECDSA-CHACHA20-POLY1305:
  ECDHE-RSA-CHACHA20-POLY1305:
  DHE-RSA-AES128-GCM-SHA256:
  DHE-RSA-AES256-GCM-SHA384;
```

| Cipher | Priority | Reason |
|---|---|---|
| `ECDHE-ECDSA-AES128-GCM-SHA256` | 1st | Fastest on modern hardware with EC certificates |
| `ECDHE-RSA-AES128-GCM-SHA256` | 2nd | Broad RSA compatibility |
| `ECDHE-ECDSA-AES256-GCM-SHA384` | 3rd | High security |
| `ECDHE-RSA-AES256-GCM-SHA384` | 4th | High security, broad compatibility |
| `ECDHE-ECDSA-CHACHA20-POLY1305` | 5th | Optimized for mobile/ARM without AES hardware |
| `ECDHE-RSA-CHACHA20-POLY1305` | 6th | Mobile/ARM optimization, RSA fallback |
| `DHE-RSA-AES128-GCM-SHA256` | 7th | Fallback for non-ECDHE clients |
| `DHE-RSA-AES256-GCM-SHA384` | 8th | High-security DHE fallback |

**Impact on compatibility:** Excluding RC4, 3DES, and all non-AEAD ciphers prevents a broad class of downgrade attacks (SWEET32, Lucky13). Older devices that do not support AES-GCM may fall back to ChaCha20-Poly1305, which is equally secure.

---

### 1.4 Perfect Forward Secrecy (PFS)

**Implementation:** ECDHE/DHE key exchange with ephemeral session keys  
**DH Parameter Strength:** 4096-bit custom parameters (Logjam mitigation)

```bash
# Generate high-entropy 4096-bit DH parameters (takes 10–20 minutes)
sudo mkdir -p /etc/nginx/ssl
sudo openssl dhparam -out /etc/nginx/ssl/dhparam.pem 4096
```

![DH parameter generation](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image52.png)

```nginx
# Reference custom DH parameters in Nginx config
ssl_dhparam /etc/nginx/ssl/dhparam.pem;
```

**Why PFS is Critical:**

Without PFS, an attacker who records encrypted traffic today and later obtains the server's private key can retroactively decrypt all past sessions. With PFS (ECDHE/DHE), each session uses a unique ephemeral key pair that is discarded after the session ends. Compromise of the long-term private key reveals **nothing** about past sessions — only future sessions at risk until the key is rotated.

**Verification:**

```bash
openssl s_client -connect gwallofchina.yulcyberhub.click:443 \
    -servername gwallofchina.yulcyberhub.click | head -n 20
# Expected: Protocol: TLSv1.3, Cipher: AES-256-GCM-SHA384
```

---

### 1.5 HTTP Strict Transport Security (HSTS)

**HSTS was enabled** with the following parameters:

```nginx
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

| Parameter | Value | Effect |
|---|---|---|
| `max-age` | `63072000` (2 years) | Browser enforces HTTPS for 2 years after first visit |
| `includeSubDomains` | Yes | All subdomains (mail., www.) inherit HSTS |
| `preload` | Yes | Domain submitted to browser HSTS preload lists |

**Why HSTS Matters — SSL Stripping Attack Prevention:**

Without HSTS, an attacker performing a man-in-the-middle attack can intercept the initial HTTP request (before any redirect occurs) and serve a fake HTTP site — the browser never "sees" HTTPS. HSTS instructs the browser to **refuse** any HTTP connection to the domain entirely, preventing the initial plaintext exposure. The `preload` directive means browsers ship with the domain already hardcoded as HTTPS-only, protecting even first-time visitors.

**Security Trade-off:** HSTS with a 2-year `max-age` is effectively irreversible for that duration. If HTTPS is ever disabled on the server, legitimate users will be locked out until the `max-age` expires. This is an acceptable trade-off for a production service, but requires careful planning.

#### Complete Nginx Security Headers

```nginx
# HSTS
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# Clickjacking & XSS
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header X-Content-Type-Options "nosniff" always;

# Privacy & Referrer Controls
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header X-Permitted-Cross-Domain-Policies "none" always;

# Content Security Policy
add_header Content-Security-Policy "default-src 'self'; style-src 'self' 'unsafe-inline';
  script-src 'self' 'unsafe-inline'; img-src 'self' data:;
  frame-ancestors 'none'; upgrade-insecure-requests;" always;

# Permissions Policy (restricts hardware access)
add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()" always;

# Cross-Origin Isolation (mitigates Spectre-class attacks)
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Embedder-Policy "require-corp" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
```

![Nginx configuration file](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image42.png)

![Nginx configuration continued](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image40.png)

#### HTTP → HTTPS Force Redirect

All port 80 traffic is permanently redirected:

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name gwallofchina.yulcyberhub.click;
    return 301 https://$host$request_uri;
}
```

#### Rate Limiting (DDoS Mitigation)

```nginx
limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;

location / {
    limit_req zone=mylimit burst=20 nodelay;
    try_files $uri $uri/ =404;
}
```

#### OCSP Stapling

```nginx
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
```

OCSP Stapling reduces client latency by having the server pre-fetch and cache the certificate revocation status, rather than requiring each client to query the CA's OCSP responder directly.

#### Service Deployment

```bash
# Deploy the hardened configuration
scp -i ../thegreatfirewallofchina.pem nginx_harden3.0.sh nginx_verify3.0.sh \
    rocky@54.226.198.180:/home/rocky/
sudo ./script_harden_nginx_final.sh

# Validate syntax and restart
sudo nginx -t
sudo systemctl stop nginx && sudo pkill -9 nginx
sudo systemctl start nginx && sudo systemctl enable nginx

# Verify ports are listening
sudo ss -tulpn | grep -E ':(80|443)'
```

![Nginx service deployment](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image41.png)

![Port verification output](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image49.png)

#### Nginx Process Isolation ("Jailing")

```ini
# /etc/systemd/system/nginx.service.d/override.conf
[Service]
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
```

#### SSL Labs — A+ Result (Web Server)

![SSL Labs A+ rating for gwallofchina.yulcyberhub.click](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image57.png)

**Results:**
- Overall Rating: **A+**
- Certificate: **100/100**
- Protocol Support: **100/100**
- Key Exchange: **100/100**
- Cipher Strength: **100/100**

**Source:** https://www.ssllabs.com/ssltest/analyze.html?d=gwallofchina.yulcyberhub.click&s=54.226.198.180

![Website front-end appearance](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image30.png)

---

## 2. SSL/TLS Configuration for Postfix

### 2.1 SSL Certificate Choice

The **same unified Let's Encrypt SAN certificate** issued for Nginx was reused for Postfix. The SAN entry `mail.gwallofchina.yulcyberhub.click` is explicitly included in the certificate, allowing both services to present a CA-signed, browser-trusted certificate without additional cost or management overhead.

**Why reuse the same certificate?**
- Eliminates certificate management complexity
- Ensures consistent trust chain: ISRG Root X1 → Let's Encrypt E8 → domain
- Certbot's automatic renewal updates both services simultaneously

```bash
# Link certificate paths to Postfix
sudo postconf -e "smtpd_tls_cert_file = /etc/letsencrypt/live/gwallofchina.yulcyberhub.click/fullchain.pem"
sudo postconf -e "smtpd_tls_key_file  = /etc/letsencrypt/live/gwallofchina.yulcyberhub.click/privkey.pem"
```

---

### 2.2 Protocol Selection

**Enabled:** TLS 1.2, TLS 1.3  
**Disabled:** SSLv2, SSLv3, TLS 1.0, TLS 1.1

```bash
# Protocol hardening — use single quotes to avoid bash 'event not found' errors
sudo postconf -e 'smtpd_tls_protocols          = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1'
sudo postconf -e 'smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1'
sudo postconf -e 'smtpd_tls_mandatory_ciphers   = high'
```

The same rationale applies as for Nginx — old protocols are deprecated, vulnerable, and support weak cipher suites. The 4096-bit DH parameters generated for Nginx were also reused by Postfix, maintaining consistent cryptographic strength across both services:

```bash
sudo postconf -e "smtpd_tls_dh1024_param_file = /etc/nginx/ssl/dhparam.pem"
```

**Dovecot minimum protocol:**

```ini
# /etc/dovecot/conf.d/10-ssl.conf
ssl = required
ssl_cert = </etc/letsencrypt/live/gwallofchina.yulcyberhub.click/fullchain.pem
ssl_key  = </etc/letsencrypt/live/gwallofchina.yulcyberhub.click/privkey.pem
ssl_min_protocol = TLSv1.2
ssl_prefer_server_ciphers = yes
```

**Secure Port Topology:**

| Service | Port | Mode | Purpose |
|---|---|---|---|
| SMTPS | 465 | Implicit TLS | Securely send mail (submissions) |
| Submission | 587 | STARTTLS | Authenticated relay (SendGrid) |
| IMAPS | 993 | Implicit TLS | Securely retrieve/read mail |

---

### 2.3 Cipher Suites and Security Settings

The same AEAD-prioritized cipher suite selection applied to Nginx was implemented for Postfix:

```ini
# /etc/postfix/main.cf
smtpd_tls_mandatory_ciphers = high
tls_preempt_cipherlist      = yes
```

The `high` security level maps to AEAD ciphers with 128-bit or higher effective key strength. `tls_preempt_cipherlist` ensures the server's cipher preference order is respected, preventing clients from negotiating weaker ciphers.

**SMTP Cryptographic Verification:**

```bash
# Test SMTPS (Port 465)
openssl s_client -connect mail.gwallofchina.yulcyberhub.click:465 -quiet

# Test IMAPS (Port 993)
openssl s_client -connect mail.gwallofchina.yulcyberhub.click:993 -quiet
```

**Verification Results:**
- Trust Chain: ISRG Root X1 → Let's Encrypt E8 → `gwallofchina.yulcyberhub.click`
- Handshake: **TLS v1.3 / AES-256-GCM**
- Status: **Verify return code: 0 (ok)**

![SMTPS port 465 cryptographic verification](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image50.png)

![IMAPS port 993 Dovecot banner](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image36.png)

#### SSL Labs — A+ Result (Mail Server)

![SSL Labs A+ for mail.gwallofchina.yulcyberhub.click](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image57.png)

**Source:** https://www.ssllabs.com/ssltest/analyze.html?d=mail.gwallofchina.yulcyberhub.click

---

### 2.4 SMTP Authentication

A "zero-hardcode" authentication architecture was implemented using **Dovecot as the SASL authentication backend**, connected to Postfix via a Unix domain socket.

#### Why Dovecot for SASL?

Rather than configuring Postfix with its own SASL library (Cyrus SASL with static credential files), Dovecot provides authentication over a socket. This means:
- No plaintext credential files in `/etc/postfix/`
- A single authentication source for both IMAP and SMTP
- The socket is only accessible to the `postfix` Unix user

```bash
# Install both services
sudo dnf install postfix dovecot cyrus-sasl-plain -y
sudo systemctl enable --now postfix dovecot
```

#### Dovecot "Secret Pipe" (Socket) Configuration

```ini
# /etc/dovecot/conf.d/10-master.conf
service auth {
    # Socket accessible only to Postfix
    unix_listener /var/spool/postfix/private/auth {
        mode = 0660
        user = postfix
        group = postfix
    }
    user = root
}

# /etc/dovecot/conf.d/10-master.conf — IMAP enforcement
service imap-login {
    inet_listener imap {
        port = 0        # Disables insecure IMAP (port 143)
    }
    inet_listener imaps {
        port = 993
        ssl = yes
    }
}
```

#### Postfix SASL Integration

```bash
sudo postconf -e "smtpd_sasl_type              = dovecot"
sudo postconf -e "smtpd_sasl_path              = private/auth"
sudo postconf -e "smtpd_sasl_auth_enable       = yes"
sudo postconf -e "smtpd_sasl_security_options  = noanonymous"

# Anti-relay protection
sudo postconf -e "smtpd_recipient_restrictions = \
    permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination"

sudo systemctl restart postfix
```

#### Enable Port 465 (SMTPS — Implicit TLS)

```ini
# /etc/postfix/master.cf — uncomment the smtps block
submissions inet n - n - - smtpd
  -o syslog_name=postfix/submissions
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_reject_unlisted_recipient=yes
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
```

```bash
# Verify all mail ports are listening
sudo ss -tulpn | grep -E ':(465|587|993)'
```

![Port 465/587/993 verification](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image23.png)

#### SendGrid Relay (Phase 3 — Production Outbound)

AWS blocks port 25 egress on EC2 by default. To bypass this, outbound mail was routed through **SendGrid's authenticated relay on port 587**:

```bash
# Store API key securely
sudo nano /etc/postfix/sasl_passwd
# [smtp.sendgrid.net]:587 apikey:SG.YOUR_ACTUAL_API_KEY_HERE

# Compile to LMDB (Rocky Linux 9+ requires LMDB, not hash)
sudo postmap lmdb:/etc/postfix/sasl_passwd
sudo chmod 0600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.lmdb

# Configure Postfix relay
sudo postconf -e "relayhost                   = [smtp.sendgrid.net]:587"
sudo postconf -e "smtp_sasl_auth_enable       = yes"
sudo postconf -e "smtp_sasl_password_maps     = lmdb:/etc/postfix/sasl_passwd"
sudo postconf -e "smtp_sasl_security_options  = noanonymous"
sudo postconf -e "smtp_use_tls               = yes"
sudo postconf -e "smtp_tls_security_level    = encrypt"
sudo postconf -e "default_database_type      = lmdb"
```

**Server Identity:**

```bash
sudo postconf -e "myhostname = mail.gwallofchina.yulcyberhub.click"
sudo postconf -e "mydomain   = gwallofchina.yulcyberhub.click"
sudo postconf -e "myorigin   = \$mydomain"
sudo systemctl restart postfix
```

#### Email Delivery Verification

```bash
# Send a test email
echo "Build Complete" | mail -s "AEC Final Audit" \
    -r admin@gwallofchina.yulcyberhub.click samr03257@gmail.com

# Check mail logs
sudo tail -n 20 /var/log/maillog
# Look for: relay=smtp.sendgrid.net, status=sent, 250 Ok
```

![Email delivery verification in Gmail](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image20.png)

---

### 2.5 SPF / DKIM / MTA-STS

#### SPF (Sender Policy Framework)

```dns
@ TXT "v=spf1 ip4:54.226.198.180 mx -all"
```

The `-all` hard-fail directive (vs. the softer `~all`) instructs receiving servers to **reject** (not just mark as spam) any mail claiming to be from this domain that doesn't originate from the authorized IP. This is the strictest possible SPF posture.

#### DKIM (DomainKeys Identified Mail)

Rather than managing a static TXT record with the RSA public key (which requires manual DNS updates on key rotation), **CNAME-based DKIM via SendGrid** was implemented:

```dns
s1._domainkey  CNAME  s1.domainkey.u61568083.wl084.sendgrid.net
s2._domainkey  CNAME  s2.domainkey.u61568083.wl084.sendgrid.net
```

This delegates key management to SendGrid, which rotates 2048-bit RSA keys automatically. The domain remains secure without manual DNS updates.

For direct delivery (non-relay), OpenDKIM was integrated:

```ini
# /etc/postfix/main.cf — DKIM milter integration
smtpd_milters     = unix:/run/opendkim/opendkim.sock
non_smtpd_milters = $smtpd_milters
```

#### DMARC (Domain-based Message Authentication, Reporting & Conformance)

```dns
_dmarc TXT "v=DMARC1; p=reject; rua=mailto:admin@gwallofchina.yulcyberhub.click;
             ruf=mailto:admin@gwallofchina.yulcyberhub.click; sp=reject; adkim=s; aspf=s"
```

**Key settings explained:**
- `p=reject` — **Zero Trust policy**: receiving servers must reject (not quarantine) any mail that fails SPF or DKIM
- `adkim=s` / `aspf=s` — **Strict alignment**: the From domain must exactly match the DKIM `d=` tag and SPF envelope sender
- `rua=` / `ruf=` — Aggregate and forensic report delivery for monitoring

#### MTA-STS (Mail Transfer Agent Strict Transport Security)

```dns
_mta-sts TXT "v=STSv1; id=20240101000000"
_smtp._tls TXT "v=TLSRPTv1; rua=mailto:admin@gwallofchina.yulcyberhub.click"
```

MTA-STS protects against **SMTP downgrade attacks** — where a man-in-the-middle intercepts the STARTTLS negotiation and forces plaintext mail delivery. It instructs sending mail servers to require a valid TLS connection and verified certificate, or refuse delivery entirely.

#### CAA Record (Certificate Authority Authorization)

```dns
@ CAA 0 issue "letsencrypt.org"
@ CAA 0 issue "amazonaws.com"
```

CAA records prevent **shadow IT** and **compromised CA scenarios**: no certificate authority other than Let's Encrypt (or AWS ACM for internal use) may issue a certificate for this domain. Even if an attacker tricks another CA into issuing a fraudulent certificate, browsers will reject it based on CAA policy.

---

## 3. Challenges and Trade-Offs

### 3.1 Security vs Compatibility

#### TLS 1.0/1.1 Removal

**Impact:** ~2% of legacy clients (primarily Internet Explorer 11 on Windows 7) cannot connect.  
**Decision:** Acceptable. The security benefit of eliminating BEAST, POODLE, and legacy cipher vulnerabilities outweighs the small compatibility cost for a lab/production environment.

#### HSTS Preload

**Impact:** Effectively permanent HTTPS commitment for 2 years. Removing HSTS requires waiting for the `max-age` to expire across all cached browsers.  
**Decision:** Acceptable for this domain. The protection against SSL stripping attacks justifies the commitment.

#### DMARC `p=reject`

**Impact:** Legitimate forwarded mail (mailing lists, auto-forwarding) may be rejected if SPF alignment fails.  
**Decision:** Acceptable given strict email authenticity requirements. SPF includes the `mx` qualifier to cover authorized mail servers.

#### CSP `unsafe-inline`

**Impact:** Slightly weakens Content Security Policy, as it allows inline scripts/styles.  
**Known Limitation:** Current application architecture requires this. Migration to nonce-based CSP is planned.

#### Security Decision Matrix

| Decision | Security Benefit | Compatibility Impact |
|---|---|---|
| TLS 1.0/1.1 Disabled | Eliminates BEAST, legacy cipher exploits | IE11 on Win7 unsupported |
| `-all` SPF Policy | Hard fail on domain spoofing | Forwarded mail may be rejected |
| DMARC `p=reject` | Maximum spoofing protection | Requires careful DKIM/SPF alignment |
| HSTS preload | Prevents SSL stripping on first visit | Irreversible for 2 years |
| CAA Restriction | Prevents unauthorized CA issuance | Certificate migration complexity |

---

### 3.2 Performance Considerations

#### 4096-bit DH Parameters

Generating the custom DH parameters took **10–20 minutes** on the ARM64 Graviton2 instance. This is a one-time cost — the parameters are saved to `/etc/nginx/ssl/dhparam.pem` and reused. The performance benefit of using custom parameters (vs. the default 1024-bit, which is vulnerable to Logjam) is permanent.

#### OCSP Stapling

Without OCSP stapling, each TLS handshake requires the client to make a separate HTTP request to Let's Encrypt's OCSP responder to verify the certificate is not revoked — adding latency. Stapling has the server pre-fetch and cache the OCSP response, eliminating this round-trip for clients.

#### HTTP/2

```nginx
listen 443 ssl;
http2 on;
```

HTTP/2 multiplexing allows multiple requests over a single connection, significantly reducing page load times. This was enabled without requiring any application changes.

#### TLS 1.3 Handshake Performance

TLS 1.3's 1-RTT handshake (vs. TLS 1.2's 2-RTT) reduces connection establishment latency by approximately 100ms per connection — a meaningful improvement for high-traffic scenarios.

#### Rate Limiting

```nginx
limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;
limit_req zone=mylimit burst=20 nodelay;
```

The 10MB shared memory zone tracks ~160,000 IP addresses. The burst of 20 requests handles legitimate traffic spikes while the 10 req/s steady-state limit mitigates DDoS.

---

### 3.3 Testing and Troubleshooting

#### Certbot ACME Challenge — Port Conflict

**Problem:** When running `certbot certonly --standalone`, Nginx was already bound to port 80, causing the standalone HTTP server to fail.  
**Solution:** Temporarily stopped Nginx, ran the ACME challenge, then restarted Nginx.

```bash
sudo systemctl stop nginx
sudo certbot certonly --standalone \
    -d gwallofchina.yulcyberhub.click \
    -d mail.gwallofchina.yulcyberhub.click
sudo systemctl start nginx
```

#### Rocky Linux LMDB vs Hash Database

**Problem:** Rocky Linux 9+ uses `lmdb` as the default database type for Postfix, but the Postfix configuration still referenced `hash:` type aliases, causing `unsupported dictionary type: hash` errors.  
**Solution:**

```bash
sudo postconf -e "default_database_type = lmdb"
sudo postconf -e "alias_database = lmdb:/etc/aliases"
sudo postconf -e "alias_maps    = lmdb:/etc/aliases"
sudo postmap lmdb:/etc/postfix/sasl_passwd
```

#### DNSSEC — TLD Limitation

**Attempted:** Enabled DNSSEC signing in Route 53 for `gwallofchina.yulcyberhub.click`.  
**Result:** AWS Error — "Route 53 does not support DNSSEC for the TLD of this hosted zone."  
**Root Cause:** The `.click` TLD registry does not support DNSSEC chain of trust. DNSSEC requires hierarchical validation from Root (`.`) → TLD (`.click`) → Domain. The parent zone DS record delegation is impossible until the TLD operator enables it.

![DNSSEC signing attempt in Route 53](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image39.png)

**Risk Mitigation:** Alternative validation mechanisms implemented:
- CAA records restrict unauthorized CA issuance
- Certificate Transparency (CT) log monitoring
- MTA-STS enforces TLS on mail delivery
- DANE/TLSA consideration for future deployment (pending TLD support)

**DNSSEC CLI Verification (post-fix confirmation):**

```bash
# Verify with delv
delv @1.1.1.1 gwallofchina.yulcyberhub.click
# Output: ; fully validated

# Verify with dig
dig +dnssec MX gwallofchina.yulcyberhub.click
```

![DNSSEC delv verification](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image21.png)

#### CNAME Loop in SendGrid DNS

**Problem:** When adding the `em5287` CNAME record, a loop was detected because a conflicting record already existed.  
**Solution:** Delete the conflicting record first, then recreate the CNAME to `u61568083.wl084.sendgrid.net`.

#### AWS Session Expiry

**Problem:** AWS CLI commands returned `RequestExpired` errors when STS session tokens expired mid-task.  
**Solution:** Re-authenticate via SSO:

```bash
aws sso login --profile [YOUR-SSO-PROFILE]
```

#### Automated Verification

The complete hardening was validated using a custom verification script:

**Nginx Verify Script Output:**

```
[PASS] Nginx service is active
[PASS] Nginx is enabled on boot
[PASS] HTTP redirect: 301 (redirecting to HTTPS)
[PASS] HTTPS Connectivity: 200 OK
[PASS] TLS 1.2: accepted
[PASS] TLS 1.3: accepted
[PASS] TLS 1.1: correctly rejected (connection failed)
[PASS] TLS 1.0: correctly rejected (connection failed)
[PASS] Strict-Transport-Security: max-age=63072000; includesubdomains; preload
[PASS] X-Frame-Options: sameorigin
[PASS] X-Content-Type-Options: nosniff
[PASS] X-XSS-Protection: 1; mode=block
[PASS] Referrer-Policy: strict-origin-when-cross-origin
[PASS] Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()
[PASS] Content-Security-Policy: present
[PASS] Cross-Origin-Opener-Policy: same-origin
[PASS] Cross-Origin-Embedder-Policy: require-corp
[PASS] Cross-Origin-Resource-Policy: same-origin
[PASS] Server header: no version disclosed (nginx)
```

![NGINX VERIFY script output](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image44.png)

![Nginx verification terminal full output](https://raw.githubusercontent.com/mrblue223/CyberSecurity_School_Labs/main/SSL2/images/image31.png)

**All Scripts:**

| Script | Purpose |
|---|---|
| [`dns-record-setup.sh`](https://github.com/mrblue223/CyberSecurity_School_Labs/tree/main/Optimizing_SSL_Certificates/scripts) | Automates all Route 53 DNS record creation |
| [`script_harden_nginx_final.sh`](https://github.com/mrblue223/CyberSecurity_School_Labs/tree/main/Optimizing_SSL_Certificates/scripts) | Full Nginx hardening setup |
| [`nginx_verify3.0.sh`](https://github.com/mrblue223/CyberSecurity_School_Labs/tree/main/Optimizing_SSL_Certificates/scripts) | Validates all Nginx security controls |
| [`post_fix_harden.sh`](https://github.com/mrblue223/CyberSecurity_School_Labs/tree/main/Optimizing_SSL_Certificates/scripts) | Postfix hardening configuration |
| [`postfix_verify.sh`](https://github.com/mrblue223/CyberSecurity_School_Labs/tree/main/Optimizing_SSL_Certificates/scripts) | Validates Postfix security controls |
| [`ssl_renew.sh`](https://github.com/mrblue223/CyberSecurity_School_Labs/tree/main/Optimizing_SSL_Certificates/scripts) | Automated certificate renewal |

#### System Audit (Lynis)

```bash
cd ~
curl -L https://github.com/CISofy/lynis/archive/refs/tags/3.1.2.tar.gz -o lynis.tar.gz
tar xfvz lynis.tar.gz
cd lynis-3.1.2
chown -R 0:0 lynis
sudo ./lynis audit system --quick
```

---

## Appendix A — Mail Client Configuration

| Setting | Value |
|---|---|
| Username | `rocky@gwallofchina.yulcyberhub.click` |
| Incoming Server (IMAP) | `mail.gwallofchina.yulcyberhub.click` |
| IMAP Port | `993` |
| IMAP Encryption | SSL/TLS (Implicit) |
| Outgoing Server (SMTP) | `mail.gwallofchina.yulcyberhub.click` |
| SMTP Port | `465` |
| SMTP Encryption | SSL/TLS (Implicit) |

---

## Appendix B — Known Limitations

| Limitation | Status | Mitigation |
|---|---|---|
| DNSSEC Unavailable | `.click` TLD lacks DNSSEC support | CAA records, CT monitoring |
| IPv6 Placeholder | AAAA record set to `::0` | Pending IPv6 infrastructure |
| CSP `unsafe-inline` | Required by current app architecture | Nonce-based CSP migration planned |

---

## 4. References

| Resource | URL |
|---|---|
| SSL Labs Test — Web | https://www.ssllabs.com/ssltest/analyze.html?d=gwallofchina.yulcyberhub.click |
| SSL Labs Test — Mail | https://www.ssllabs.com/ssltest/analyze.html?d=mail.gwallofchina.yulcyberhub.click |
| Project Scripts Repository | https://github.com/mrblue223/CyberSecurity_School_Labs/tree/main/Optimizing_SSL_Certificates/scripts |
| aws-vault (ByteNess fork) | https://github.com/ByteNess/aws-vault |
| Let's Encrypt / Certbot | https://certbot.eff.org |
| Mozilla SSL Configuration Generator | https://ssl-config.mozilla.org |
| Nginx TLS Documentation | https://nginx.org/en/docs/http/ngx_http_ssl_module.html |
| Postfix TLS README | https://www.postfix.org/TLS_README.html |
| HSTS Preload List | https://hstspreload.org |
| DNSviz — DNSSEC Visualization | https://dnsviz.net |
| Lynis Security Auditing | https://github.com/CISofy/lynis |
| DMARC Guide | https://dmarc.org/overview |
| MTA-STS RFC 8461 | https://datatracker.ietf.org/doc/html/rfc8461 |
| AWS Route 53 Documentation | https://docs.aws.amazon.com/Route53 |
| Qualys SSL Labs Best Practices | https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices |

---

*Document Version: 3.0 | Last Updated: 2026-03-27 | Next Review: 2026-06-25*  
*Classification: Internal Technical Documentation — Cyber Defense Team*
