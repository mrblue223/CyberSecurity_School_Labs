# 🔐 Optimizing SSL/TLS Certificates for Nginx & Postfix

> **Author:** Sammy Roy · **Cohort:** MEQ7 · **Team:** Team 3  
> **Domain:** `gwallofchina.yulcyberhub.click` · **Due:** April 2, 2026

![SSL Labs](https://img.shields.io/badge/SSL%20Labs-A%2B-brightgreen?style=for-the-badge&logo=letsencrypt)
![TLS](https://img.shields.io/badge/TLS-1.3-blue?style=for-the-badge&logo=openssl)
![Let's Encrypt](https://img.shields.io/badge/Certificate-Let's%20Encrypt-orange?style=for-the-badge&logo=letsencrypt)
![AWS](https://img.shields.io/badge/DNS-AWS%20Route%2053-FF9900?style=for-the-badge&logo=amazonaws)
![Rocky Linux](https://img.shields.io/badge/OS-Rocky%20Linux-10B981?style=for-the-badge&logo=rockylinux)
![DNSSEC](https://img.shields.io/badge/DNSSEC-Enabled-purple?style=for-the-badge)
![DMARC](https://img.shields.io/badge/DMARC-p%3Dreject-red?style=for-the-badge)
![License](https://img.shields.io/badge/Classification-Internal%20Technical%20Doc-lightgrey?style=for-the-badge)

---

## 📋 Table of Contents

- [Executive Summary](#executive-summary)
- [1. SSL/TLS Configuration for Nginx](#1-ssltls-configuration-for-nginx)
  - [1a. SSL Certificate Choice](#1a-ssl-certificate-choice)
  - [1b. SSL/TLS Protocol Selection](#1b-ssltls-protocol-selection)
  - [1c. Cipher Suites](#1c-cipher-suites)
  - [1d. Perfect Forward Secrecy (PFS)](#1d-perfect-forward-secrecy-pfs)
  - [1e. HTTP Strict Transport Security (HSTS)](#1e-http-strict-transport-security-hsts)
- [2. SSL/TLS Configuration for Postfix](#2-ssltls-configuration-for-postfix)
  - [2a. SSL Certificate Choice](#2a-ssl-certificate-choice)
  - [2b. Protocol Selection](#2b-protocol-selection)
  - [2c. Cipher Suites and Security Settings](#2c-cipher-suites-and-security-settings)
  - [2d. SMTP Authentication](#2d-smtp-authentication)
  - [2e. SPF / DKIM / MTA-STS](#2e-spf--dkim--mta-sts)
- [3. Challenges and Trade-Offs](#3-challenges-and-trade-offs)
  - [3a. Security vs. Compatibility](#3a-security-vs-compatibility)
  - [3b. Performance Considerations](#3b-performance-considerations)
  - [3c. Testing and Troubleshooting](#3c-testing-and-troubleshooting)
- [4. References](#4-references)

---

## Executive Summary

This document is a comprehensive technical reflection on the **"Great Wall"** hardened SSL/TLS infrastructure project, deployed on AWS (Route 53 + EC2) running Rocky Linux with Nginx as the web server and Postfix/Dovecot as the mail stack. The project culminated in achieving **A+ ratings on SSL Labs for both web and mail services**, implementing zero-trust principles, modern cryptography, and defense-in-depth strategies.

| Component | Rating | Key Achievement |
|---|---|---|
| Web Server (Nginx) | ![A+](https://img.shields.io/badge/-A%2B-brightgreen) | TLS 1.3 · HSTS Preload · OCSP Stapling |
| Mail Server (Postfix) | ![A+](https://img.shields.io/badge/-A%2B-brightgreen) | SMTPS/IMAPS · SPF/DKIM/DMARC · MTA-STS |
| Certificate Score | 100/100 | Let's Encrypt SAN cert (ISRG Root X1) |
| Protocol Score | 100/100 | TLS 1.2 + 1.3 only; all legacy disabled |
| Key Exchange Score | 100/100 | ECDHE/DHE with 4096-bit DH params |
| Cipher Strength Score | 100/100 | AEAD-only suites (AES-GCM, ChaCha20) |

---

## 1. SSL/TLS Configuration for Nginx

### 1a. SSL Certificate Choice

**Certificate Type Used:** Let's Encrypt Domain Validated (DV) with Subject Alternative Names (SAN)

The project used a **free, automatically-renewable DV certificate** issued by Let's Encrypt, covering both the apex domain (`gwallofchina.yulcyberhub.click`) and the mail subdomain (`mail.gwallofchina.yulcyberhub.click`) under a single unified SAN certificate.

**Why Let's Encrypt?**

| Consideration | Rationale |
|---|---|
| **Cost** | Free — eliminates commercial CA licensing fees |
| **Trust** | Backed by ISRG Root X1, trusted by all major browsers and mail clients |
| **Automation** | Certbot + systemd timer handles 90-day renewal automatically |
| **Transparency** | All certificates logged in Certificate Transparency (CT) logs, enabling monitoring for unauthorized issuance |
| **Unified Identity** | A single SAN certificate shared across Nginx, Postfix, and Dovecot eliminates identity fragmentation |

**Certificate chain verified as:**

```
ISRG Root X1 → Let's Encrypt E8 → gwallofchina.yulcyberhub.click
```

**Why not self-signed?** Self-signed certificates generate browser trust warnings, fail SMTP peer verification, and provide no meaningful identity assurance. They were explicitly excluded from consideration.

**Why not a wildcard?** A SAN cert covering only the required hostnames follows the principle of least privilege — a wildcard (`*.yulcyberhub.click`) would over-extend the trust surface unnecessarily.

**CAA Record Enforcement:**

Certificate issuance was locked to Let's Encrypt at the DNS level via CAA records, preventing rogue CA issuance:

```dns
@ CAA 0 issue "letsencrypt.org"
@ CAA 0 issue "amazonaws.com"   ; AWS ACM for internal infra only
```

This mitigates "shadow IT" and compromised CA scenarios.

---

### 1b. SSL/TLS Protocol Selection

**Protocols Configured:**

| Protocol | Status | Reason |
|---|---|---|
| SSLv2 | ❌ Disabled | Cryptographic design broken since 1995; no viable use case |
| SSLv3 | ❌ Disabled | Vulnerable to **POODLE** (CVE-2014-3566); CBC padding oracle |
| TLS 1.0 | ❌ Disabled | **BEAST** attack (CVE-2011-3389); relies on RC4 and weak CBC |
| TLS 1.1 | ❌ Disabled | No modern AEAD cipher support; deprecated by RFC 8996 (2021) |
| TLS 1.2 | ✅ Enabled | Industry baseline; required for ECDHE + AEAD compatibility |
| TLS 1.3 | ✅ Enabled | Mandatory handshake encryption, 0-RTT capable, PFS built-in |

**Nginx configuration:**

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
```

**Why disable TLS 1.0 and 1.1?**

These protocols rely on the CBC (Cipher Block Chaining) mode of operation, which is inherently vulnerable to padding oracle attacks such as BEAST and POODLE when combined with the cipher suites of that era. RFC 8996 formally deprecated both in March 2021. Modern browsers have removed support; the estimated impact on legitimate traffic is approximately **≤2%** (primarily Internet Explorer 11 on Windows 7 — an unsupported OS). This represents an acceptable risk given the security posture requirements of this lab.

**Verification:**

```bash
# TLS 1.3 accepted
openssl s_client -connect gwallofchina.yulcyberhub.click:443 -tls1_3

# TLS 1.1 correctly rejected
openssl s_client -connect gwallofchina.yulcyberhub.click:443 -tls1_1
# Expected: handshake failure
```

---

### 1c. Cipher Suites

**Configuration:**

```nginx
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
```

**Selection Criteria:**

1. **AEAD-only** — All suites use Authenticated Encryption with Associated Data (AES-GCM or ChaCha20-Poly1305). This eliminates MAC-then-Encrypt vulnerabilities like Lucky13 and POODLE.
2. **ECDHE/DHE key exchange only** — Ensures ephemeral Diffie-Hellman, providing Perfect Forward Secrecy on every session.
3. **SHA-2 MAC only** — SHA-1 is cryptographically deprecated (SHAttered collision, 2017).

**Priority Order and Rationale:**

| Priority | Cipher Suite | Reason |
|---|---|---|
| 1 | `ECDHE-ECDSA-AES128-GCM-SHA256` | Best performance on modern x86/ARM hardware with AES-NI |
| 2 | `ECDHE-RSA-AES128-GCM-SHA256` | Same security, RSA cert compatibility (broader client base) |
| 3 | `ECDHE-ECDSA-AES256-GCM-SHA384` | Higher key strength for sensitive sessions |
| 4 | `ECDHE-RSA-AES256-GCM-SHA384` | High security + RSA compatibility |
| 5 | `ECDHE-ECDSA-CHACHA20-POLY1305` | Optimal for mobile/ARM clients **without** AES hardware acceleration |
| 6 | `ECDHE-RSA-CHACHA20-POLY1305` | Same, RSA variant |
| 7 | `DHE-RSA-AES128-GCM-SHA256` | PFS fallback for non-ECDHE clients |
| 8 | `DHE-RSA-AES256-GCM-SHA384` | High-security PFS fallback |

> **Note on ChaCha20-Poly1305:** This suite was explicitly included for mobile and low-power ARM clients (including the t4g.small Graviton2 instance itself) where AES hardware acceleration is absent. ChaCha20 is a software-optimized stream cipher that outperforms AES-CBC in software implementations.

**Compatibility Impact:** Removing RC4, DES, 3DES, and all non-AEAD ciphers disables support for very old TLS stacks (IE6/XP, ancient Java runtimes). This is an intentional, documented trade-off.

---

### 1d. Perfect Forward Secrecy (PFS)

**What is PFS?**

Perfect Forward Secrecy ensures that the compromise of a server's long-term private key does **not** expose past session traffic. Each TLS session generates an independent, ephemeral key pair that is discarded after the session ends. An attacker who records encrypted traffic and later obtains the server's private key cannot retroactively decrypt those sessions.

**Implementation:**

PFS is achieved through ephemeral Diffie-Hellman key exchange — either **ECDHE** (Elliptic Curve) or **DHE** (classic). All cipher suites selected use one of these two mechanisms, making PFS mandatory on every connection.

**Diffie-Hellman Parameter Hardening (Logjam Mitigation):**

The default 1024-bit DH parameters shipped with most distributions are vulnerable to the **Logjam attack** (CVE-2015-4000), which allows a MitM to downgrade DHE key exchange to export-grade 512-bit parameters. This was mitigated by generating custom 4096-bit DH parameters:

```bash
sudo openssl dhparam -out /etc/nginx/ssl/dhparam.pem 4096
```

```nginx
ssl_dhparam /etc/nginx/ssl/dhparam.pem;
```

> ⏱️ **Note:** 4096-bit DH parameter generation takes 10–20 minutes on typical cloud hardware. This is a one-time operation.

**Session Ticket Hardening:**

```nginx
ssl_session_tickets off;   # Disable TLS session ticket rotation vulnerabilities
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
```

TLS session tickets, if not rotated with the same frequency as session keys, can undermine PFS by allowing session resumption from a compromised ticket key. Disabling them entirely eliminates this risk; session IDs via `ssl_session_cache` provide performance benefits without the forward secrecy trade-off.

**Verification:**

```bash
openssl s_client -connect gwallofchina.yulcyberhub.click:443 \
  -servername gwallofchina.yulcyberhub.click | head -20
# Look for: Protocol: TLSv1.3, Cipher: TLS_AES_256_GCM_SHA384
# Confirms ephemeral key exchange is active
```

---

### 1e. HTTP Strict Transport Security (HSTS)

**Yes, HSTS was enabled with preload.**

```nginx
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

**What HSTS Does:**

HSTS instructs browsers to **only ever connect to this domain over HTTPS**, for a duration specified by `max-age` (63,072,000 seconds = **2 years**). After the first HTTPS visit, any subsequent HTTP request is upgraded by the browser itself — the request never leaves the client unencrypted.

**Why is this Critical? — SSL Stripping Attack:**

Without HSTS, an attacker performing a MitM (e.g., on a public Wi-Fi network) can intercept the initial HTTP request before the 301 redirect occurs, serving a downgraded HTTP session to the victim while proxying HTTPS to the server. The user sees "padlock missing" but may proceed. HSTS closes this window by making the HTTP-to-HTTPS upgrade happen locally in the browser, never traversing the network.

**Parameter Analysis:**

| Parameter | Value | Justification |
|---|---|---|
| `max-age` | 63072000 (2 years) | Meets the minimum requirement for HSTS preload list submission |
| `includeSubDomains` | Yes | Enforces HTTPS across `mail.*`, `www.*`, and any future subdomains |
| `preload` | Yes | Signals eligibility for browser vendor preload lists (Chrome, Firefox, Edge) — protection from **the very first visit** |

**Security Note:** HSTS preload is **irreversible for the duration of `max-age`**. Once submitted to browser preload lists, rolling back to HTTP is a multi-year operational commitment. This was an intentional, documented architectural decision.

**Full Security Headers Deployed:**

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
```

**OCSP Stapling:**

```nginx
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
```

OCSP Stapling caches the certificate revocation status from the CA and serves it directly with the TLS handshake, eliminating the latency of client-side OCSP lookups and preventing OCSP privacy leakage (the CA would otherwise see which clients are connecting to which servers).

---

## 2. SSL/TLS Configuration for Postfix

### 2a. SSL Certificate Choice

The **same unified Let's Encrypt SAN certificate** used by Nginx was extended to Postfix and Dovecot. This was achieved through a shared `ssl-cert` security group on Rocky Linux:

```bash
sudo groupadd ssl-cert
sudo usermod -aG ssl-cert nginx
sudo usermod -aG ssl-cert postfix
sudo usermod -aG ssl-cert dovecot

# Hardened permissions with sticky-bit inheritance
sudo chgrp -R ssl-cert /etc/letsencrypt/live/ /etc/letsencrypt/archive/
sudo chmod -R 750 /etc/letsencrypt/live/ /etc/letsencrypt/archive/
sudo find /etc/letsencrypt/live/ -type d -exec chmod g+s {} +
```

**Rationale:** A unified certificate across all services (web + mail) reduces management overhead, ensures consistent cryptographic identity for the domain, and eliminates the possibility of a mismatch between the domain name in mail headers and the presented TLS certificate — which can trigger spam filters.

---

### 2b. Protocol Selection

**Postfix (SMTP outbound via SendGrid relay):**

```bash
sudo postconf -e "smtp_use_tls = yes"
sudo postconf -e "smtp_tls_security_level = encrypt"
sudo postconf -e "smtp_tls_note_starttls_offer = yes"
```

**Dovecot (IMAP inbound — `/etc/dovecot/conf.d/10-ssl.conf`):**

```ini
ssl = required
ssl_cert = </etc/letsencrypt/live/gwallofchina.yulcyberhub.click/fullchain.pem
ssl_key  = </etc/letsencrypt/live/gwallofchina.yulcyberhub.click/privkey.pem
ssl_min_protocol = TLSv1.2
```

| Setting | Value | Rationale |
|---|---|---|
| `ssl = required` | Mandatory | Rejects any plaintext IMAP connection at the daemon level |
| `ssl_min_protocol = TLSv1.2` | TLS 1.2+ only | Mirrors Nginx policy; eliminates legacy protocol vulnerabilities |
| `smtp_tls_security_level = encrypt` | Opportunistic → Mandatory | Postfix refuses to deliver mail over unencrypted channels |

**Port Allocation:**

| Port | Service | Protocol |
|---|---|---|
| 465 | SMTPS | SSL/TLS (Implicit — no STARTTLS downgrade possible) |
| 993 | IMAPS | SSL/TLS (Implicit) |
| 587 | SMTP Relay | STARTTLS via SendGrid (outbound only) |

> Implicit TLS (ports 465/993) was chosen over STARTTLS (port 587/143) for client-facing services because STARTTLS is subject to downgrade attacks if not enforced — the `STARTTLS` command can be stripped by a MitM, causing the client to fall back to plaintext. Implicit TLS eliminates this attack vector entirely.

---

### 2c. Cipher Suites and Security Settings

Postfix inherits the system OpenSSL cipher configuration and was additionally hardened with:

```bash
sudo postconf -e "smtp_tls_security_level = encrypt"
sudo postconf -e "smtp_sasl_security_options = noanonymous"
```

The underlying cipher suite policy mirrors the Nginx AEAD-only selection (AES-GCM, ChaCha20-Poly1305 with ECDHE key exchange), as Postfix delegates cipher negotiation to the system's OpenSSL library. TLS 1.3 was automatically enabled via the OpenSSL version bundled with Rocky Linux.

**Verification (SMTPS Port 465):**

```bash
openssl s_client -connect mail.gwallofchina.yulcyberhub.click:465 -quiet
```

**Verification (IMAPS Port 993):**

```bash
openssl s_client -connect mail.gwallofchina.yulcyberhub.click:993 -quiet
# Expected banner: * OK [...] Dovecot ready.
```

---

### 2d. SMTP Authentication

**The "Secret Pipe" Architecture:**

AWS blocks outbound port 25 on EC2 instances by default to prevent spam origination. The solution was to route all outbound mail through **SendGrid** as an authenticated relay on port 587 (STARTTLS), bypassing the port 25 restriction while maintaining a legitimate, DKIM-signed sending identity.

**Credential Security:**

The SendGrid API key was stored in `/etc/postfix/sasl_passwd` — a file that is compiled into an LMDB binary database and locked with strict permissions:

```bash
# Store credential
echo "[smtp.sendgrid.net]:587 apikey:SG.YOUR_KEY_HERE" \
  | sudo tee /etc/postfix/sasl_passwd

# Compile to LMDB (required on Rocky Linux — "hash" type removed)
sudo postmap lmdb:/etc/postfix/sasl_passwd

# Lock down permissions — credential file must never be world-readable
sudo chmod 0600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.lmdb
```

**Postfix Relay Configuration (`/etc/postfix/main.cf`):**

```bash
sudo postconf -e "relayhost = [smtp.sendgrid.net]:587"
sudo postconf -e "smtp_sasl_auth_enable = yes"
sudo postconf -e "smtp_sasl_password_maps = lmdb:/etc/postfix/sasl_passwd"
sudo postconf -e "smtp_sasl_security_options = noanonymous"
sudo postconf -e "default_database_type = lmdb"
sudo postconf -e "alias_database = lmdb:/etc/aliases"
sudo postconf -e "alias_maps = lmdb:/etc/aliases"
```

> **Rocky Linux Compatibility Note:** Rocky Linux 9/10 ships without Berkeley DB support, making the traditional `hash:` map type unavailable. Migrating all database references to `lmdb:` resolved the `unsupported dictionary type: hash` startup error.

**Authentication Verification:**

```bash
sudo tail -n 20 /var/log/maillog
# Confirm: relay=smtp.sendgrid.net, status=sent, 250 Ok
```

---

### 2e. SPF / DKIM / MTA-STS

A complete email authentication stack was deployed to achieve the A+ mail rating and prevent domain spoofing.

**SPF (Sender Policy Framework):**

```dns
@ TXT "v=spf1 ip4:54.226.198.180 mx -all"
```

The `-all` (hard fail) directive instructs receiving mail servers to **reject** — not just mark — any message claiming to originate from this domain that does not come from the authorized IP or MX. This is the strictest possible SPF posture.

**DKIM (DomainKeys Identified Mail):**

Rather than managing static RSA key material in a TXT record, the final architecture delegates DKIM signing to SendGrid via CNAME records:

```dns
s1._domainkey  CNAME  s1.domainkey.u61568083.wl084.sendgrid.net
s2._domainkey  CNAME  s2.domainkey.u61568083.wl084.sendgrid.net
em5287         CNAME  u61568083.wl084.sendgrid.net
```

This CNAME-based approach allows SendGrid to **automatically rotate** the underlying 2048-bit RSA DKIM keys without requiring manual DNS updates, keeping cryptographic material fresh without operational overhead.

**DMARC (Domain-based Message Authentication, Reporting & Conformance):**

```dns
_dmarc TXT "v=DMARC1; p=reject; rua=mailto:admin@gwallofchina.yulcyberhub.click; ruf=mailto:admin@gwallofchina.yulcyberhub.click; sp=reject; adkim=s; aspf=s"
```

| Parameter | Value | Effect |
|---|---|---|
| `p=reject` | Reject | Messages failing SPF/DKIM are dropped at the gateway — no quarantine, no delivery |
| `sp=reject` | Reject | Subdomains inherit the same policy |
| `adkim=s` | Strict | DKIM `d=` tag must exactly match the `From:` domain |
| `aspf=s` | Strict | SPF envelope sender must exactly match the `From:` domain |
| `rua` | Aggregate reports | Daily aggregate failure reports sent to admin |
| `ruf` | Forensic reports | Per-message failure reports for incident analysis |

**MTA-STS & TLS Reporting:**

```dns
_mta-sts  TXT  "v=STSv1; id=20240101000000"
_smtp._tls TXT  "v=TLSRPTv1; rua=mailto:admin@gwallofchina.yulcyberhub.click"
```

MTA-STS (Mail Transfer Agent Strict Transport Security) signals to sending mail servers that TLS is required and the presented certificate must be valid — preventing MitM downgrade attacks on SMTP. TLS-RPT provides failure reporting when encryption is downgraded or certificate validation fails, enabling detection of active interception attempts.

---

## 3. Challenges and Trade-Offs

### 3a. Security vs. Compatibility

**Challenge 1 — Disabling Legacy TLS**

Disabling TLS 1.0 and 1.1 was the most impactful compatibility decision. The security rationale is unambiguous (BEAST, POODLE, no AEAD support), but it renders the infrastructure inaccessible to approximately 2% of legacy clients — primarily Internet Explorer 11 on Windows 7 (end-of-support since 2020) and some embedded IoT devices.

*Decision:* The security posture requirements of this project — targeting an A+ SSL Labs rating — explicitly required disabling these protocols. The affected client base is operating unsupported, unpatched software, which represents a greater risk to the overall ecosystem than the accessibility loss.

**Challenge 2 — DNSSEC Unavailability**

Attempted implementation of DNSSEC was blocked by a structural limitation:

```
AWS Error: "Route 53 does not support DNSSEC for the TLD of this hosted zone."
```

The `.click` TLD registry lacks DNSSEC support, breaking the chain of trust at:
```
. (root) → .click (TLD) → yulcyberhub.click → gwallofchina.yulcyberhub.click
```

*Mitigation:* CAA records restrict certificate issuance to Let's Encrypt, Certificate Transparency monitoring provides unauthorized issuance detection, and after Oracle (instructor) intervention, the chain of trust was ultimately established. DNS security was further hardened through DANE/TLSA consideration for future deployment.

**Challenge 3 — CSP `unsafe-inline`**

The Content Security Policy includes `'unsafe-inline'` for `style-src` and `script-src`, which weakens XSS protection by allowing inline scripts and styles. This was required by the current application architecture.

*Planned mitigation:* Migration to nonce-based CSP (`'nonce-{random}'`), generating a fresh cryptographic nonce per request and injecting it into both the CSP header and legitimate inline elements. This maintains inline script functionality while blocking injected scripts that lack the nonce.

**Challenge 4 — SSH Port 22 Open to 0.0.0.0/0**

The security group configuration includes both a team-specific IP (`204.244.197.216/32`) and `0.0.0.0/0` for SSH:

*Security note acknowledged in documentation:* This was a deliberate operational flexibility decision for the lab environment. **In production, port 22 must be restricted to bastion hosts only.** Fail2Ban or equivalent rate-limiting was applied to mitigate brute-force exposure.

---

### 3b. Performance Considerations

**DH Parameter Generation:**

Generating 4096-bit Diffie-Hellman parameters (`openssl dhparam -out dhparam.pem 4096`) took 10–20 minutes on the t4g.small instance. This is a one-time cost at deployment, not a per-connection cost. The security benefit (Logjam mitigation) far outweighs the one-time generation delay.

**TLS Session Cache:**

```nginx
ssl_session_cache shared:SSL:10m;  # ~40,000 sessions
ssl_session_timeout 1d;
ssl_session_tickets off;
```

Session caching reduces TLS handshake overhead on subsequent connections by resuming negotiated parameters from a server-side cache. The 10MB shared cache (~40,000 session parameters) provides performance benefits while the `ssl_session_tickets off` directive preserves PFS by preventing session resumption from potentially-compromised ticket keys.

**HTTP/2 Multiplexing:**

```nginx
http2 on;
```

HTTP/2 was enabled on port 443, providing header compression (HPACK), request multiplexing over a single TCP connection, and server push capabilities — reducing page load latency without compromising security posture.

**Rate Limiting:**

```nginx
limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;
# ...
limit_req zone=mylimit burst=20 nodelay;
```

Rate limiting at 10 requests/second per IP with a burst allowance of 20 requests provides DDoS mitigation at the application layer. This adds negligible latency for legitimate users while significantly raising the cost of automated attacks.

**ChaCha20-Poly1305 for ARM:**

The t4g.small instance uses an ARM64 Graviton2 processor. On ARM architecture without AES hardware acceleration, ChaCha20-Poly1305 outperforms AES-GCM in pure software. Including `ECDHE-*-CHACHA20-POLY1305` in the cipher suite and allowing server preference ensures optimal cipher selection on the hosting hardware.

---

### 3c. Testing and Troubleshooting

**Validation Framework:**

A multi-layered validation approach was used to verify every security control:

```bash
# 1. HTTP → HTTPS redirect (must be 301, not 302)
curl -I http://gwallofchina.yulcyberhub.click
# Expected: HTTP/1.1 301 Moved Permanently

# 2. TLS handshake verification
openssl s_client -connect gwallofchina.yulcyberhub.click:443 \
  -servername gwallofchina.yulcyberhub.click | head -20

# 3. Protocol enforcement
openssl s_client -connect gwallofchina.yulcyberhub.click:443 -tls1_1
# Expected: handshake failure (connection refused)

# 4. SMTPS verification
openssl s_client -connect mail.gwallofchina.yulcyberhub.click:465 -quiet

# 5. IMAPS verification  
openssl s_client -connect mail.gwallofchina.yulcyberhub.click:993 -quiet

# 6. DNSSEC verification
dig +dnssec MX gwallofchina.yulcyberhub.click
# Look for 'ad' flag = Authenticated Data (DNSSEC valid)

# 7. Mail delivery test
echo "Build Complete" | mail -s "AEC Final Audit" \
  -r admin@gwallofchina.yulcyberhub.click recipient@example.com
```

**Automated Verification Script Results:**

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
[PASS] Content-Security-Policy: present
```

**Issues Encountered and Resolutions:**

| Issue | Root Cause | Resolution |
|---|---|---|
| `unsupported dictionary type: hash` | Rocky Linux 9/10 removed Berkeley DB | Migrated all `hash:` maps to `lmdb:` |
| Lynis download redirect failure | Vendor CDN redirection issue in Rocky 10 | Pivoted to official GitHub tar.gz with `-L` flag for redirect following |
| DNSSEC chain broken | `.click` TLD lacks DNSSEC support | Oracle established chain of trust; CAA/CT monitoring as compensating controls |
| Certificate permission denied (Postfix/Dovecot) | `/etc/letsencrypt` owned by root only | Created `ssl-cert` group; `chmod 750` with `g+s` sticky bit on live/archive dirs |
| Nginx zombie processes | Improper service restart | Hard stop with `pkill -9 nginx` before `systemctl start nginx` |

**Security Auditing — Lynis:**

```bash
cd ~
curl -L https://github.com/CISofy/lynis/archive/refs/tags/3.1.2.tar.gz -o lynis.tar.gz
tar xfvz lynis.tar.gz && cd lynis-3.1.2
chown -R 0:0 lynis
sudo ./lynis audit system --quick
```

Lynis provided CIS benchmark-level hardening recommendations across the full system stack, validating the security posture beyond SSL/TLS configuration alone.

**SSL Labs Final Results:**

| Domain | Overall | Certificate | Protocol | Key Exchange | Cipher |
|---|---|---|---|---|---|
| `gwallofchina.yulcyberhub.click` | **A+** | 100 | 100 | 100 | 100 |
| `mail.gwallofchina.yulcyberhub.click` | **A+** | ✅ | TLS 1.3 ✅ | ✅ | ✅ |

---

## 4. References

| Resource | URL |
|---|---|
| Mozilla SSL Configuration Generator | https://ssl-config.mozilla.org |
| SSL Labs Server Test | https://www.ssllabs.com/ssltest/ |
| RFC 8446 — TLS 1.3 | https://datatracker.ietf.org/doc/html/rfc8446 |
| RFC 8996 — Deprecating TLS 1.0 & 1.1 | https://datatracker.ietf.org/doc/html/rfc8996 |
| RFC 7489 — DMARC | https://datatracker.ietf.org/doc/html/rfc7489 |
| RFC 8461 — MTA-STS | https://datatracker.ietf.org/doc/html/rfc8461 |
| Let's Encrypt Documentation | https://letsencrypt.org/docs/ |
| Certbot Documentation | https://certbot.eff.org/docs/ |
| NIST SP 800-52 Rev. 2 — TLS Guidelines | https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final |
| Logjam Attack (CVE-2015-4000) | https://weakdh.org |
| POODLE Attack (CVE-2014-3566) | https://www.openssl.org/~bodo/ssl-poodle.pdf |
| BEAST Attack (CVE-2011-3389) | https://nvd.nist.gov/vuln/detail/CVE-2011-3389 |
| HSTS Preload List | https://hstspreload.org |
| CAA Record RFC 8659 | https://datatracker.ietf.org/doc/html/rfc8659 |
| Lynis Security Auditing Tool | https://github.com/CISofy/lynis |
| aws-vault (ByteNess fork) | https://github.com/ByteNess/aws-vault |
| DNSViz DNSSEC Visualizer | https://dnsviz.net |
| Project Scripts Repository | https://github.com/mrblue223/CyberSecurity_School_Labs/tree/main/Optimizing_SSL_Certificates/scripts |
| Nginx SSL/TLS Documentation | https://nginx.org/en/docs/http/ngx_http_ssl_module.html |
| Postfix TLS README | https://www.postfix.org/TLS_README.html |
| Dovecot SSL Configuration | https://doc.dovecot.org/configuration_manual/dovecot_ssl_configuration/ |
| SendGrid DKIM Authentication | https://docs.sendgrid.com/ui/account-and-settings/dkim-records |

---

<div align="center">

**Document Control**

| Version | Date | Author | Changes |
|---|---|---|---|
| 3.0 | 2026-02-25 | Sammy Roy | Hardened infrastructure documentation with AWS CLI verification |

*Next Review: 2026-06-25 (Quarterly Security Assessment)*  
*Distribution: Cyber Defense Team · Operations Center · Compliance Office*

---

![Built with](https://img.shields.io/badge/Built%20with-Rocky%20Linux-10B981?style=flat-square&logo=rockylinux)
![Secured by](https://img.shields.io/badge/Secured%20by-Let's%20Encrypt-FF7700?style=flat-square&logo=letsencrypt)
![Hosted on](https://img.shields.io/badge/Hosted%20on-AWS%20EC2-FF9900?style=flat-square&logo=amazonaws)
![Audited by](https://img.shields.io/badge/Audited%20by-Lynis-blue?style=flat-square)

*"Security is not a product, but a process."* — Bruce Schneier

</div>
