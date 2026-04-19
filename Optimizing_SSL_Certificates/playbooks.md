# GwallR3 — Operational Playbooks

> **Domain:** `gwallofchina.yulcyberhub.click`
> **Bastion:** `i-03cd6b2122a92f1b7` · WireGuard `10.200.0.1` · Public IP dynamic
> **Frontend:** `i-0b71d405f8ad5f73b` · Private `172.31.18.210` · Public IP dynamic
> **CloudFront:** `E3V6XIAZ15OGQ6` · `d1origzrc8v9ew.cloudfront.net`
> **Hosted Zone:** `Z0433076DMIP84BGAZGN`
> **Security Group:** `sg-0c7a7efce68ce2773`
> **AWS Profile:** `MEQ7_RBAC_Room3-453875232433`
> **SSH Key:** `~/.ssh/thegreatfirewallofchina.pem`
> **SSH User:** `rocky`
> **WireGuard Subnet:** `10.200.0.0/24` · Kali `10.200.0.2` · Wazuh `10.200.0.6`

---

## Table of Contents

1. [Playbook 01 — Frontend IP Changed After Reboot](#playbook-01--frontend-ip-changed-after-reboot)
2. [Playbook 02 — Certificate Expired or Renewal Failed](#playbook-02--certificate-expired-or-renewal-failed)
3. [Playbook 03 — Instance Unreachable / Server Down](#playbook-03--instance-unreachable--server-down)
4. [Playbook 04 — SSH Key Lost / Locked Out of Server](#playbook-04--ssh-key-lost--locked-out-of-server)
5. [Playbook 05 — WireGuard Tunnel Down](#playbook-05--wireguard-tunnel-down)
6. [Playbook 06 — Nginx Down / HTTPS Not Responding](#playbook-06--nginx-down--https-not-responding)
7. [Playbook 07 — CloudFront 504 / WAF Bypass](#playbook-07--cloudfront-504--waf-bypass)
8. [Playbook 08 — Mail Delivery Failing (SPF / DKIM / DMARC)](#playbook-08--mail-delivery-failing-spf--dkim--dmarc)
9. [Playbook 09 — Postfix / Mail Queue Stuck](#playbook-09--postfix--mail-queue-stuck)
10. [Playbook 10 — Dovecot / IMAP Down](#playbook-10--dovecot--imap-down)
11. [Playbook 11 — Webmail 502 / Node.js Down](#playbook-11--webmail-502--nodejs-down)
12. [Playbook 12 — Disk Full](#playbook-12--disk-full)
13. [Playbook 13 — Wazuh Agent Disconnected](#playbook-13--wazuh-agent-disconnected)
14. [Playbook 14 — Security Group Misconfiguration / Port Locked Out](#playbook-14--security-group-misconfiguration--port-locked-out)
15. [Playbook 15 — IAM Role / Permission Failure](#playbook-15--iam-role--permission-failure)
16. [Playbook 16 — Daily Health Check (Preventive)](#playbook-16--daily-health-check-preventive)

---

## Playbook 01 — Frontend IP Changed After Reboot

**Symptoms:**
- `504 Gateway Timeout` on `mail.gwallofchina.yulcyberhub.click`
- `HTTP/2 PROTOCOL_ERROR` on `gwallofchina.yulcyberhub.click`
- CloudFront cannot reach origin
- Webmail and main site both down

**Severity:** 🔴 Critical

---

### Step 1 — Get the new frontend IP

```bash
aws ec2 describe-instances \
  --profile MEQ7_RBAC_Room3-453875232433 \
  --instance-ids i-0b71d405f8ad5f73b \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text
```

### Step 2 — Update origin DNS records

Replace `NEW_IP` with the IP from Step 1.

```bash
aws route53 change-resource-record-sets \
  --hosted-zone-id Z0433076DMIP84BGAZGN \
  --profile MEQ7_RBAC_Room3-453875232433 \
  --change-batch '{
    "Changes": [
      {
        "Action": "UPSERT",
        "ResourceRecordSet": {
          "Name": "origin.gwallofchina.yulcyberhub.click",
          "Type": "A",
          "TTL": 300,
          "ResourceRecords": [{"Value": "NEW_IP"}]
        }
      },
      {
        "Action": "UPSERT",
        "ResourceRecordSet": {
          "Name": "origin-mail.gwallofchina.yulcyberhub.click",
          "Type": "A",
          "TTL": 300,
          "ResourceRecords": [{"Value": "NEW_IP"}]
        }
      }
    ]
  }'
```

### Step 3 — Update SPF record

```bash
aws route53 change-resource-record-sets \
  --hosted-zone-id Z0433076DMIP84BGAZGN \
  --profile MEQ7_RBAC_Room3-453875232433 \
  --change-batch '{
    "Changes": [{
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "gwallofchina.yulcyberhub.click",
        "Type": "TXT",
        "TTL": 300,
        "ResourceRecords": [{"Value": "\"v=spf1 ip4:NEW_IP include:sendgrid.net mx ~all\""}]
      }
    }]
  }'
```

### Step 4 — Confirm main domain points to CloudFront ALIAS (not direct A)

```bash
dig gwallofchina.yulcyberhub.click +short
# Must show CloudFront IPs (13.x.x.x range) NOT the server IP
# If showing server IP directly, run the fix below
```

If showing server IP directly:

```bash
aws route53 change-resource-record-sets \
  --hosted-zone-id Z0433076DMIP84BGAZGN \
  --profile MEQ7_RBAC_Room3-453875232433 \
  --change-batch '{
    "Changes": [{
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "gwallofchina.yulcyberhub.click",
        "Type": "A",
        "AliasTarget": {
          "HostedZoneId": "Z2FDTNDATAQYW2",
          "DNSName": "d1origzrc8v9ew.cloudfront.net",
          "EvaluateTargetHealth": false
        }
      }
    }]
  }'
```

### Step 5 — Invalidate CloudFront cache

```bash
aws cloudfront create-invalidation \
  --profile MEQ7_RBAC_Room3-453875232433 \
  --distribution-id E3V6XIAZ15OGQ6 \
  --paths "/*"
```

### Step 6 — Fix Maildir permissions if mail delivery broken

```bash
ssh frontend
sudo chown -R vmail:vmail /var/mail/vhosts/
sudo chmod -R 770 /var/mail/vhosts/
```

### Step 7 — Verify

```bash
sleep 30
curl -sI https://gwallofchina.yulcyberhub.click | grep -E "HTTP|x-cache|via"
curl -sI https://mail.gwallofchina.yulcyberhub.click | grep -E "HTTP|x-cache|via"
curl -k -sI https://NEW_IP | head -3  # should be silent (444)
dig gwallofchina.yulcyberhub.click +short  # should show 13.x.x.x CloudFront IPs
dig TXT gwallofchina.yulcyberhub.click +short | grep spf  # verify new IP in SPF
```

> ⚠️ **Prevention:** Assign an Elastic IP to the frontend to prevent this on every reboot.

---

## Playbook 02 — Certificate Expired or Renewal Failed

**Symptoms:**
- Browser shows `NET::ERR_CERT_DATE_INVALID`
- Mail clients report TLS handshake failure
- `sudo certbot renew` exits non-zero

**Severity:** 🔴 Critical

---

### Step 1 — Check certificate status

```bash
ssh frontend
sudo certbot certificates

# Check days remaining
echo | openssl s_client -connect gwallofchina.yulcyberhub.click:443 \
  -servername gwallofchina.yulcyberhub.click 2>/dev/null \
  | openssl x509 -noout -dates
```

### Step 2 — Attempt renewal

```bash
sudo certbot renew --dry-run
sudo certbot renew
```

### Step 3 — If renewal fails, check IAM role

```bash
# Verify instance role is attached
curl -s -H "X-aws-ec2-metadata-token: $(curl -s -X PUT \
  http://169.254.169.254/latest/api/token \
  -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Test Route53 access from the instance
aws route53 list-hosted-zones --region us-east-1
```

### Step 4 — If Route53 access works, force renewal

```bash
sudo certbot certonly \
  --dns-route53 \
  --domain gwallofchina.yulcyberhub.click \
  --domain "*.gwallofchina.yulcyberhub.click" \
  --force-renewal
```

### Step 5 — Reload services after renewal

```bash
sudo systemctl reload nginx
sudo systemctl reload postfix
sudo systemctl reload dovecot
```

### Step 6 — Verify

```bash
echo | openssl s_client -connect gwallofchina.yulcyberhub.click:443 \
  -servername gwallofchina.yulcyberhub.click 2>/dev/null \
  | openssl x509 -noout -dates
```

---

## Playbook 03 — Instance Unreachable / Server Down

**Symptoms:**
- SSH connection times out or refused
- HTTPS returns no response
- CloudFront returning 504 on all endpoints

**Severity:** 🔴 Critical

---

### Step 1 — Check instance state

```bash
aws ec2 describe-instance-status \
  --instance-ids i-0b71d405f8ad5f73b \
  --profile MEQ7_RBAC_Room3-453875232433 \
  --output table
```

### Step 2 — If stopped, start it

```bash
aws ec2 start-instances \
  --instance-ids i-0b71d405f8ad5f73b \
  --profile MEQ7_RBAC_Room3-453875232433

aws ec2 wait instance-running \
  --instance-ids i-0b71d405f8ad5f73b \
  --profile MEQ7_RBAC_Room3-453875232433
```

### Step 3 — If running but unreachable, stop/start (forces new hardware)

```bash
# NOTE: stop/start not reboot — forces migration to new host
aws ec2 stop-instances \
  --instance-ids i-0b71d405f8ad5f73b \
  --profile MEQ7_RBAC_Room3-453875232433

aws ec2 wait instance-stopped \
  --instance-ids i-0b71d405f8ad5f73b \
  --profile MEQ7_RBAC_Room3-453875232433

aws ec2 start-instances \
  --instance-ids i-0b71d405f8ad5f73b \
  --profile MEQ7_RBAC_Room3-453875232433
```

### Step 4 — Get new IP and update DNS

Follow **Playbook 01** to update origin DNS records after the IP changes.

### Step 5 — Verify services after restart

```bash
ssh frontend
sudo systemctl status nginx postfix dovecot
/usr/local/bin/pm2 status
```

---

## Playbook 04 — SSH Key Lost / Locked Out of Server

**Symptoms:**
- `Permission denied (publickey)` on SSH
- PEM file missing or corrupted

**Severity:** 🟠 High — services still running, no admin access

---

### Step 1 — Connect via WireGuard first

```bash
# If WireGuard tunnel is up, try bastion-public then hop to frontend
ssh -i ~/.ssh/thegreatfirewallofchina.pem rocky@107.20.1.113
ssh -i ~/.ssh/thegreatfirewallofchina.pem rocky@172.31.18.210
```

### Step 2 — If no key available, use EC2 Instance Connect

```bash
# Generate a temporary keypair
ssh-keygen -t ed25519 -f /tmp/recovery_key -N ""

# Push the public key (valid for 60 seconds)
aws ec2-instance-connect send-ssh-public-key \
  --instance-id i-0b71d405f8ad5f73b \
  --instance-os-user rocky \
  --ssh-public-key file:///tmp/recovery_key.pub \
  --availability-zone us-east-1a \
  --profile MEQ7_RBAC_Room3-453875232433

# SSH in immediately (within 60 seconds)
ssh -i /tmp/recovery_key rocky@98.84.149.61
```

### Step 3 — Restore permanent key access

```bash
# On local machine — generate new permanent key
ssh-keygen -t ed25519 -f ~/.ssh/thegreatfirewallofchina_new -C "gwall-recovery"

# On server — add new key
echo "PASTE_PUBLIC_KEY_HERE" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Test from second terminal before closing recovery session
ssh -i ~/.ssh/thegreatfirewallofchina_new rocky@98.84.149.61
```

---

## Playbook 05 — WireGuard Tunnel Down

**Symptoms:**
- Cannot SSH to bastion via `10.200.0.1`
- Wazuh agents disconnected
- `ping 10.200.0.1` fails

**Severity:** 🟠 High

---

### Step 1 — Check WireGuard status on Kali

```bash
sudo wg show
ip addr show wg0
```

### Step 2 — Get current bastion public IP

```bash
aws ec2 describe-instances \
  --profile MEQ7_RBAC_Room3-453875232433 \
  --instance-ids i-03cd6b2122a92f1b7 \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text
```

### Step 3 — Update WireGuard endpoint if bastion IP changed

```bash
sudo wg-quick down wg0
sudo sed -i 's/Endpoint = .*/Endpoint = NEW_BASTION_IP:51820/' /etc/wireguard/wg0.conf
sudo wg-quick up wg0
```

### Step 4 — Verify tunnel

```bash
ping -c 3 10.200.0.1
sudo wg show
# Confirm: latest handshake within last few minutes
```

### Step 5 — If bastion WireGuard service is down, SSH via public IP

```bash
ssh bastion-public
sudo systemctl status wg-quick@wg0
sudo systemctl restart wg-quick@wg0
sudo wg show
```

---

## Playbook 06 — Nginx Down / HTTPS Not Responding

**Symptoms:**
- `curl: (7) Failed to connect` on port 443
- CloudFront returning 502 or 504
- Browser shows connection refused

**Severity:** 🔴 Critical

---

### Step 1 — Check Nginx status

```bash
ssh frontend
sudo systemctl status nginx
sudo nginx -t
```

### Step 2 — Check error logs

```bash
sudo tail -50 /var/log/nginx/error.log
sudo tail -50 /var/log/nginx/gwallofchina.error.log
sudo tail -50 /var/log/nginx/webmail.error.log
```

### Step 3 — Restart Nginx

```bash
sudo systemctl restart nginx
sudo systemctl status nginx
```

### Step 4 — If config test fails, check recent changes

```bash
sudo nginx -t 2>&1
# Fix any syntax errors shown
# Common issues:
#   - ssl_certificate path wrong after reboot
#   - dhparam file missing
#   - proxy_pass target not running
```

### Step 5 — Verify certificate files exist

```bash
sudo ls -la /etc/letsencrypt/live/gwallofchina.yulcyberhub.click/
sudo ls -la /etc/nginx/ssl/dhparam.pem
```

### Step 6 — Verify

```bash
curl -sI https://gwallofchina.yulcyberhub.click | grep -E "HTTP|x-cache"
curl -sI https://mail.gwallofchina.yulcyberhub.click | grep HTTP
```

---

## Playbook 07 — CloudFront 504 / WAF Bypass

**Symptoms:**
- `504 Gateway Timeout` from CloudFront
- `x-cache: Error from cloudfront` in headers
- Direct IP access not blocked

**Severity:** 🔴 Critical

---

### Step 1 — Verify origin DNS resolves to correct IP

```bash
dig origin.gwallofchina.yulcyberhub.click +short
dig origin-mail.gwallofchina.yulcyberhub.click +short

# Compare with actual frontend IP
aws ec2 describe-instances \
  --profile MEQ7_RBAC_Room3-453875232433 \
  --instance-ids i-0b71d405f8ad5f73b \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text
```

If IPs don't match → follow **Playbook 01**.

### Step 2 — Verify X-Origin-Verify header is on CloudFront

```bash
aws cloudfront get-distribution \
  --profile MEQ7_RBAC_Room3-453875232433 \
  --id E3V6XIAZ15OGQ6 \
  --query 'Distribution.DistributionConfig.Origins.Items[*].{Domain:DomainName,Headers:CustomHeaders.Items}' \
  --output json
# Both origins must have X-Origin-Verify header
```

### Step 3 — Test origin directly with secret header

```bash
FRONTEND_IP=$(aws ec2 describe-instances \
  --profile MEQ7_RBAC_Room3-453875232433 \
  --instance-ids i-0b71d405f8ad5f73b \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text)

curl -k -I https://$FRONTEND_IP \
  -H "X-Origin-Verify: <REDACTED>" \
  -H "Host: gwallofchina.yulcyberhub.click"
# Expected: HTTP/2 200
```

### Step 4 — Verify direct IP is blocked (no header)

```bash
curl -k -sI https://$FRONTEND_IP | head -3
# Expected: no response (444 silent drop)
```

### Step 5 — Verify main domain is CloudFront ALIAS not direct A

```bash
dig gwallofchina.yulcyberhub.click +short
# Must show 13.x.x.x CloudFront IPs — if showing server IP follow Playbook 01 Step 4
```

### Step 6 — Invalidate CloudFront cache

```bash
aws cloudfront create-invalidation \
  --profile MEQ7_RBAC_Room3-453875232433 \
  --distribution-id E3V6XIAZ15OGQ6 \
  --paths "/*"
```

---

## Playbook 08 — Mail Delivery Failing (SPF / DKIM / DMARC)

**Symptoms:**
- Outbound emails going to spam
- SPF / DKIM / DMARC failures in email headers
- Bounce messages with authentication errors

**Severity:** 🟠 High

---

### Step 1 — Verify SPF record has correct IP

```bash
FRONTEND_IP=$(aws ec2 describe-instances \
  --profile MEQ7_RBAC_Room3-453875232433 \
  --instance-ids i-0b71d405f8ad5f73b \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text)
echo "Frontend IP: $FRONTEND_IP"

dig TXT gwallofchina.yulcyberhub.click +short | grep spf
# Must contain ip4:$FRONTEND_IP
```

If SPF IP is wrong, update it:

```bash
aws route53 change-resource-record-sets \
  --hosted-zone-id Z0433076DMIP84BGAZGN \
  --profile MEQ7_RBAC_Room3-453875232433 \
  --change-batch "{
    \"Changes\": [{
      \"Action\": \"UPSERT\",
      \"ResourceRecordSet\": {
        \"Name\": \"gwallofchina.yulcyberhub.click\",
        \"Type\": \"TXT\",
        \"TTL\": 300,
        \"ResourceRecords\": [{\"Value\": \"\\\"v=spf1 ip4:$FRONTEND_IP include:sendgrid.net mx ~all\\\"\"}]
      }
    }]
  }"
```

### Step 2 — Verify DKIM records exist

```bash
dig TXT default._domainkey.gwallofchina.yulcyberhub.click +short
dig TXT s1._domainkey.gwallofchina.yulcyberhub.click +short
dig TXT s2._domainkey.gwallofchina.yulcyberhub.click +short
```

### Step 3 — Verify DMARC record

```bash
dig TXT _dmarc.gwallofchina.yulcyberhub.click +short
```

### Step 4 — Check OpenDKIM is running

```bash
ssh frontend
sudo systemctl status opendkim
sudo opendkim-testkey -d gwallofchina.yulcyberhub.click -s default -vvv
```

### Step 5 — Send test email and check headers

```bash
echo "Test" | mail -s "DKIM Test" check-auth@verifier.port25.com
# Wait for auto-reply and check Authentication-Results header
```

---

## Playbook 09 — Postfix / Mail Queue Stuck

**Symptoms:**
- Outbound emails not delivering
- Mail queue backing up
- `postqueue -p` shows large queue

**Severity:** 🟠 High

---

### Step 1 — Check Postfix status

```bash
ssh frontend
sudo systemctl status postfix
sudo postqueue -p | head -20
sudo postqueue -p | wc -l
```

### Step 2 — Check mail logs

```bash
sudo tail -50 /var/log/maillog
sudo journalctl -u postfix --since "1 hour ago"
```

### Step 3 — Flush the queue

```bash
sudo postqueue -f
# Wait 2 minutes then check queue again
sudo postqueue -p | wc -l
```

### Step 4 — If queue won't clear, check common causes

```bash
# Port 25 blocked?
telnet smtp.gmail.com 25

# DNS resolving?
dig MX gmail.com +short

# SendGrid fallback working?
telnet smtp.sendgrid.net 587
```

### Step 5 — If queue is full of bounces, clear it

```bash
# Nuclear option — clears entire queue
sudo postsuper -d ALL

# Or delete only deferred messages
sudo postsuper -d ALL deferred
```

### Step 6 — Restart Postfix

```bash
sudo systemctl restart postfix
sudo systemctl status postfix
```

---

## Playbook 10 — Dovecot / IMAP Down

**Symptoms:**
- Webmail login fails
- IMAP clients cannot connect on port 993
- `Connection refused` on port 993

**Severity:** 🟠 High

---

### Step 1 — Check Dovecot status

```bash
ssh frontend
sudo systemctl status dovecot
sudo ss -tlnp | grep 993
```

### Step 2 — Check logs

```bash
sudo tail -50 /var/log/maillog | grep dovecot
sudo journalctl -u dovecot --since "1 hour ago"
```

### Step 3 — Restart Dovecot

```bash
sudo systemctl restart dovecot
sudo systemctl status dovecot
```

### Step 4 — Verify Maildir permissions

```bash
sudo ls -la /var/mail/vhosts/gwallofchina.yulcyberhub.click/
sudo chown -R vmail:vmail /var/mail/vhosts/
sudo chmod -R 770 /var/mail/vhosts/
```

### Step 5 — Test IMAP connection

```bash
curl -v imaps://mail.gwallofchina.yulcyberhub.click \
  --user "rocky@gwallofchina.yulcyberhub.click:PASSWORD" \
  -k 2>&1 | head -20
```

---

## Playbook 11 — Webmail 502 / Node.js Down

**Symptoms:**
- `502 Bad Gateway` on `mail.gwallofchina.yulcyberhub.click`
- Webmail page not loading
- Port 3000 not listening

**Severity:** 🟠 High

---

### Step 1 — Check PM2 status

```bash
ssh frontend
/usr/local/bin/pm2 status
/usr/local/bin/pm2 logs webmail --lines 30
```

### Step 2 — Check if port 3000 is listening

```bash
sudo ss -tlnp | grep 3000
```

### Step 3 — Restart webmail

```bash
/usr/local/bin/pm2 restart webmail
/usr/local/bin/pm2 status
```

### Step 4 — If PM2 not starting, check app logs

```bash
/usr/local/bin/pm2 logs webmail --err --lines 50
cat /home/rocky/.pm2/logs/webmail-error.log | tail -30
```

### Step 5 — If Maildir permission errors in logs

```bash
sudo chown -R vmail:vmail /var/mail/vhosts/
sudo chmod -R 770 /var/mail/vhosts/
/usr/local/bin/pm2 restart webmail
```

### Step 6 — Verify

```bash
curl -sI http://localhost:3000 | grep HTTP
# Expected: HTTP/1.1 200 OK
```

---

## Playbook 12 — Disk Full

**Symptoms:**
- Services failing with write errors
- `No space left on device` in logs
- PM2 delivery errors in webmail

**Severity:** 🟠 High

---

### Step 1 — Check disk usage

```bash
ssh frontend
df -h
du -sh /var/log/* | sort -rh | head -10
du -sh /var/mail/vhosts/* | sort -rh | head -10
```

### Step 2 — Clear old logs

```bash
sudo journalctl --vacuum-size=200M
sudo find /var/log -name "*.gz" -mtime +14 -delete
sudo find /var/log/nginx -name "*.log.*" -mtime +7 -delete
```

### Step 3 — Clear mail queue if backed up

```bash
sudo postqueue -p | wc -l
sudo postsuper -d ALL deferred
```

### Step 4 — Check PM2 logs

```bash
/usr/local/bin/pm2 flush
rm -f /home/rocky/.pm2/logs/*.log
```

### Step 5 — Verify space recovered

```bash
df -h
```

---

## Playbook 13 — Wazuh Agent Disconnected

**Symptoms:**
- `gwall-siem agents check` shows Disconnected
- `sudo gwall-siem status` shows agent down

**Severity:** 🟡 Medium

---

### Step 1 — Check agent status

```bash
ssh wazuh
sudo gwall-siem agents check
sudo /var/ossec/bin/agent_control -l
```

### Step 2 — Wait — agents reconnect automatically after manager restart

```bash
sleep 30
sudo gwall-siem agents check
```

### Step 3 — If still disconnected, check bastion forwarding

```bash
ssh bastion
sudo firewall-cmd --list-all-policies
# vpc-to-vpn policy must exist and be ACCEPT
```

### Step 4 — Check agent on the disconnected host

```bash
# On bastion
ssh bastion
sudo systemctl status wazuh-agent
sudo systemctl restart wazuh-agent

# On frontend
ssh frontend
sudo systemctl status wazuh-agent
sudo systemctl restart wazuh-agent
```

### Step 5 — Verify

```bash
ssh wazuh
sleep 15
sudo gwall-siem agents check
```

---

## Playbook 14 — Security Group Misconfiguration / Port Locked Out

**Symptoms:**
- SSH port 22 inaccessible from WireGuard
- Cannot reach bastion or frontend

**Severity:** 🔴 Critical

---

### Step 1 — Check current Security Group rules

```bash
aws ec2 describe-security-groups \
  --group-ids sg-0c7a7efce68ce2773 \
  --profile MEQ7_RBAC_Room3-453875232433 \
  --query 'SecurityGroups[0].IpPermissions' \
  --output table
```

### Step 2 — Add SSH rule back temporarily from your current IP

```bash
MY_IP=$(curl -s https://checkip.amazonaws.com)
aws ec2 authorize-security-group-ingress \
  --group-id sg-0c7a7efce68ce2773 \
  --protocol tcp \
  --port 22 \
  --cidr $MY_IP/32 \
  --profile MEQ7_RBAC_Room3-453875232433
```

### Step 3 — SSH in and restore WireGuard

```bash
ssh -i ~/.ssh/thegreatfirewallofchina.pem rocky@107.20.1.113
# Restore WireGuard, then bring up tunnel and test
```

### Step 4 — Remove temporary rule after WireGuard is verified

```bash
aws ec2 revoke-security-group-ingress \
  --group-id sg-0c7a7efce68ce2773 \
  --protocol tcp \
  --port 22 \
  --cidr $MY_IP/32 \
  --profile MEQ7_RBAC_Room3-453875232433
```

---

## Playbook 15 — IAM Role / Permission Failure

**Symptoms:**
- `certbot renew` fails with Route53 access denied
- AWS CLI commands failing from EC2 instance
- `Unable to locate credentials` errors

**Severity:** 🟠 High

---

### Step 1 — Verify instance profile is attached

```bash
aws ec2 describe-instances \
  --profile MEQ7_RBAC_Room3-453875232433 \
  --instance-ids i-0b71d405f8ad5f73b \
  --query 'Reservations[0].Instances[0].IamInstanceProfile' \
  --output json
# Expected: meq7-ec2-role-frontend-room3
```

### Step 2 — Test credentials from inside the instance

```bash
ssh frontend
aws sts get-caller-identity
aws route53 list-hosted-zones --region us-east-1
```

### Step 3 — Check IMDSv2 is working

```bash
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### Step 4 — If role is missing, contact Oracle (instructor) to reattach

The IAM role `meq7-ec2-role-frontend-room3` must be attached at the instance profile level — this cannot be done with the `MEQ7_RBAC_Room3` role permissions.

---

## Playbook 16 — Daily Health Check (Preventive)

Run before each work session to catch issues early.

---

```bash
# ── FROM KALI ─────────────────────────────────────────────────

# 1. WireGuard tunnel active
sudo wg show | grep -E "peer|handshake|transfer"
ping -c 2 10.200.0.1

# 2. Main site up via CloudFront
curl -sI https://gwallofchina.yulcyberhub.click | grep -E "HTTP|x-cache"

# 3. Webmail up via CloudFront
curl -sI https://mail.gwallofchina.yulcyberhub.click | grep -E "HTTP|x-cache"

# 4. Direct IP blocked
curl -k -sI https://$(aws ec2 describe-instances \
  --profile MEQ7_RBAC_Room3-453875232433 \
  --instance-ids i-0b71d405f8ad5f73b \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text) | head -2

# 5. DNS resolves to CloudFront not server IP
dig gwallofchina.yulcyberhub.click +short

# 6. Origin DNS matches current frontend IP
dig origin.gwallofchina.yulcyberhub.click +short
aws ec2 describe-instances \
  --profile MEQ7_RBAC_Room3-453875232433 \
  --instance-ids i-0b71d405f8ad5f73b \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text

# 7. SPF record has correct IP
dig TXT gwallofchina.yulcyberhub.click +short | grep spf

# ── FROM WAZUH MANAGER ────────────────────────────────────────
ssh wazuh
sudo gwall-siem status

# ── FROM FRONTEND ─────────────────────────────────────────────
ssh frontend
sudo systemctl is-active nginx postfix dovecot
/usr/local/bin/pm2 status
df -h | grep -v tmpfs
```

### Expected healthy output

| Check | Expected |
|---|---|
| Main site | `HTTP/2 200` + `x-cache: Miss from cloudfront` |
| Webmail | `HTTP/2 200` + `x-cache: Miss from cloudfront` |
| Direct IP | No response (silent 444) |
| DNS main domain | `13.x.x.x` CloudFront IPs |
| Origin DNS == Frontend IP | Both show same IP |
| SPF | Contains current frontend IP |
| Wazuh agents | All 3 Active |
| Services | `active` for nginx, postfix, dovecot |
| Webmail PM2 | `online` |
| Disk | Under 80% used |

---

## Quick Reference

| Resource | Value |
|---|---|
| Bastion Instance | `i-03cd6b2122a92f1b7` |
| Frontend Instance | `i-0b71d405f8ad5f73b` |
| Frontend current IP | `98.84.149.61` (dynamic — verify before use) |
| Security Group | `sg-0c7a7efce68ce2773` |
| Hosted Zone | `Z0433076DMIP84BGAZGN` |
| CloudFront Distribution | `E3V6XIAZ15OGQ6` |
| CloudFront Domain | `d1origzrc8v9ew.cloudfront.net` |
| CloudFront Hosted Zone ID | `Z2FDTNDATAQYW2` |
| WireGuard Bastion IP | `10.200.0.1` |
| WireGuard Kali IP | `10.200.0.2` |
| WireGuard Wazuh IP | `10.200.0.6` |
| AWS Profile | `MEQ7_RBAC_Room3-453875232433` |
| SSH Key | `~/.ssh/thegreatfirewallofchina.pem` |
| SSH User | `rocky` |
| Bastion SSH alias | `ssh bastion` |
| Frontend SSH alias | `ssh frontend` |
| Wazuh SSH alias | `ssh wazuh` |

