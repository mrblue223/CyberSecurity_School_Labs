# Great Wall Infrastructure — Operational Playbooks

> **Domain:** `gwallofchina.yulcyberhub.click`  
> **Instance:** `i-0b71d405f8ad5f73b` · **IP:** `54.226.198.180`  
> **Region:** `us-east-1` · **Account:** `453875232433`  
> **OS:** Rocky Linux 10 (aarch64) · **Profile:** `MEQ7_RBAC_Room3-453875232433`

---

## Table of Contents

1. [Playbook 01 — Certificate Expired or Renewal Failed](#playbook-01--certificate-expired-or-renewal-failed)
2. [Playbook 02 — Instance Unreachable / Server Down](#playbook-02--instance-unreachable--server-down)
3. [Playbook 03 — Elastic IP Lost or IP Address Changed](#playbook-03--elastic-ip-lost-or-ip-address-changed)
4. [Playbook 04 — SSH Key Lost / Locked Out of Server](#playbook-04--ssh-key-lost--locked-out-of-server)
5. [Playbook 05 — Disk Full](#playbook-05--disk-full)
6. [Playbook 06 — Mail Delivery Failing (SPF / DKIM / DMARC)](#playbook-06--mail-delivery-failing-spf--dkim--dmarc)
7. [Playbook 07 — Nginx Down / HTTPS Not Responding](#playbook-07--nginx-down--https-not-responding)
8. [Playbook 08 — Postfix / Mail Queue Stuck](#playbook-08--postfix--mail-queue-stuck)
9. [Playbook 09 — Dovecot / IMAP Down](#playbook-09--dovecot--imap-down)
10. [Playbook 10 — OpenDKIM Signing Failure](#playbook-10--opendkim-signing-failure)
11. [Playbook 11 — DNSSEC Broken / DNS Not Resolving](#playbook-11--dnssec-broken--dns-not-resolving)
12. [Playbook 12 — Full Instance Recovery from Snapshot](#playbook-12--full-instance-recovery-from-snapshot)
13. [Playbook 13 — Security Group Misconfiguration / Port Locked Out](#playbook-13--security-group-misconfiguration--port-locked-out)
14. [Playbook 14 — IAM Role / Permission Failure](#playbook-14--iam-role--permission-failure)
15. [Playbook 15 — Daily Health Check (Preventive)](#playbook-15--daily-health-check-preventive)

---

## Quick Reference — Key IDs

```
Instance ID:        i-0b71d405f8ad5f73b
Elastic IP:         54.226.198.180
Security Group:     sg-0c7a7efce68ce2773
Hosted Zone ID:     Z0433076DMIP84BGAZGN
KMS Key ARN:        arn:aws:kms:us-east-1:453875232433:key/df174539-...
IAM Profile:        meq7-ec2-role-frontend-room3
SSH Key:            thegreatfirewallofchina.pem
SSH User:           rocky
AWS Profile:        MEQ7_RBAC_Room3-453875232433
```

---

## Playbook 01 — Certificate Expired or Renewal Failed

**Symptoms:**
- Browser shows `NET::ERR_CERT_DATE_INVALID`
- Mail clients report TLS handshake failure
- `sudo certbot renew` exits non-zero
- Expiry alert email received

**Severity:** 🔴 Critical — services degraded immediately

---

### Step 1 — Check Certificate Status

```bash
# Check expiry date
sudo certbot certificates

# Check live expiry via OpenSSL
echo | openssl s_client -connect gwallofchina.yulcyberhub.click:443 \
  -servername gwallofchina.yulcyberhub.click 2>/dev/null \
  | openssl x509 -noout -dates

# Check days remaining
EXPIRY=$(echo | openssl s_client \
  -connect gwallofchina.yulcyberhub.click:443 \
  -servername gwallofchina.yulcyberhub.click 2>/dev/null \
  | openssl x509 -noout -enddate | cut -d= -f2)
echo "Days remaining: $(( ($(date -d "$EXPIRY" +%s) - $(date +%s)) / 86400 ))"
```

### Step 2 — Diagnose Renewal Failure

```bash
# Check renewal logs
sudo journalctl -u certbot-renew --since "48 hours ago"
sudo cat /var/log/letsencrypt/letsencrypt.log | tail -100

# Dry-run to see exact error
sudo certbot renew --dry-run --cert-name gwallofchina.yulcyberhub.click -v
```

### Step 3 — Check IAM Role (Most Common Cause)

```bash
# Verify IMDSv2 token works
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Verify IAM role is attached
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/info

# Test Route 53 permissions directly
aws route53 list-hosted-zones \
  --profile MEQ7_RBAC_Room3-453875232433
# Expected: zone Z0433076DMIP84BGAZGN in the list
```

### Step 4 — Check Route 53 Propagation Timing

```bash
# Increase propagation wait if DNS is slow
sudo certbot renew \
  --dns-route53 \
  --dns-route53-propagation-seconds 120 \
  --cert-name gwallofchina.yulcyberhub.click
```

### Step 5 — Force Renewal

```bash
# Force renew even if not near expiry
sudo certbot renew \
  --force-renewal \
  --dns-route53 \
  --dns-route53-propagation-seconds 120 \
  --cert-name gwallofchina.yulcyberhub.click
```

### Step 6 — If Let's Encrypt Rate Limited (5 certs/week exceeded)

```bash
# Check rate limit status at: https://crt.sh/?q=gwallofchina.yulcyberhub.click
# Use staging environment to test without consuming quota
sudo certbot certonly \
  --dns-route53 \
  --staging \
  -d gwallofchina.yulcyberhub.click \
  -d mail.gwallofchina.yulcyberhub.click \
  -d mta-sts.gwallofchina.yulcyberhub.click

# Wait 7 days for rate limit to reset, then issue real cert
```

### Step 7 — Reload Services After Renewal

```bash
sudo systemctl reload nginx
sudo systemctl reload postfix
sudo systemctl reload dovecot

# Verify new cert is live
echo | openssl s_client -connect gwallofchina.yulcyberhub.click:443 \
  -servername gwallofchina.yulcyberhub.click 2>/dev/null \
  | openssl x509 -noout -dates
```

### Step 8 — Verify Timer is Active

```bash
sudo systemctl is-active certbot-renew.timer
sudo systemctl status certbot-renew.timer
sudo systemctl list-timers certbot-renew.timer
```

**Resolution time target:** < 30 minutes

---

## Playbook 02 — Instance Unreachable / Server Down

**Symptoms:**
- `ping 54.226.198.180` times out
- SSH connection refused or times out
- HTTPS returns no response
- All services unreachable

**Severity:** 🔴 Critical — full outage

---

### Step 1 — Check Instance State from AWS Console / CLI

```bash
aws ec2 describe-instance-status \
  --instance-ids i-0b71d405f8ad5f73b \
  --profile MEQ7_RBAC_Room3-453875232433 \
  --output table

# Look for:
# InstanceState: running / stopped / terminated
# SystemStatus: ok / impaired
# InstanceStatus: ok / impaired
```

### Step 2 — If Instance is Running but Unreachable (OS Hang)

```bash
# Stop and start — forces migration to new physical host
# NOTE: stop/start, NOT reboot (reboot stays on same hardware)
aws ec2 stop-instances \
  --instance-ids i-0b71d405f8ad5f73b \
  --profile MEQ7_RBAC_Room3-453875232433

# Wait for stopped state
aws ec2 wait instance-stopped \
  --instance-ids i-0b71d405f8ad5f73b \
  --profile MEQ7_RBAC_Room3-453875232433

aws ec2 start-instances \
  --instance-ids i-0b71d405f8ad5f73b \
  --profile MEQ7_RBAC_Room3-453875232433

aws ec2 wait instance-running \
  --instance-ids i-0b71d405f8ad5f73b \
  --profile MEQ7_RBAC_Room3-453875232433
```

### Step 3 — Verify Elastic IP is Still Associated

```bash
aws ec2 describe-addresses \
  --profile MEQ7_RBAC_Room3-453875232433 \
  --query 'Addresses[?PublicIp==`54.226.198.180`]'

# If InstanceId is missing — re-associate
aws ec2 associate-address \
  --instance-id i-0b71d405f8ad5f73b \
  --public-ip 54.226.198.180 \
  --profile MEQ7_RBAC_Room3-453875232433
```

### Step 4 — Get Console Output (No SSH Needed)

```bash
# View last 64KB of serial console output
aws ec2 get-console-output \
  --instance-id i-0b71d405f8ad5f73b \
  --profile MEQ7_RBAC_Room3-453875232433 \
  --output text | tail -100

# Look for: kernel panic, OOM killer, filesystem errors
```

### Step 5 — If Instance State is Stopped (Unexpected)

```bash
# Check CloudTrail for who stopped it
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=i-0b71d405f8ad5f73b \
  --start-time $(date -d '24 hours ago' --iso-8601=seconds) \
  --profile MEQ7_RBAC_Room3-453875232433

# Start it back up
aws ec2 start-instances \
  --instance-ids i-0b71d405f8ad5f73b \
  --profile MEQ7_RBAC_Room3-453875232433
```

### Step 6 — If Instance is Terminated

> **This is the worst case.** Go to [Playbook 12](#playbook-12--full-instance-recovery-from-snapshot).

### Step 7 — Once SSH is Available — Check Services

```bash
ssh -i thegreatfirewallofchina.pem rocky@54.226.198.180

# Check all critical services
sudo systemctl status nginx postfix dovecot opendkim

# Restart anything that is not active
sudo systemctl start nginx postfix dovecot opendkim

# Check for errors
sudo journalctl -u nginx --since "1 hour ago"
sudo journalctl -u postfix --since "1 hour ago"
```

**Resolution time target:** < 15 minutes (stop/start) · < 60 minutes (full recovery)

---

## Playbook 03 — Elastic IP Lost or IP Address Changed

**Symptoms:**
- DNS resolves to wrong IP
- Certificate mismatch errors (cert is issued to old IP's domain)
- Mail bouncing — SPF fail (`54.226.198.180` no longer the sending IP)
- DNSSEC validation errors

**Severity:** 🔴 Critical — all external services broken

---

### Step 1 — Find Your Elastic IP Allocation

```bash
# List all Elastic IPs in account
aws ec2 describe-addresses \
  --profile MEQ7_RBAC_Room3-453875232433 \
  --output table

# If 54.226.198.180 is listed but not associated:
aws ec2 associate-address \
  --instance-id i-0b71d405f8ad5f73b \
  --public-ip 54.226.198.180 \
  --profile MEQ7_RBAC_Room3-453875232433

# Verify association
aws ec2 describe-addresses \
  --filters Name=public-ip,Values=54.226.198.180 \
  --profile MEQ7_RBAC_Room3-453875232433
```

### Step 2 — If Elastic IP Was Released (Worst Case)

```bash
# Allocate a new Elastic IP
NEW_EIP=$(aws ec2 allocate-address \
  --domain vpc \
  --profile MEQ7_RBAC_Room3-453875232433 \
  --query 'PublicIp' --output text)

echo "New EIP: $NEW_EIP"

# Associate to instance
aws ec2 associate-address \
  --instance-id i-0b71d405f8ad5f73b \
  --public-ip "$NEW_EIP" \
  --profile MEQ7_RBAC_Room3-453875232433
```

### Step 3 — Update DNS Records in Route 53

```bash
NEW_IP="<your-new-ip>"

# Update all A records pointing to the old IP
for RECORD in "gwallofchina.yulcyberhub.click" "mail.gwallofchina.yulcyberhub.click" "mta-sts.gwallofchina.yulcyberhub.click"; do
  aws route53 change-resource-record-sets \
    --hosted-zone-id Z0433076DMIP84BGAZGN \
    --profile MEQ7_RBAC_Room3-453875232433 \
    --change-batch "{
      \"Changes\": [{
        \"Action\": \"UPSERT\",
        \"ResourceRecordSet\": {
          \"Name\": \"${RECORD}\",
          \"Type\": \"A\",
          \"TTL\": 300,
          \"ResourceRecords\": [{\"Value\": \"${NEW_IP}\"}]
        }
      }]
    }"
  echo "Updated: $RECORD → $NEW_IP"
done
```

### Step 4 — Update SPF Record

```bash
# SPF is tied to your sending IP — must be updated
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
        \"ResourceRecords\": [{
          \"Value\": \"\\\"v=spf1 ip4:${NEW_IP} include:sendgrid.net mx ~all\\\"\"
        }]
      }
    }]
  }"
```

### Step 5 — Update Postfix mynetworks

```bash
ssh -i thegreatfirewallofchina.pem rocky@"$NEW_IP"

sudo postconf -e "mynetworks = 127.0.0.0/8 ${NEW_IP}/32"
sudo systemctl reload postfix
```

### Step 6 — Certificate is Still Valid (No Change Needed)

> Your cert is domain-based (`gwallofchina.yulcyberhub.click`), not IP-based.
> Once DNS propagates (TTL 300 = ~5 min), the cert will work automatically.

### Step 7 — Verify DNS Propagation

```bash
# Check from multiple resolvers
dig A gwallofchina.yulcyberhub.click @8.8.8.8
dig A gwallofchina.yulcyberhub.click @1.1.1.1
dig A mail.gwallofchina.yulcyberhub.click @8.8.8.8

# Verify SPF update
dig TXT gwallofchina.yulcyberhub.click | grep spf
```

**Resolution time target:** < 20 minutes + DNS TTL propagation (5 min)

---

## Playbook 04 — SSH Key Lost / Locked Out of Server

**Symptoms:**
- `Permission denied (publickey)` on SSH
- PEM file missing or corrupted
- New team member needs access

**Severity:** 🟠 High — no direct server access, services still running

---

### Step 1 — Use EC2 Instance Connect (Primary Recovery Method)

```bash
# Generate a temporary keypair on your local machine
ssh-keygen -t ed25519 -f /tmp/recovery_key -N ""

# Push the public key to the instance (valid for 60 seconds)
aws ec2-instance-connect send-ssh-public-key \
  --instance-id i-0b71d405f8ad5f73b \
  --instance-os-user rocky \
  --ssh-public-key file:///tmp/recovery_key.pub \
  --availability-zone us-east-1a \
  --profile MEQ7_RBAC_Room3-453875232433

# SSH in immediately (within 60 seconds of the above command)
ssh -i /tmp/recovery_key rocky@54.226.198.180
```

### Step 2 — Once In, Add Your New Permanent Key

```bash
# On your local machine, generate a new permanent keypair
ssh-keygen -t ed25519 -f ~/.ssh/gwall_new_key -C "gwall-recovery-$(date +%Y%m%d)"

# Copy the public key content
cat ~/.ssh/gwall_new_key.pub

# On the server (via recovery session), add the new key
echo "<paste-your-new-public-key>" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Test the new key from a second terminal before closing recovery session
ssh -i ~/.ssh/gwall_new_key rocky@54.226.198.180
```

### Step 3 — Store the New Key Securely in S3

```bash
# Encrypt and upload to S3 using your existing KMS key
aws kms encrypt \
  --key-id arn:aws:kms:us-east-1:453875232433:key/df174539-... \
  --plaintext fileb://~/.ssh/gwall_new_key \
  --output text --query CiphertextBlob \
  --profile MEQ7_RBAC_Room3-453875232433 \
  | base64 --decode > gwall_new_key.encrypted

aws s3 cp gwall_new_key.encrypted \
  s3://your-backup-bucket/ssh-keys/gwall_new_key.encrypted \
  --server-side-encryption aws:kms \
  --profile MEQ7_RBAC_Room3-453875232433
```

### Step 4 — If EC2 Instance Connect Also Fails

```bash
# Verify the IAM policy allows ec2-instance-connect:SendSSHPublicKey
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::453875232433:user/<your-user> \
  --action-names ec2-instance-connect:SendSSHPublicKey \
  --resource-arns arn:aws:ec2:us-east-1:453875232433:instance/i-0b71d405f8ad5f73b \
  --profile MEQ7_RBAC_Room3-453875232433

# If denied — fix the policy, then retry Step 1
```

### Step 5 — If Instance Connect Is Not Available (Last Resort)

```bash
# Stop the instance
aws ec2 stop-instances --instance-ids i-0b71d405f8ad5f73b \
  --profile MEQ7_RBAC_Room3-453875232433
aws ec2 wait instance-stopped --instance-ids i-0b71d405f8ad5f73b \
  --profile MEQ7_RBAC_Room3-453875232433

# Detach the root volume
VOLUME_ID=$(aws ec2 describe-instances \
  --instance-ids i-0b71d405f8ad5f73b \
  --query 'Reservations[].Instances[].BlockDeviceMappings[?DeviceName==`/dev/xvda`].Ebs.VolumeId' \
  --output text --profile MEQ7_RBAC_Room3-453875232433)

aws ec2 detach-volume --volume-id "$VOLUME_ID" \
  --profile MEQ7_RBAC_Room3-453875232433

# Attach to a rescue instance, mount, edit authorized_keys, reattach
# This is a last resort — go to Playbook 12 instead if possible
```

**Resolution time target:** < 10 minutes (Instance Connect) · < 60 minutes (volume rescue)

---

## Playbook 05 — Disk Full

**Symptoms:**
- Services writing errors: `No space left on device`
- Mail queue growing but not delivering
- Nginx logs stopped writing
- SSH login hangs

**Severity:** 🟠 High — services degrading

---

### Step 1 — Check What's Full

```bash
ssh -i thegreatfirewallofchina.pem rocky@54.226.198.180

# Check all filesystems
df -hT

# Find the biggest consumers
sudo du -sh /* 2>/dev/null | sort -rh | head -20
sudo du -sh /var/* 2>/dev/null | sort -rh | head -20
sudo du -sh /var/log/* 2>/dev/null | sort -rh | head -10
```

### Step 2 — Quick Wins (Mail Queue)

```bash
# Check mail queue size
sudo postqueue -p | tail -1

# How much space is the queue using
sudo du -sh /var/spool/postfix/

# If queue is massive and stuck — flush or purge
sudo postqueue -f          # flush (attempt delivery now)
sudo postsuper -d ALL      # nuclear — delete ALL queued mail
```

### Step 3 — Quick Wins (Logs)

```bash
# Check log sizes
sudo du -sh /var/log/*

# Rotate logs immediately
sudo logrotate -f /etc/logrotate.conf

# Clear old compressed logs (>30 days)
sudo find /var/log -name "*.gz" -mtime +30 -delete
sudo find /var/log -name "*.1" -mtime +7 -delete

# Vacuum journald
sudo journalctl --vacuum-size=200M
sudo journalctl --vacuum-time=14d
```

### Step 4 — Quick Wins (Mail Storage)

```bash
# Check vmail storage
sudo du -sh /var/mail/vhosts/

# Per-user breakdown
sudo du -sh /var/mail/vhosts/gwallofchina.yulcyberhub.click/*/

# If a mailbox is enormous — check for spam or loop
sudo du -sh /var/mail/vhosts/gwallofchina.yulcyberhub.click/*/Maildir/new/
```

### Step 5 — Expand EBS Volume (Permanent Fix)

```bash
# From your local machine — expand the volume
VOLUME_ID=$(aws ec2 describe-instances \
  --instance-ids i-0b71d405f8ad5f73b \
  --query 'Reservations[].Instances[].BlockDeviceMappings[0].Ebs.VolumeId' \
  --output text --profile MEQ7_RBAC_Room3-453875232433)

# Resize — no downtime required on Nitro instances
aws ec2 modify-volume \
  --volume-id "$VOLUME_ID" \
  --size 30 \
  --profile MEQ7_RBAC_Room3-453875232433

# On the server — grow the partition (no reboot needed)
sudo growpart /dev/nvme0n1 1
sudo xfs_growfs /          # for XFS (Rocky Linux default)
# OR
sudo resize2fs /dev/nvme0n1p1  # for ext4

# Verify
df -hT
```

### Step 6 — Set Up Log Rotation (Prevent Recurrence)

```bash
sudo tee /etc/logrotate.d/gwall << 'EOF'
/var/log/nginx/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    sharedscripts
    postrotate
        systemctl reload nginx > /dev/null 2>&1 || true
    endscript
}

/var/log/maillog {
    daily
    rotate 14
    compress
    missingok
    postrotate
        systemctl reload postfix > /dev/null 2>&1 || true
    endscript
}
EOF
```

**Resolution time target:** < 15 minutes (cleanup) · < 30 minutes (EBS expand)

---

## Playbook 06 — Mail Delivery Failing (SPF / DKIM / DMARC)

**Symptoms:**
- Mail bouncing with `550 5.7.26` or similar
- Recipients getting spam classification
- `dkim=fail`, `spf=fail`, or `dmarc=fail` in headers
- OpenDKIM not signing

**Severity:** 🟠 High — outbound mail broken

---

### Step 1 — Identify Which Check Is Failing

```bash
# Send a test to Port25 auto-checker
echo "auth test" | mail -s "Auth Test $(date)" \
  -r sroy@gwallofchina.yulcyberhub.click \
  check-auth@verifier.port25.com

# Check mail logs for the result
sudo tail -f /var/log/maillog
```

### Step 2 — Diagnose SPF

```bash
# Verify SPF record is correct
dig TXT gwallofchina.yulcyberhub.click | grep spf

# Expected:
# "v=spf1 ip4:54.226.198.180 include:sendgrid.net mx ~all"

# Check what IP mail is actually being sent FROM
sudo grep "status=sent" /var/log/maillog | tail -5

# If IP changed — see Playbook 03
```

### Step 3 — Diagnose DKIM

```bash
# Check OpenDKIM is running
sudo systemctl status opendkim

# Test the key
sudo opendkim-testkey -d gwallofchina.yulcyberhub.click -s mail -vvv
# Expected: key OK

# Check the DNS record
dig TXT mail._domainkey.gwallofchina.yulcyberhub.click

# Verify milter is connected to Postfix
sudo postconf smtpd_milters non_smtpd_milters
# Expected: inet:localhost:8891

# Check OpenDKIM socket is listening
sudo ss -tlnp | grep 8891
```

### Step 4 — Restart OpenDKIM and Postfix

```bash
sudo systemctl restart opendkim
sudo systemctl restart postfix

# Watch logs for signing confirmation
sudo tail -f /var/log/maillog | grep -i dkim
# Expected: dkim=pass after sending a test
```

### Step 5 — Diagnose DMARC

```bash
# Check DMARC record
dig TXT _dmarc.gwallofchina.yulcyberhub.click
# Expected: v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s

# DMARC passes only if BOTH SPF and DKIM pass AND align
# adkim=s means DKIM d= must exactly match From: domain
# aspf=s means envelope sender must match From: domain
# Verify From: header matches gwallofchina.yulcyberhub.click
```

### Step 6 — Check for Placeholder DKIM Record

```bash
# This was a known issue — verify it's still gone
dig TXT default._domainkey.gwallofchina.yulcyberhub.click
# Expected: status: NXDOMAIN
# If it returns data — delete it again (see §2.3 of README)
```

### Step 7 — Full Auth Test After Fixes

```bash
# Send to Gmail and inspect headers
echo "Full auth test" | mail -s "DKIM/SPF/DMARC Test" \
  -r sroy@gwallofchina.yulcyberhub.click \
  your.gmail@gmail.com

# In Gmail: open message → three-dot → Show original
# Expected:
# dkim=pass header.i=@gwallofchina.yulcyberhub.click header.s=mail
# spf=pass ... designates 54.226.198.180 as permitted sender
# dmarc=pass (p=REJECT sp=REJECT dis=NONE)
```

**Resolution time target:** < 20 minutes

---

## Playbook 07 — Nginx Down / HTTPS Not Responding

**Symptoms:**
- `curl -I https://gwallofchina.yulcyberhub.click` times out or connection refused
- Browser shows `ERR_CONNECTION_REFUSED`
- Port 443 not listening

**Severity:** 🔴 Critical — web and webmail down

---

### Step 1 — Check Nginx Status

```bash
ssh -i thegreatfirewallofchina.pem rocky@54.226.198.180

sudo systemctl status nginx
sudo journalctl -u nginx --since "30 minutes ago"
```

### Step 2 — Test Config Before Restarting

```bash
# ALWAYS test config first — a bad config will prevent restart
sudo nginx -t

# If config test fails — check for recent changes
sudo git -C /etc/nginx log --oneline -5 2>/dev/null || \
  ls -lt /etc/nginx/conf.d/
```

### Step 3 — Common Config Errors and Fixes

```bash
# Error: "bind() to 0.0.0.0:443 failed (98: Address already in use)"
sudo ss -tlnp | grep 443
# If another process is on 443 — find and kill it
sudo fuser -k 443/tcp

# Error: "SSL_CTX_use_certificate_file failed"
# Certificate file missing or wrong path
sudo ls -la /etc/letsencrypt/live/gwallofchina.yulcyberhub.click/
# If missing — run certbot (Playbook 01)

# Error: "cannot load certificate key"
# Permission issue on private key
sudo stat /etc/letsencrypt/live/gwallofchina.yulcyberhub.click/privkey.pem
# Fix permissions
sudo chgrp ssl-cert /etc/letsencrypt/archive/gwallofchina.yulcyberhub.click/privkey*.pem
sudo chmod 640 /etc/letsencrypt/archive/gwallofchina.yulcyberhub.click/privkey*.pem
```

### Step 4 — Restart Nginx

```bash
sudo systemctl restart nginx
sudo systemctl status nginx

# Verify ports are listening
sudo ss -tlnp | grep -E ':(80|443)'
```

### Step 5 — Verify from Outside

```bash
# From your local machine
curl -I https://gwallofchina.yulcyberhub.click
# Expected: HTTP/2 200

curl -I http://gwallofchina.yulcyberhub.click
# Expected: HTTP/1.1 301 Moved Permanently

# Check TLS is working
echo | openssl s_client -connect gwallofchina.yulcyberhub.click:443 \
  -servername gwallofchina.yulcyberhub.click 2>/dev/null \
  | openssl x509 -noout -subject -dates
```

**Resolution time target:** < 10 minutes

---

## Playbook 08 — Postfix / Mail Queue Stuck

**Symptoms:**
- Outbound mail not delivering
- Mail queue growing: `sudo postqueue -p | wc -l` increasing
- Senders getting delayed delivery notices
- Logs showing connection timeouts

**Severity:** 🟠 High — outbound mail queued, not delivered

---

### Step 1 — Inspect the Queue

```bash
ssh -i thegreatfirewallofchina.pem rocky@54.226.198.180

# Queue summary
sudo postqueue -p

# Queue size (number of messages)
sudo postqueue -p | grep -c "^[0-9A-F]"

# View a specific queued message
sudo postcat -q <queue-id>
```

### Step 2 — Check Why Messages Are Stuck

```bash
# Tail mail logs for delivery errors
sudo tail -100 /var/log/maillog | grep -E "error|deferred|timeout|refused"

# Common errors:
# "Connection timed out" — port 25 blocked by AWS (get port 25 unblocked)
# "Host or domain name not found" — DNS issue
# "Connection refused" — recipient server blocking you
# "Service unavailable" — SendGrid fallback not working
```

### Step 3 — Check Port 25 Outbound

```bash
# Test if port 25 outbound is open
# (AWS blocks port 25 by default on new accounts)
telnet smtp.gmail.com 25
# If connection hangs — port 25 is blocked

# Test SendGrid fallback on 587
telnet smtp.sendgrid.net 587
# This should connect even if 25 is blocked

# Check fallback relay config
sudo postconf relayhost fallback_relay
```

### Step 4 — Flush the Queue

```bash
# Attempt immediate delivery of all queued messages
sudo postqueue -f

# Monitor the result
sudo tail -f /var/log/maillog
```

### Step 5 — If Messages Are Truly Stuck (Undeliverable)

```bash
# List all deferred messages
sudo postqueue -p | grep "^[0-9A-F]" | awk '{print $1}'

# Delete all deferred messages (nuclear option)
sudo postsuper -d ALL deferred

# Delete specific message
sudo postsuper -d <queue-id>
```

### Step 6 — Check OpenDKIM Milter Connection

```bash
# If milter is failing, Postfix queues everything
sudo systemctl status opendkim
sudo ss -tlnp | grep 8891

# If milter is down and milter_default_action = reject, mail is rejected
# Verify setting
sudo postconf milter_default_action
# Should be: accept (so mail goes through even if milter is down)
```

### Step 7 — Restart Postfix

```bash
sudo systemctl restart postfix
sudo systemctl status postfix

# Verify ports
sudo ss -tlnp | grep -E ':(25|465|587)'
```

**Resolution time target:** < 15 minutes

---

## Playbook 09 — Dovecot / IMAP Down

**Symptoms:**
- Mail clients cannot connect on port 993
- Webmail cannot load inbox
- `openssl s_client -connect mail.gwallofchina.yulcyberhub.click:993` fails
- `sudo ss -tlnp | grep 993` returns nothing

**Severity:** 🟠 High — inbound mail reading broken (delivery still works)

---

### Step 1 — Check Dovecot Status

```bash
ssh -i thegreatfirewallofchina.pem rocky@54.226.198.180

sudo systemctl status dovecot
sudo journalctl -u dovecot --since "30 minutes ago"
```

### Step 2 — Test Auth

```bash
# Test authentication directly
sudo doveadm auth test sroy@gwallofchina.yulcyberhub.click
# Enter password when prompted
# Expected: passdb: sroy@gwallofchina.yulcyberhub.click auth succeeded
```

### Step 3 — Common Dovecot Errors and Fixes

```bash
# Error: "SSL certificate not found"
sudo ls /etc/letsencrypt/live/gwallofchina.yulcyberhub.click/
# If missing — Playbook 01

# Error: "Permission denied" on ssl_cert
sudo stat /etc/letsencrypt/live/gwallofchina.yulcyberhub.click/fullchain.pem
# Dovecot needs to be in ssl-cert group
sudo usermod -aG ssl-cert dovecot
sudo systemctl restart dovecot

# Error: "chown: changing ownership of /var/mail/vhosts"
sudo ls -la /var/mail/
sudo chown -R vmail:vmail /var/mail/vhosts/
sudo chmod 755 /var/mail /var/mail/vhosts/
```

### Step 4 — Restart Dovecot

```bash
sudo systemctl restart dovecot
sudo systemctl status dovecot

# Verify port 993 is listening
sudo ss -tlnp | grep 993
```

### Step 5 — Test IMAP Connection

```bash
# From your local machine
openssl s_client -connect mail.gwallofchina.yulcyberhub.click:993 -quiet
# Expected: "* OK [...] Dovecot ready."
# Type: a1 LOGIN user@gwallofchina.yulcyberhub.click password
# Expected: a1 OK Logged in
```

**Resolution time target:** < 10 minutes

---

## Playbook 10 — OpenDKIM Signing Failure

**Symptoms:**
- Mail arrives at recipients with `dkim=neutral` or `dkim=fail`
- `sudo systemctl status opendkim` shows failed
- Exit code 78 on startup
- Mail logs: `Milter (inet:localhost:8891): to error state`

**Severity:** 🟠 High — DMARC will fail, mail may be rejected

---

### Step 1 — Check OpenDKIM Status

```bash
ssh -i thegreatfirewallofchina.pem rocky@54.226.198.180

sudo systemctl status opendkim
sudo journalctl -u opendkim --since "1 hour ago"
```

### Step 2 — Test the Key

```bash
sudo opendkim-testkey -d gwallofchina.yulcyberhub.click -s mail -vvv
# Expected: key OK

# If "key not secure" — check permissions
sudo ls -la /etc/opendkim/keys/gwallofchina.yulcyberhub.click/
sudo chmod 600 /etc/opendkim/keys/gwallofchina.yulcyberhub.click/mail.private
sudo chown opendkim:opendkim /etc/opendkim/keys/gwallofchina.yulcyberhub.click/mail.private
```

### Step 3 — Common OpenDKIM Errors and Fixes

```bash
# Error: exit code 78 / "TrustAnchorFile"
# This is a known Rocky Linux 10 bug
sudo grep TrustAnchorFile /etc/opendkim.conf
# If present — remove it
sudo sed -i '/TrustAnchorFile/d' /etc/opendkim.conf

# Error: "signing table references unknown key"
# KeyTable is empty or wrong format
sudo cat /etc/opendkim/KeyTable
# Expected:
# mail._domainkey.gwallofchina.yulcyberhub.click gwallofchina.yulcyberhub.click:mail:/etc/opendkim/keys/gwallofchina.yulcyberhub.click/mail.private

sudo cat /etc/opendkim/SigningTable
# Expected:
# *@gwallofchina.yulcyberhub.click mail._domainkey.gwallofchina.yulcyberhub.click

# Error: milter socket not listening
sudo ss -tlnp | grep 8891
# If nothing — OpenDKIM is not running, restart it
```

### Step 4 — Restart OpenDKIM and Postfix

```bash
sudo systemctl restart opendkim
sudo ss -tlnp | grep 8891  # Verify socket is up
sudo systemctl restart postfix

# Send a test and check logs
echo "DKIM test" | mail -s "DKIM Test" \
  -r sroy@gwallofchina.yulcyberhub.click \
  check-auth@verifier.port25.com

sudo tail -f /var/log/maillog | grep -i dkim
```

**Resolution time target:** < 15 minutes

---

## Playbook 11 — DNSSEC Broken / DNS Not Resolving

**Symptoms:**
- `dig +dnssec gwallofchina.yulcyberhub.click` returns no `ad` flag
- `delv @1.1.1.1 gwallofchina.yulcyberhub.click` shows validation failure
- Some resolvers reject responses
- Email from some domains bouncing with DNS errors

**Severity:** 🟠 High — DNSSEC validation failing for some resolvers

---

### Step 1 — Check DNSSEC Status

```bash
# From your local machine
dig +dnssec MX gwallofchina.yulcyberhub.click @8.8.8.8
# Expected: flags include "ad"

delv @1.1.1.1 gwallofchina.yulcyberhub.click
# Expected: "; fully validated"

# Check DNSViz for visual chain analysis
# https://dnsviz.net/d/gwallofchina.yulcyberhub.click/dnssec/
```

### Step 2 — Check KMS Key Status

```bash
aws kms describe-key \
  --key-id arn:aws:kms:us-east-1:453875232433:key/df174539-... \
  --profile MEQ7_RBAC_Room3-453875232433 \
  --query 'KeyMetadata.{State:KeyState,Enabled:Enabled}'
# Expected: State=Enabled, Enabled=true

# Check Route 53 DNSSEC signing status
aws route53 get-dnssec \
  --hosted-zone-id Z0433076DMIP84BGAZGN \
  --profile MEQ7_RBAC_Room3-453875232433
```

### Step 3 — Check DS Record in Parent Zone

```bash
# The DS record must exist in yulcyberhub.click (Oracle's zone)
dig DS gwallofchina.yulcyberhub.click @8.8.8.8
# Expected: DS record with key tag 11486

# If DS record is missing — contact Oracle to re-insert
# DS value: 11486 13 2 5D8E98E506AB70F3CF69286813298312235CA86318D376D221D964A26A2B98A7
```

### Step 4 — If KMS Key Permissions Are Broken

```bash
# Re-add Route 53 as permitted principal on the KMS key
aws kms create-grant \
  --key-id arn:aws:kms:us-east-1:453875232433:key/df174539-... \
  --grantee-principal dnssec-route53.amazonaws.com \
  --operations DescribeKey GetPublicKey Sign \
  --profile MEQ7_RBAC_Room3-453875232433
```

### Step 5 — Emergency — Disable DNSSEC (Last Resort Only)

> ⚠️ Only do this if DNSSEC is actively breaking resolution for users.
> Disabling removes the security guarantee entirely.

```bash
# Contact Oracle first to remove DS record from parent zone
# Then disable signing in Route 53
aws route53 disable-hosted-zone-dnssec \
  --hosted-zone-id Z0433076DMIP84BGAZGN \
  --profile MEQ7_RBAC_Room3-453875232433
```

**Resolution time target:** < 30 minutes (own zone) · Depends on Oracle (parent DS)

---

## Playbook 12 — Full Instance Recovery from Snapshot

**Symptoms:**
- Instance terminated
- Data corrupted beyond repair
- Need to rebuild in a new AZ

**Severity:** 🔴 Critical — full rebuild required

---

### Step 1 — Find the Latest AMI Snapshot

```bash
aws ec2 describe-images \
  --owners self \
  --filters "Name=name,Values=gwall-backup-*" \
  --query 'sort_by(Images, &CreationDate)[-1].{ID:ImageId,Name:Name,Date:CreationDate}' \
  --profile MEQ7_RBAC_Room3-453875232433
```

### Step 2 — Launch New Instance from AMI

```bash
LATEST_AMI="<ami-id-from-above>"

aws ec2 run-instances \
  --image-id "$LATEST_AMI" \
  --instance-type t4g.small \
  --key-name thegreatfirewallofchina \
  --security-group-ids sg-0c7a7efce68ce2773 \
  --iam-instance-profile Name=meq7-ec2-role-frontend-room3 \
  --metadata-options '{"HttpTokens":"required"}' \
  --tag-specifications '{"ResourceType":"instance","Tags":[{"Key":"Name","Value":"gwall-recovered"}]}' \
  --profile MEQ7_RBAC_Room3-453875232433
```

### Step 3 — Re-Associate Elastic IP

```bash
NEW_INSTANCE_ID="<instance-id-from-above>"

# Wait for instance to be running
aws ec2 wait instance-running \
  --instance-ids "$NEW_INSTANCE_ID" \
  --profile MEQ7_RBAC_Room3-453875232433

# Re-associate the Elastic IP
aws ec2 associate-address \
  --instance-id "$NEW_INSTANCE_ID" \
  --public-ip 54.226.198.180 \
  --profile MEQ7_RBAC_Room3-453875232433
```

### Step 4 — Verify Services on New Instance

```bash
ssh -i thegreatfirewallofchina.pem rocky@54.226.198.180

# Check all services
sudo systemctl status nginx postfix dovecot opendkim

# Start any that are down
sudo systemctl start nginx postfix dovecot opendkim

# Check cert is valid
sudo certbot certificates

# Check mail queue
sudo postqueue -p
```

### Step 5 — If EBS Mail Volume Needs Restoration

```bash
# Find latest EBS snapshot
aws ec2 describe-snapshots \
  --owner-ids self \
  --filters "Name=description,Values=gwall-mail-*" \
  --query 'sort_by(Snapshots, &StartTime)[-1].{ID:SnapshotId,Date:StartTime}' \
  --profile MEQ7_RBAC_Room3-453875232433

# Create volume from snapshot
aws ec2 create-volume \
  --snapshot-id <snapshot-id> \
  --availability-zone us-east-1a \
  --volume-type gp3 \
  --profile MEQ7_RBAC_Room3-453875232433

# Attach to new instance
aws ec2 attach-volume \
  --volume-id <new-volume-id> \
  --instance-id "$NEW_INSTANCE_ID" \
  --device /dev/sdf \
  --profile MEQ7_RBAC_Room3-453875232433
```

### Step 6 — Run Full Verification

```bash
# Web
curl -I https://gwallofchina.yulcyberhub.click

# Mail TLS
openssl s_client -connect mail.gwallofchina.yulcyberhub.click:993 -quiet

# DKIM
sudo opendkim-testkey -d gwallofchina.yulcyberhub.click -s mail -vvv

# DNSSEC
dig +dnssec MX gwallofchina.yulcyberhub.click | grep "ad"

# Send a test email
echo "Recovery test" | mail -s "Post-Recovery Test" \
  -r sroy@gwallofchina.yulcyberhub.click \
  check-auth@verifier.port25.com
```

**Resolution time target:** < 60 minutes from snapshot

---

## Playbook 13 — Security Group Misconfiguration / Port Locked Out

**Symptoms:**
- Can no longer SSH (port 22 accidentally removed)
- HTTPS stopped working (port 443 removed)
- Mail stopped (port 25/465/993 removed)

**Severity:** 🔴 Critical if SSH lost · 🟠 High for service ports

---

### Step 1 — Restore SSH Access (Port 22)

```bash
# From your local machine — no SSH needed to fix security groups
YOUR_IP=$(curl -s https://checkip.amazonaws.com)/32

aws ec2 authorize-security-group-ingress \
  --group-id sg-0c7a7efce68ce2773 \
  --protocol tcp \
  --port 22 \
  --cidr "$YOUR_IP" \
  --profile MEQ7_RBAC_Room3-453875232433
```

### Step 2 — Restore All Required Ports

```bash
# Full security group restore script
SG="sg-0c7a7efce68ce2773"
PROFILE="MEQ7_RBAC_Room3-453875232433"

for PORT in 25 80 443 465 587 993; do
  aws ec2 authorize-security-group-ingress \
    --group-id "$SG" \
    --protocol tcp \
    --port "$PORT" \
    --cidr 0.0.0.0/0 \
    --profile "$PROFILE" 2>/dev/null && echo "✅ Port $PORT restored" \
    || echo "ℹ️  Port $PORT already exists"
done
```

### Step 3 — Verify Current Rules

```bash
aws ec2 describe-security-groups \
  --group-ids sg-0c7a7efce68ce2773 \
  --query 'SecurityGroups[0].IpPermissions[*].{Port:FromPort,CIDR:IpRanges[0].CidrIp}' \
  --profile MEQ7_RBAC_Room3-453875232433 \
  --output table
```

**Resolution time target:** < 5 minutes

---

## Playbook 14 — IAM Role / Permission Failure

**Symptoms:**
- `certbot renew` fails with `AccessDenied` on Route 53
- `aws` CLI commands from the instance return permission errors
- IMDSv2 metadata not returning IAM credentials

**Severity:** 🟠 High — cert renewal and AWS operations broken

---

### Step 1 — Verify IAM Role is Attached

```bash
# On the instance
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/info
# Expected: "InstanceProfileArn": "...meq7-ec2-role-frontend-room3..."

# Get temporary credentials
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/meq7-ec2-role-frontend-room3
# Expected: AccessKeyId, SecretAccessKey, Token, Expiration
```

### Step 2 — If Role is Not Attached

```bash
# From your local machine — attach the role
aws ec2 associate-iam-instance-profile \
  --instance-id i-0b71d405f8ad5f73b \
  --iam-instance-profile Name=meq7-ec2-role-frontend-room3 \
  --profile MEQ7_RBAC_Room3-453875232433
```

### Step 3 — Verify Route 53 Permissions on the Role

```bash
# Simulate what the instance role can do
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::453875232433:instance-profile/meq7-ec2-role-frontend-room3 \
  --action-names route53:ChangeResourceRecordSets route53:ListHostedZones route53:GetChange \
  --resource-arns "*" \
  --profile MEQ7_RBAC_Room3-453875232433
# Expected: EvalDecision = allowed for all three
```

### Step 4 — Test Certbot Renewal

```bash
sudo certbot renew --dry-run --cert-name gwallofchina.yulcyberhub.click
# If still failing after role fix — check the renewal config
sudo cat /etc/letsencrypt/renewal/gwallofchina.yulcyberhub.click.conf | grep authenticator
# Expected: authenticator = dns-route53
```

**Resolution time target:** < 20 minutes

---

## Playbook 15 — Daily Health Check (Preventive)

Run this every morning. Add it as a cron job or run it manually.

```bash
#!/bin/bash
# /usr/local/bin/gwall-healthcheck.sh
# Run daily: 0 8 * * * rocky /usr/local/bin/gwall-healthcheck.sh

DOMAIN="gwallofchina.yulcyberhub.click"
MAIL_DOMAIN="mail.gwallofchina.yulcyberhub.click"
ALERT_EMAIL="sroy@gwallofchina.yulcyberhub.click"
PASS="✅"
FAIL="❌"
WARN="⚠️"
REPORT=""

echo "=============================="
echo " Great Wall Daily Health Check"
echo " $(date)"
echo "=============================="

# 1. Certificate expiry
EXPIRY=$(echo | openssl s_client -connect ${DOMAIN}:443 \
  -servername ${DOMAIN} 2>/dev/null \
  | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
DAYS=$(( ($(date -d "$EXPIRY" +%s) - $(date +%s)) / 86400 ))
if [ "$DAYS" -gt 14 ]; then
  echo "$PASS Certificate valid — $DAYS days remaining"
else
  echo "$FAIL Certificate expires in $DAYS days — RENEW NOW"
  REPORT="$REPORT\nCERT EXPIRY: $DAYS days"
fi

# 2. Nginx
if systemctl is-active nginx > /dev/null 2>&1; then
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" https://$DOMAIN)
  [ "$HTTP_CODE" = "200" ] && echo "$PASS Nginx — HTTPS 200 OK" \
    || echo "$WARN Nginx running but HTTPS returned $HTTP_CODE"
else
  echo "$FAIL Nginx is DOWN"
  REPORT="$REPORT\nNGINX DOWN"
fi

# 3. Postfix
if systemctl is-active postfix > /dev/null 2>&1; then
  QUEUE=$(sudo postqueue -p | grep -c "^[0-9A-F]" 2>/dev/null || echo 0)
  [ "$QUEUE" -lt 50 ] && echo "$PASS Postfix — running ($QUEUE messages queued)" \
    || echo "$WARN Postfix — $QUEUE messages in queue"
else
  echo "$FAIL Postfix is DOWN"
  REPORT="$REPORT\nPOSTFIX DOWN"
fi

# 4. Dovecot
if systemctl is-active dovecot > /dev/null 2>&1; then
  echo "$PASS Dovecot — running"
else
  echo "$FAIL Dovecot is DOWN"
  REPORT="$REPORT\nDOVECOT DOWN"
fi

# 5. OpenDKIM
if systemctl is-active opendkim > /dev/null 2>&1; then
  echo "$PASS OpenDKIM — running"
else
  echo "$FAIL OpenDKIM is DOWN"
  REPORT="$REPORT\nOPENDKIM DOWN"
fi

# 6. Port checks
for PORT in 25 443 465 993; do
  timeout 5 bash -c "echo > /dev/tcp/$MAIL_DOMAIN/$PORT" 2>/dev/null \
    && echo "$PASS Port $PORT — open" \
    || echo "$FAIL Port $PORT — UNREACHABLE"
done

# 7. Disk usage
DISK=$(df / | tail -1 | awk '{print $5}' | tr -d '%')
[ "$DISK" -lt 80 ] && echo "$PASS Disk — ${DISK}% used" \
  || echo "$WARN Disk at ${DISK}% — clean up soon"

# 8. DNSSEC
AD_FLAG=$(dig +dnssec MX $DOMAIN @8.8.8.8 | grep "flags:" | grep -c "ad")
[ "$AD_FLAG" -gt 0 ] && echo "$PASS DNSSEC — ad flag present (validated)" \
  || echo "$FAIL DNSSEC — ad flag missing"

# 9. SPF record
SPF=$(dig TXT $DOMAIN | grep "v=spf1" | grep -c "54.226.198.180")
[ "$SPF" -gt 0 ] && echo "$PASS SPF — correct IP in record" \
  || echo "$FAIL SPF — IP mismatch or record missing"

# 10. DKIM key
DKIM=$(dig TXT mail._domainkey.$DOMAIN | grep -c "v=DKIM1")
[ "$DKIM" -gt 0 ] && echo "$PASS DKIM — key record present" \
  || echo "$FAIL DKIM — key record missing"

echo "=============================="

# Send alert if anything failed
if [ -n "$REPORT" ]; then
  echo -e "GWALL ALERT:\n$REPORT" | mail -s "🚨 Great Wall Health Alert" $ALERT_EMAIL
fi
```

```bash
# Install the script
sudo cp gwall-healthcheck.sh /usr/local/bin/gwall-healthcheck.sh
sudo chmod +x /usr/local/bin/gwall-healthcheck.sh

# Schedule daily at 8am
echo "0 8 * * * rocky /usr/local/bin/gwall-healthcheck.sh >> /var/log/gwall-health.log 2>&1" \
  | sudo tee /etc/cron.d/gwall-healthcheck

# Run it now
sudo /usr/local/bin/gwall-healthcheck.sh
```

---

## Escalation Path

If you cannot resolve the issue within the target time:

```
Level 1 — Self (these playbooks)         Target: < 60 min
Level 2 — Team (Keeshon / Paulo)         Escalate if L1 fails
Level 3 — Oracle / Instructor            DNS parent zone issues only
Level 4 — AWS Support                    Infrastructure / IAM issues
           https://console.aws.amazon.com/support
```

---

*Last updated: April 2026 · Maintainer: Sammy Roy · MEQ7 Team 3*
