#!/bin/bash

# --- CONFIGURATION VARIABLES ---
# Replace the placeholder with the API key you generated in the SendGrid UI
SENDGRID_API_KEY="<SENDGRID API KEY"
DOMAIN="gwallofchina.yulcyberhub.click"
RELAY_HOST="[smtp.sendgrid.net]:587"

echo "--- Starting Hardened Mail Relay Setup: $DOMAIN ---"

# 1. Install Dependencies
echo "[1/5] Installing Postfix and SASL modules..."
dnf install postfix cyrus-sasl-plain mailx -y > /dev/null

# 2. Configure LMDB Password Database
echo "[2/5] Configuring LMDB credential store..."
cat <<EOF > /etc/postfix/sasl_passwd
$RELAY_HOST apikey:$SENDGRID_API_KEY
EOF

# Convert to LMDB and secure permissions
postmap lmdb:/etc/postfix/sasl_passwd
chmod 0600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.lmdb
rm -f /etc/postfix/sasl_passwd.db # Cleanup legacy hash if exists

# 3. Apply Hardened Postfix Settings (main.cf)
echo "[3/5] Applying Security Policies to main.cf..."
postconf -e "myhostname = mail.$DOMAIN"
postconf -e "relayhost = $RELAY_HOST"
postconf -e "smtp_sasl_auth_enable = yes"
postconf -e "smtp_sasl_password_maps = lmdb:/etc/postfix/sasl_passwd"
postconf -e "smtp_sasl_security_options = noanonymous"
postconf -e "smtp_use_tls = yes"
postconf -e "smtp_tls_security_level = encrypt"
postconf -e "default_database_type = lmdb"
postconf -e "alias_database = lmdb:/etc/aliases"
postconf -e "alias_maps = lmdb:/etc/aliases"

# 4. Rebuild Aliases and Restart
echo "[4/5] Finalizing services..."
newaliases
systemctl restart postfix

# 5. Automated Verification Audit
echo "--- Build Complete. Running Verification ---"

# Check A: Relay Host
RELAY_CHECK=$(postconf -h relayhost)
if [[ "$RELAY_CHECK" == "$RELAY_HOST" ]]; then
    echo "[PASS] Relay Host set to SendGrid Port 587"
else
    echo "[FAIL] Relay Host mismatch: $RELAY_CHECK"
fi

# Check B: Database Type
DB_CHECK=$(postconf -h default_database_type)
if [[ "$DB_CHECK" == "lmdb" ]]; then
    echo "[PASS] Modern LMDB database active"
else
    echo "[FAIL] Legacy hash database still active"
fi

# Check C: Live Mail Test (Triggering Queue)
echo "Sending test email to samr03257@gmail.com..."
echo "AEC Project Audit: Postfix LMDB Relay is functional." | mail -s "Great Wall Audit: SUCCESS" -r admin@$DOMAIN samr03257@gmail.com

sleep 2
echo "[AUDIT] Checking maillog for status..."
grep "status=sent" /var/log/maillog | tail -n 1
