#!/bin/bash

# ==============================================================================
#  🛡️  GREAT WALL MAIL INFRASTRUCTURE MANAGER
#  Purpose: Add or Remove Virtual Mail Users (Postfix LMDB & Dovecot)
#  Author:  mrblue
# ==============================================================================

# Configuration Paths
VMAILBOX="<REDACTED>"
DOVECOT_PASSWD="<REDACTED>"
VMAIL_DOMAIN="<REDACTED>"
VMAIL_BASE="<REDACTED>"

# 🔐 STAGE 1: Sudo Permission Check
if [ "$EUID" -ne 0 ]; then 
  echo "------------------------------------------------------------------"
  echo " ERROR: THIS SCRIPT MUST BE RUN WITH SUDO PERMISSIONS."
  echo " Author: mrblue | Purpose: Secure Mail Administration"
  echo "------------------------------------------------------------------"
  exit 1
fi

usage() {
    echo "Usage: sudo $0 {add|remove} username"
    exit 1
}

# Ensure correct number of arguments
if [ $# -lt 2 ]; then
    usage
fi

ACTION=$1
USERNAME=$2
FULL_EMAIL="${USERNAME}@${VMAIL_DOMAIN}"
MAIL_DIR="${VMAIL_DOMAIN}/${USERNAME}/"
USER_DIR="${VMAIL_BASE}/${MAIL_DIR}"

case "$ACTION" in
    add)
        echo "--- Adding New Secure Mail User: $FULL_EMAIL ---"
        
        # Check if user exists in the Dovecot users file
        if grep -q "^$FULL_EMAIL:" "$DOVECOT_PASSWD"; then
            echo "❌ Error: User $FULL_EMAIL already exists in $DOVECOT_PASSWD."
            exit 1
        fi

        read -s -p "Enter strong password for $USERNAME: " PASSWORD
        echo ""
        
        # 1. Update Postfix Virtual Maps (LMDB)
        echo "$FULL_EMAIL $MAIL_DIR" >> "$VMAILBOX"
        postmap lmdb:"$VMAILBOX"

        # 2. Update Dovecot Password File (SHA512-CRYPT)
        # Format: user@domain:{SHA512-CRYPT}hash:5000:5000::/var/mail/vhosts/domain/user
        HASHED_PASS=$(doveadm pw -s SHA512-CRYPT -p "$PASSWORD")
        echo "${FULL_EMAIL}:${HASHED_PASS}:5000:5000::${VMAIL_BASE}/${VMAIL_DOMAIN}/${USERNAME}" >> "$DOVECOT_PASSWD"

        # 3. Provision Filesystem & Set Secure Permissions
        mkdir -p "$USER_DIR"
        chown -R vmail:vmail "$VMAIL_BASE"
        chmod 700 "$USER_DIR"
        
        echo "✅ Success: $FULL_EMAIL added to the Great Wall."
        ;;

    remove)
        echo "--- De-authorizing Mail User: $FULL_EMAIL ---"
        
        if ! grep -q "^$FULL_EMAIL:" "$DOVECOT_PASSWD"; then
            echo "❌ Error: User $FULL_EMAIL not found in $DOVECOT_PASSWD."
            exit 1
        fi

        # 1. Strip from Postfix vmailbox & Rebuild LMDB
        sed -i "/^$FULL_EMAIL /d" "$VMAILBOX"
        postmap lmdb:"$VMAILBOX"

        # 2. Strip from Dovecot Authentication
        sed -i "/^$FULL_EMAIL:/d" "$DOVECOT_PASSWD"

        # 3. Secure File Handling
        echo "Configuration entries removed for $FULL_EMAIL."
        read -p "Permanently delete all mail files in $USER_DIR? (y/N): " CONFIRM
        if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
            rm -rf "$USER_DIR"
            echo "🗑️  Mail storage purged from filesystem."
        else
            echo "📂 Mail storage preserved at $USER_DIR."
        fi

        echo "✅ Success: $FULL_EMAIL removed from mail services."
        ;;

    *)
        usage
        ;;
esac
