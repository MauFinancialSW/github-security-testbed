#!/bin/bash
# =============================================================================
# STIG Auto-Remediation Script for RHEL/Amazon Linux
# =============================================================================
# Course: GitHub Copilot for Cybersecurity Specialists
# Lesson: 05 - Compliance, IR, Configuration Management
#
# Copilot Prompt Used:
# "Create STIG remediation script for Linux hardening"
#
# Features:
# - RHEL 8 STIG compliance
# - Automated remediation
# - Backup before changes
# - Compliance verification
# =============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Logging
LOG_FILE="/var/log/stig-remediation-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/var/backup/stig-$(date +%Y%m%d-%H%M%S)"

log() {
    echo -e "${GREEN}[+]${NC} $1" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[-]${NC} $1" | tee -a "$LOG_FILE"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
    exit 1
fi

# Create backup directory
mkdir -p "$BACKUP_DIR"
log "Backup directory: $BACKUP_DIR"

# =============================================================================
# STIG V-230221: Disable SSH Root Login
# =============================================================================
remediate_v230221() {
    log "V-230221: Configuring SSH to deny root login..."

    local sshd_config="/etc/ssh/sshd_config"
    cp "$sshd_config" "$BACKUP_DIR/sshd_config.bak"

    if grep -q "^PermitRootLogin" "$sshd_config"; then
        sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$sshd_config"
    else
        echo "PermitRootLogin no" >> "$sshd_config"
    fi

    systemctl restart sshd
    log "V-230221: REMEDIATED - Root login via SSH disabled"
}

# =============================================================================
# STIG V-230222: SSH Protocol Version 2
# =============================================================================
remediate_v230222() {
    log "V-230222: Ensuring SSH Protocol version 2..."

    local sshd_config="/etc/ssh/sshd_config"

    if grep -q "^Protocol" "$sshd_config"; then
        sed -i 's/^Protocol.*/Protocol 2/' "$sshd_config"
    else
        echo "Protocol 2" >> "$sshd_config"
    fi

    systemctl restart sshd
    log "V-230222: REMEDIATED - SSH Protocol 2 enforced"
}

# =============================================================================
# STIG V-230223: SSH Idle Timeout
# =============================================================================
remediate_v230223() {
    log "V-230223: Configuring SSH idle timeout..."

    local sshd_config="/etc/ssh/sshd_config"

    # Set ClientAliveInterval to 600 seconds (10 minutes)
    if grep -q "^ClientAliveInterval" "$sshd_config"; then
        sed -i 's/^ClientAliveInterval.*/ClientAliveInterval 600/' "$sshd_config"
    else
        echo "ClientAliveInterval 600" >> "$sshd_config"
    fi

    # Set ClientAliveCountMax to 0
    if grep -q "^ClientAliveCountMax" "$sshd_config"; then
        sed -i 's/^ClientAliveCountMax.*/ClientAliveCountMax 0/' "$sshd_config"
    else
        echo "ClientAliveCountMax 0" >> "$sshd_config"
    fi

    systemctl restart sshd
    log "V-230223: REMEDIATED - SSH idle timeout configured"
}

# =============================================================================
# STIG V-230234: Password Complexity
# =============================================================================
remediate_v230234() {
    log "V-230234: Configuring password complexity requirements..."

    local pwquality_conf="/etc/security/pwquality.conf"
    cp "$pwquality_conf" "$BACKUP_DIR/pwquality.conf.bak" 2>/dev/null || true

    cat > "$pwquality_conf" << 'EOF'
# STIG-compliant password quality settings
minlen = 15
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
difok = 8
minclass = 4
maxrepeat = 3
maxclassrepeat = 4
gecoscheck = 1
dictcheck = 1
EOF

    log "V-230234: REMEDIATED - Password complexity configured"
}

# =============================================================================
# STIG V-230235: Password History
# =============================================================================
remediate_v230235() {
    log "V-230235: Configuring password history..."

    local system_auth="/etc/pam.d/system-auth"
    cp "$system_auth" "$BACKUP_DIR/system-auth.bak"

    # Add password history (remember last 5 passwords)
    if grep -q "pam_pwhistory.so" "$system_auth"; then
        sed -i 's/pam_pwhistory.so.*/pam_pwhistory.so remember=5 retry=3/' "$system_auth"
    else
        sed -i '/pam_pwquality.so/a password    requisite     pam_pwhistory.so remember=5 retry=3' "$system_auth"
    fi

    log "V-230235: REMEDIATED - Password history configured"
}

# =============================================================================
# STIG V-230240: Account Lockout
# =============================================================================
remediate_v230240() {
    log "V-230240: Configuring account lockout policy..."

    local system_auth="/etc/pam.d/system-auth"
    local password_auth="/etc/pam.d/password-auth"

    # Configure faillock
    for auth_file in "$system_auth" "$password_auth"; do
        if ! grep -q "pam_faillock.so" "$auth_file"; then
            # Add faillock before pam_unix
            sed -i '/^auth.*pam_unix.so/i auth        required      pam_faillock.so preauth silent audit deny=3 unlock_time=900 fail_interval=900' "$auth_file"
            sed -i '/^auth.*pam_unix.so/a auth        required      pam_faillock.so authfail audit deny=3 unlock_time=900 fail_interval=900' "$auth_file"
        fi
    done

    log "V-230240: REMEDIATED - Account lockout configured (3 attempts, 15 min lock)"
}

# =============================================================================
# STIG V-230250: Audit Configuration
# =============================================================================
remediate_v230250() {
    log "V-230250: Configuring audit rules..."

    local audit_rules="/etc/audit/rules.d/stig.rules"

    cat > "$audit_rules" << 'EOF'
# STIG Audit Rules
# Delete all previous rules
-D

# Set buffer size
-b 8192

# Failure mode
-f 2

# Time changes
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# User/Group changes
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Network configuration
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

# Login/Logout
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# Session initiation
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# Privileged commands
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Kernel module changes
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules

# Make rules immutable (requires reboot to change)
-e 2
EOF

    # Restart auditd
    systemctl restart auditd

    log "V-230250: REMEDIATED - Audit rules configured"
}

# =============================================================================
# STIG V-230260: File Permissions on /etc/passwd
# =============================================================================
remediate_v230260() {
    log "V-230260: Setting file permissions on system files..."

    chmod 644 /etc/passwd
    chmod 644 /etc/group
    chmod 000 /etc/shadow
    chmod 000 /etc/gshadow

    chown root:root /etc/passwd /etc/group
    chown root:root /etc/shadow /etc/gshadow

    log "V-230260: REMEDIATED - System file permissions set"
}

# =============================================================================
# STIG V-230270: Disable USB Storage
# =============================================================================
remediate_v230270() {
    log "V-230270: Disabling USB storage..."

    cat > /etc/modprobe.d/usb-storage.conf << 'EOF'
install usb-storage /bin/true
blacklist usb-storage
EOF

    log "V-230270: REMEDIATED - USB storage disabled"
}

# =============================================================================
# STIG V-230280: Enable FIPS Mode
# =============================================================================
remediate_v230280() {
    log "V-230280: Enabling FIPS mode..."

    # Check if FIPS is already enabled
    if grep -q "1" /proc/sys/crypto/fips_enabled 2>/dev/null; then
        log "V-230280: FIPS mode already enabled"
        return
    fi

    # Enable FIPS
    if command -v fips-mode-setup &> /dev/null; then
        fips-mode-setup --enable
        warn "V-230280: FIPS enabled - REBOOT REQUIRED"
    else
        warn "V-230280: fips-mode-setup not available, manual FIPS configuration needed"
    fi
}

# =============================================================================
# STIG V-230290: Disable CTRL-ALT-DEL
# =============================================================================
remediate_v230290() {
    log "V-230290: Disabling CTRL-ALT-DEL..."

    systemctl mask ctrl-alt-del.target

    log "V-230290: REMEDIATED - CTRL-ALT-DEL disabled"
}

# =============================================================================
# STIG V-230300: Configure Login Banner
# =============================================================================
remediate_v230300() {
    log "V-230300: Configuring login banner..."

    cat > /etc/issue << 'EOF'
*******************************************************************************
* WARNING: This is a U.S. Government computer system. Unauthorized access     *
* or use is prohibited and may result in administrative, civil, and/or        *
* criminal penalties. By accessing this system, you agree to monitoring.      *
*******************************************************************************
EOF

    cp /etc/issue /etc/issue.net

    # Configure SSH banner
    if ! grep -q "^Banner" /etc/ssh/sshd_config; then
        echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
    fi

    systemctl restart sshd

    log "V-230300: REMEDIATED - Login banner configured"
}

# =============================================================================
# STIG V-230310: Configure NTP
# =============================================================================
remediate_v230310() {
    log "V-230310: Configuring time synchronization..."

    # Use chronyd
    yum install -y chrony 2>/dev/null || true

    cat > /etc/chrony.conf << 'EOF'
# Use approved time sources
server time.nist.gov iburst
server pool.ntp.org iburst

# Record the rate at which the system clock gains/losses time.
driftfile /var/lib/chrony/drift

# Allow the system clock to be stepped in the first three updates
makestep 1.0 3

# Enable kernel synchronization of the real-time clock (RTC).
rtcsync

# Log changes
logdir /var/log/chrony
EOF

    systemctl enable chronyd
    systemctl restart chronyd

    log "V-230310: REMEDIATED - Time synchronization configured"
}

# =============================================================================
# Verification Function
# =============================================================================
verify_remediation() {
    log "Verifying remediation..."

    local passed=0
    local failed=0

    # Check SSH root login
    if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
        ((passed++))
    else
        ((failed++))
        warn "V-230221: SSH root login still enabled"
    fi

    # Check password complexity
    if grep -q "minlen = 15" /etc/security/pwquality.conf; then
        ((passed++))
    else
        ((failed++))
        warn "V-230234: Password complexity not configured"
    fi

    # Check audit rules
    if [ -f /etc/audit/rules.d/stig.rules ]; then
        ((passed++))
    else
        ((failed++))
        warn "V-230250: Audit rules not found"
    fi

    log "Verification complete: $passed passed, $failed failed"
}

# =============================================================================
# Main
# =============================================================================
main() {
    echo "=============================================="
    echo "STIG Auto-Remediation Script"
    echo "=============================================="
    echo "Log file: $LOG_FILE"
    echo "Backup directory: $BACKUP_DIR"
    echo ""

    read -p "Continue with remediation? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 1
    fi

    # Run all remediations
    remediate_v230221  # SSH root login
    remediate_v230222  # SSH protocol
    remediate_v230223  # SSH timeout
    remediate_v230234  # Password complexity
    remediate_v230235  # Password history
    remediate_v230240  # Account lockout
    remediate_v230250  # Audit configuration
    remediate_v230260  # File permissions
    remediate_v230270  # USB storage
    remediate_v230280  # FIPS mode
    remediate_v230290  # CTRL-ALT-DEL
    remediate_v230300  # Login banner
    remediate_v230310  # NTP

    echo ""
    verify_remediation

    echo ""
    echo "=============================================="
    echo "Remediation complete!"
    echo "Review log: $LOG_FILE"
    echo "Backups stored in: $BACKUP_DIR"
    echo "=============================================="
}

main "$@"
