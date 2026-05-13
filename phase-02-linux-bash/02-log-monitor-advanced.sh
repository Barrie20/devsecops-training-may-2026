#!/bin/bash
# =============================================================
# DevSecOps Log Monitor v2.0 — Advanced Security Monitoring
# =============================================================
# This script demonstrates real-world security monitoring
# that DevSecOps engineers build and maintain daily.
#
# What it does:
# 1. Monitors authentication logs for brute force attacks
# 2. Detects suspicious sudo usage
# 3. Identifies new user creation (persistence technique)
# 4. Checks for SSH key changes
# 5. Monitors for port scanning activity
# 6. Generates a security report
# =============================================================

# --- Configuration ---
LOG_DIR="/var/log"
AUTH_LOG="$LOG_DIR/auth.log"
SYSLOG="$LOG_DIR/syslog"
REPORT_DIR="/tmp/security-reports"
REPORT_FILE="$REPORT_DIR/report-$(date +%Y%m%d-%H%M%S).txt"
FAILED_LOGIN_THRESHOLD=5
ALERT_EMAIL="security-team@company.com"

# --- Colors for terminal output ---
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# --- Functions ---

setup() {
    mkdir -p "$REPORT_DIR"
    echo "========================================" | tee "$REPORT_FILE"
    echo " SECURITY MONITORING REPORT" | tee -a "$REPORT_FILE"
    echo " Generated: $(date)" | tee -a "$REPORT_FILE"
    echo " Hostname: $(hostname)" | tee -a "$REPORT_FILE"
    echo "========================================" | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"
}

check_failed_logins() {
    echo -e "${YELLOW}[CHECK 1] Failed Login Attempts${NC}" | tee -a "$REPORT_FILE"
    echo "----------------------------------------" | tee -a "$REPORT_FILE"

    if [ ! -f "$AUTH_LOG" ]; then
        echo "  Auth log not found at $AUTH_LOG" | tee -a "$REPORT_FILE"
        return
    fi

    # Count failed logins in last 24 hours
    FAILED_COUNT=$(grep "Failed password" "$AUTH_LOG" 2>/dev/null | \
        grep "$(date +%b\ %d)" | wc -l)

    echo "  Failed logins today: $FAILED_COUNT" | tee -a "$REPORT_FILE"

    if [ "$FAILED_COUNT" -gt "$FAILED_LOGIN_THRESHOLD" ]; then
        echo -e "  ${RED}[ALERT] Threshold exceeded! Possible brute force attack.${NC}" | tee -a "$REPORT_FILE"

        echo "  Top attacking IPs:" | tee -a "$REPORT_FILE"
        grep "Failed password" "$AUTH_LOG" 2>/dev/null | \
            grep "$(date +%b\ %d)" | \
            awk '{print $(NF-3)}' | \
            sort | uniq -c | sort -nr | head -10 | \
            while read count ip; do
                echo "    $ip — $count attempts" | tee -a "$REPORT_FILE"
            done

        echo "  Targeted usernames:" | tee -a "$REPORT_FILE"
        grep "Failed password" "$AUTH_LOG" 2>/dev/null | \
            grep "$(date +%b\ %d)" | \
            awk '{for(i=1;i<=NF;i++) if($i=="for") print $(i+1)}' | \
            sort | uniq -c | sort -nr | head -5 | \
            while read count user; do
                echo "    $user — $count attempts" | tee -a "$REPORT_FILE"
            done
    else
        echo -e "  ${GREEN}[OK] Within normal range.${NC}" | tee -a "$REPORT_FILE"
    fi
    echo "" | tee -a "$REPORT_FILE"
}

check_sudo_usage() {
    echo -e "${YELLOW}[CHECK 2] Sudo Usage${NC}" | tee -a "$REPORT_FILE"
    echo "----------------------------------------" | tee -a "$REPORT_FILE"

    if [ ! -f "$AUTH_LOG" ]; then
        echo "  Auth log not found." | tee -a "$REPORT_FILE"
        return
    fi

    SUDO_COUNT=$(grep "sudo:" "$AUTH_LOG" 2>/dev/null | \
        grep "$(date +%b\ %d)" | wc -l)

    echo "  Sudo commands today: $SUDO_COUNT" | tee -a "$REPORT_FILE"

    # Show sudo commands (potential privilege escalation)
    echo "  Recent sudo activity:" | tee -a "$REPORT_FILE"
    grep "sudo:" "$AUTH_LOG" 2>/dev/null | \
        grep "COMMAND" | tail -5 | \
        while IFS= read -r line; do
            echo "    $line" | tee -a "$REPORT_FILE"
        done

    # Check for failed sudo attempts (suspicious!)
    FAILED_SUDO=$(grep "sudo:" "$AUTH_LOG" 2>/dev/null | \
        grep "authentication failure" | wc -l)

    if [ "$FAILED_SUDO" -gt 0 ]; then
        echo -e "  ${RED}[ALERT] $FAILED_SUDO failed sudo attempts detected!${NC}" | tee -a "$REPORT_FILE"
    fi
    echo "" | tee -a "$REPORT_FILE"
}

check_new_users() {
    echo -e "${YELLOW}[CHECK 3] New User Accounts${NC}" | tee -a "$REPORT_FILE"
    echo "----------------------------------------" | tee -a "$REPORT_FILE"

    # Check for new user creation (common persistence technique)
    NEW_USERS=$(grep "new user" "$AUTH_LOG" 2>/dev/null | \
        grep "$(date +%b\ %d)" | wc -l)

    if [ "$NEW_USERS" -gt 0 ]; then
        echo -e "  ${RED}[ALERT] $NEW_USERS new user(s) created today!${NC}" | tee -a "$REPORT_FILE"
        grep "new user" "$AUTH_LOG" 2>/dev/null | \
            grep "$(date +%b\ %d)" | tee -a "$REPORT_FILE"
    else
        echo -e "  ${GREEN}[OK] No new users created.${NC}" | tee -a "$REPORT_FILE"
    fi

    # Check for users with UID 0 (root equivalent — VERY suspicious)
    ROOT_USERS=$(awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null)
    ROOT_COUNT=$(echo "$ROOT_USERS" | wc -w)

    if [ "$ROOT_COUNT" -gt 1 ]; then
        echo -e "  ${RED}[ALERT] Multiple UID 0 accounts found: $ROOT_USERS${NC}" | tee -a "$REPORT_FILE"
    fi
    echo "" | tee -a "$REPORT_FILE"
}

check_ssh_activity() {
    echo -e "${YELLOW}[CHECK 4] SSH Activity${NC}" | tee -a "$REPORT_FILE"
    echo "----------------------------------------" | tee -a "$REPORT_FILE"

    # Successful SSH logins
    echo "  Successful SSH logins today:" | tee -a "$REPORT_FILE"
    grep "Accepted" "$AUTH_LOG" 2>/dev/null | \
        grep "$(date +%b\ %d)" | \
        awk '{print "    User:", $9, "from", $11, "at", $1, $2, $3}' | \
        tee -a "$REPORT_FILE"

    # Check if SSH config was modified
    if [ -f /etc/ssh/sshd_config ]; then
        SSH_MODIFIED=$(find /etc/ssh/sshd_config -mtime -1 2>/dev/null)
        if [ -n "$SSH_MODIFIED" ]; then
            echo -e "  ${RED}[ALERT] SSH config modified in last 24 hours!${NC}" | tee -a "$REPORT_FILE"
        fi
    fi

    # Check authorized_keys for changes
    find /home -name "authorized_keys" -mtime -1 2>/dev/null | \
        while IFS= read -r keyfile; do
            echo -e "  ${RED}[ALERT] SSH key file modified: $keyfile${NC}" | tee -a "$REPORT_FILE"
        done
    echo "" | tee -a "$REPORT_FILE"
}

check_listening_ports() {
    echo -e "${YELLOW}[CHECK 5] Listening Ports${NC}" | tee -a "$REPORT_FILE"
    echo "----------------------------------------" | tee -a "$REPORT_FILE"

    echo "  Currently listening:" | tee -a "$REPORT_FILE"
    ss -tlnp 2>/dev/null | grep LISTEN | \
        awk '{print "    " $4, $6}' | tee -a "$REPORT_FILE"

    # Check for common backdoor ports
    SUSPICIOUS_PORTS="4444 5555 6666 1337 31337 12345"
    for port in $SUSPICIOUS_PORTS; do
        if ss -tlnp 2>/dev/null | grep -q ":$port "; then
            echo -e "  ${RED}[ALERT] Suspicious port $port is listening!${NC}" | tee -a "$REPORT_FILE"
        fi
    done
    echo "" | tee -a "$REPORT_FILE"
}

check_cron_jobs() {
    echo -e "${YELLOW}[CHECK 6] Scheduled Tasks (Cron)${NC}" | tee -a "$REPORT_FILE"
    echo "----------------------------------------" | tee -a "$REPORT_FILE"

    # Check all user crontabs
    echo "  System cron jobs:" | tee -a "$REPORT_FILE"
    ls /etc/cron.d/ 2>/dev/null | \
        while IFS= read -r job; do
            echo "    /etc/cron.d/$job" | tee -a "$REPORT_FILE"
        done

    # Check for recently modified cron files (persistence technique)
    find /etc/cron* /var/spool/cron -mtime -1 2>/dev/null | \
        while IFS= read -r cronfile; do
            echo -e "  ${YELLOW}[WARN] Recently modified: $cronfile${NC}" | tee -a "$REPORT_FILE"
        done
    echo "" | tee -a "$REPORT_FILE"
}

generate_summary() {
    echo "========================================" | tee -a "$REPORT_FILE"
    echo " SUMMARY" | tee -a "$REPORT_FILE"
    echo "========================================" | tee -a "$REPORT_FILE"
    echo "  Report saved to: $REPORT_FILE" | tee -a "$REPORT_FILE"
    echo "  Run 'cat $REPORT_FILE' to review" | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"

    # Count alerts
    ALERT_COUNT=$(grep -c "\[ALERT\]" "$REPORT_FILE")
    if [ "$ALERT_COUNT" -gt 0 ]; then
        echo -e "  ${RED}Total alerts: $ALERT_COUNT — INVESTIGATE IMMEDIATELY${NC}" | tee -a "$REPORT_FILE"
    else
        echo -e "  ${GREEN}No critical alerts. System appears healthy.${NC}" | tee -a "$REPORT_FILE"
    fi
}

# --- Main Execution ---
main() {
    setup
    check_failed_logins
    check_sudo_usage
    check_new_users
    check_ssh_activity
    check_listening_ports
    check_cron_jobs
    generate_summary
}

# Run the monitor
main "$@"
