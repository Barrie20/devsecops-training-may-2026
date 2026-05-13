#!/bin/bash
# DevSecOps Log Monitor - PHASE 2 Lab

LOG_FILE="/var/log/auth.log"
THRESHOLD=5
EMAIL="aalphabarrie@gmail.com"  # Replace with real email or use Slack webhook

echo "=== Log Monitor Started at $(date) ==="

# Detect failed login attempts
FAILED=$(grep "Failed password" $LOG_FILE | wc -l)
echo "Failed logins today: $FAILED"

if [ $FAILED -gt $THRESHOLD ]; then
    echo "ALERT: High failed logins detected!" 
    echo "Top suspicious IPs:" 
    grep "Failed password" $LOG_FILE | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head -5
    # Add notification (example with mail)
    # echo "Alert" | mail -s "Security Alert" $EMAIL
fi

# Check for new users or sudo usage
grep "sudo" $LOG_FILE | tail -10
