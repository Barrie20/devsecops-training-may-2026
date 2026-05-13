# Phase 2 — Linux & Bash Mastery for DevSecOps

---

## Why Linux Matters in DevSecOps

95% of production servers run Linux. Every container runs Linux.
Every CI/CD pipeline runs on Linux. If you can't navigate Linux,
you can't do DevSecOps.

---

## The Linux Filesystem — Mental Model

Think of it like a tree growing upside down:

```
/ (root - the trunk)
├── /etc        → Configuration files (settings)
├── /var        → Variable data (logs, databases)
│   └── /var/log → ALL system logs live here
├── /home       → User home directories
├── /tmp        → Temporary files (cleared on reboot)
├── /opt        → Optional/third-party software
├── /usr        → User programs and utilities
│   └── /usr/bin → Most commands live here
├── /bin        → Essential commands (ls, cp, mv)
├── /sbin       → System admin commands
└── /proc       → Virtual filesystem (running processes)
```

### Security-Critical Directories:
- `/var/log` — Where you investigate breaches
- `/etc/passwd` — User accounts
- `/etc/shadow` — Password hashes (restricted)
- `/etc/ssh/` — SSH configuration
- `/etc/sudoers` — Who has root access

---

## Essential Commands — Grouped by Purpose

### Navigation & Discovery
```bash
pwd                    # Where am I?
ls -la                 # List all files with permissions
cd /var/log            # Change directory
find / -name "*.log"   # Find files by name
find / -perm -4000     # Find SUID files (security audit!)
which python3          # Where is this command?
```

### File Operations
```bash
cat file.txt           # View file contents
head -20 file.txt      # First 20 lines
tail -f /var/log/syslog  # Follow log in real-time (CRITICAL for debugging)
less file.txt          # Page through large files
wc -l file.txt         # Count lines
```

### Text Processing (The Power Tools)
```bash
# grep — search for patterns
grep "Failed password" /var/log/auth.log
grep -r "password" /etc/    # Recursive search (find hardcoded creds!)
grep -i "error" app.log     # Case-insensitive
grep -c "404" access.log    # Count matches

# awk — column extraction
awk '{print $1}' access.log              # Print first column
awk -F: '{print $1}' /etc/passwd         # Print usernames
awk '$9 == 500 {print $1}' access.log    # Filter by HTTP 500 errors

# sed — stream editing
sed 's/http/https/g' config.txt          # Replace http with https
sed -n '10,20p' file.txt                 # Print lines 10-20
sed -i 's/old/new/g' file.txt            # Edit file in place

# sort & uniq — analyze patterns
sort access.log | uniq -c | sort -nr | head -10  # Top 10 repeated lines
```

### Permissions (CRITICAL for Security)
```bash
# Format: rwxrwxrwx = owner|group|others
# r=read(4) w=write(2) x=execute(1)

chmod 700 script.sh     # Owner only: rwx------
chmod 644 config.txt    # Owner rw, others read: rw-r--r--
chmod 600 private.key   # Owner rw only: rw-------  (for SSH keys!)

chown root:root /etc/shadow   # Change owner
chown -R appuser:appuser /app # Recursive ownership change

# Security audit: find world-writable files
find / -perm -002 -type f 2>/dev/null
```

### Process Management
```bash
ps aux                  # All running processes
ps aux | grep nginx     # Find specific process
top                     # Real-time process monitor
htop                    # Better process monitor (install it)
kill -9 PID             # Force kill process
kill -15 PID            # Graceful shutdown (preferred)
systemctl status nginx  # Check service status
systemctl restart nginx # Restart service
journalctl -u nginx     # View service logs
```

### Networking
```bash
netstat -tlnp           # What ports are listening?
ss -tlnp                # Modern replacement for netstat
curl -I https://example.com  # Check HTTP headers
curl -k https://self-signed.com  # Skip cert verification (testing only!)
wget https://example.com/file    # Download file
ip addr show            # Show network interfaces
dig example.com         # DNS lookup
nslookup example.com    # DNS lookup (simpler)
traceroute example.com  # Network path
```

### Package Management (Ubuntu/Debian)
```bash
apt update              # Update package list
apt upgrade             # Upgrade all packages
apt install nginx       # Install package
apt remove nginx        # Remove package
apt list --installed    # List installed packages

# Security: Check for available security updates
apt list --upgradable 2>/dev/null | grep -i security
```

---

## Memory Technique: "LOG FIND KILL NET" Framework

When investigating a security incident, follow this order:

1. **LOG** — Check logs first (`/var/log/auth.log`, `/var/log/syslog`)
2. **FIND** — Find suspicious files (`find / -newer /tmp/marker -type f`)
3. **KILL** — Kill malicious processes (`ps aux | grep suspicious`)
4. **NET** — Check network connections (`ss -tlnp`, `netstat -an`)

---

## Common Mistakes

1. Running commands as root unnecessarily — use `sudo` for specific commands
2. Setting permissions to 777 — NEVER do this in production
3. Not checking logs after changes — always verify
4. Using `rm -rf /` without thinking — double-check paths
5. Ignoring exit codes — check `$?` after critical commands

---

## Interview Insight

**Q: "A server is behaving strangely. Walk me through your investigation."**

"I'd follow a systematic approach:

1. **Check system load:** `top` or `uptime` — is CPU/memory maxed?
2. **Check logs:** `tail -100 /var/log/syslog` — any errors?
3. **Check processes:** `ps aux --sort=-%cpu` — anything unexpected?
4. **Check network:** `ss -tlnp` — any unauthorized listeners?
5. **Check disk:** `df -h` — is disk full?
6. **Check recent changes:** `last` — who logged in recently?
7. **Check cron:** `crontab -l` and `/etc/cron.d/` — any malicious scheduled tasks?

If I suspect compromise, I'd isolate the server from the network immediately
while preserving evidence for forensics."
