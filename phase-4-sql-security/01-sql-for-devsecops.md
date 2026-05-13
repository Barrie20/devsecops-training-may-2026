# Phase 4 — SQL for Security & Monitoring

---

## Why DevSecOps Engineers Need SQL

Every security tool generates data. Logs, events, alerts, metrics — they all
end up in databases or query engines. SQL is how you ask questions of that data.

**Where you'll use SQL in DevSecOps:**
- AWS CloudWatch Logs Insights (SQL-like)
- AWS Athena (query S3 data with SQL)
- Splunk (SPL is SQL-inspired)
- Elasticsearch (SQL plugin)
- SIEM tools (Sentinel, Chronicle)
- PostgreSQL/MySQL for app security data
- Grafana dashboards (SQL data sources)

---

## SQL Fundamentals — The 6 Commands You Need

Think of a database table like a spreadsheet:
- Rows = individual records (events, logs, users)
- Columns = attributes (timestamp, IP, username, action)

### 1. SELECT — "Show me this data"
```sql
-- Show all columns from the login_events table
SELECT * FROM login_events;

-- Show only specific columns
SELECT timestamp, username, ip_address, status
FROM login_events;
```

### 2. WHERE — "Filter the data"
```sql
-- Only failed logins
SELECT * FROM login_events
WHERE status = 'FAILED';

-- Failed logins from a specific IP
SELECT * FROM login_events
WHERE status = 'FAILED' AND ip_address = '192.168.1.100';

-- Events in the last 24 hours
SELECT * FROM login_events
WHERE timestamp > NOW() - INTERVAL '24 hours';
```

### 3. GROUP BY — "Summarize the data"
```sql
-- Count failed logins per IP address
SELECT ip_address, COUNT(*) as attempt_count
FROM login_events
WHERE status = 'FAILED'
GROUP BY ip_address
ORDER BY attempt_count DESC;
```

### 4. JOIN — "Combine data from multiple tables"
```sql
-- Match login events with user details
SELECT l.timestamp, l.ip_address, u.username, u.department
FROM login_events l
JOIN users u ON l.user_id = u.id
WHERE l.status = 'FAILED';
```

### 5. HAVING — "Filter after grouping"
```sql
-- IPs with more than 10 failed attempts (brute force!)
SELECT ip_address, COUNT(*) as attempts
FROM login_events
WHERE status = 'FAILED'
GROUP BY ip_address
HAVING COUNT(*) > 10
ORDER BY attempts DESC;
```

### 6. Subqueries — "Nested questions"
```sql
-- Users who logged in from IPs that also had failed attempts
SELECT DISTINCT username
FROM login_events
WHERE status = 'SUCCESS'
AND ip_address IN (
    SELECT ip_address
    FROM login_events
    WHERE status = 'FAILED'
    GROUP BY ip_address
    HAVING COUNT(*) > 5
);
```

---

## Real-World Security Queries

### Detect Brute Force Attacks
```sql
-- IPs with 10+ failed logins in the last hour
SELECT 
    ip_address,
    COUNT(*) as failed_attempts,
    MIN(timestamp) as first_attempt,
    MAX(timestamp) as last_attempt,
    COUNT(DISTINCT username) as unique_users_targeted
FROM login_events
WHERE status = 'FAILED'
    AND timestamp > NOW() - INTERVAL '1 hour'
GROUP BY ip_address
HAVING COUNT(*) >= 10
ORDER BY failed_attempts DESC;
```

### Detect Account Compromise (Success After Failures)
```sql
-- Successful login from an IP that previously failed many times
SELECT 
    s.username,
    s.ip_address,
    s.timestamp as success_time,
    f.fail_count
FROM login_events s
JOIN (
    SELECT ip_address, COUNT(*) as fail_count
    FROM login_events
    WHERE status = 'FAILED'
        AND timestamp > NOW() - INTERVAL '24 hours'
    GROUP BY ip_address
    HAVING COUNT(*) > 5
) f ON s.ip_address = f.ip_address
WHERE s.status = 'SUCCESS'
    AND s.timestamp > NOW() - INTERVAL '24 hours';
```

### Detect Unusual Login Times
```sql
-- Logins outside business hours (potential compromise)
SELECT 
    username,
    ip_address,
    timestamp,
    EXTRACT(HOUR FROM timestamp) as login_hour
FROM login_events
WHERE status = 'SUCCESS'
    AND (EXTRACT(HOUR FROM timestamp) < 6 
         OR EXTRACT(HOUR FROM timestamp) > 22)
ORDER BY timestamp DESC;
```

### Detect Privilege Escalation
```sql
-- Users who gained admin access recently
SELECT 
    u.username,
    r.role_name,
    r.granted_at,
    r.granted_by
FROM user_roles r
JOIN users u ON r.user_id = u.id
WHERE r.role_name IN ('admin', 'superuser', 'root')
    AND r.granted_at > NOW() - INTERVAL '7 days'
ORDER BY r.granted_at DESC;
```

### Detect Data Exfiltration
```sql
-- Users downloading unusually large amounts of data
SELECT 
    username,
    SUM(bytes_downloaded) as total_bytes,
    COUNT(*) as download_count,
    DATE(timestamp) as download_date
FROM data_access_logs
WHERE timestamp > NOW() - INTERVAL '24 hours'
GROUP BY username, DATE(timestamp)
HAVING SUM(bytes_downloaded) > 1073741824  -- More than 1GB
ORDER BY total_bytes DESC;
```

### Detect Suspicious API Activity
```sql
-- API calls from IPs in unusual geographic locations
SELECT 
    a.ip_address,
    a.endpoint,
    a.method,
    COUNT(*) as call_count,
    g.country,
    g.city
FROM api_access_logs a
JOIN geo_ip g ON a.ip_address = g.ip_address
WHERE g.country NOT IN ('US', 'GB', 'CA')  -- Expected countries
    AND a.timestamp > NOW() - INTERVAL '24 hours'
GROUP BY a.ip_address, a.endpoint, a.method, g.country, g.city
ORDER BY call_count DESC;
```

### Monitor Security Group Changes (AWS)
```sql
-- CloudTrail: Who modified security groups?
SELECT 
    eventTime,
    userIdentity_userName as who,
    requestParameters_groupId as security_group,
    requestParameters_ipPermissions as rule_added,
    sourceIPAddress as from_ip
FROM cloudtrail_logs
WHERE eventName IN (
    'AuthorizeSecurityGroupIngress',
    'AuthorizeSecurityGroupEgress',
    'RevokeSecurityGroupIngress'
)
AND eventTime > NOW() - INTERVAL '7 days'
ORDER BY eventTime DESC;
```

---

## AWS CloudWatch Logs Insights Queries

CloudWatch uses a SQL-like syntax. These are queries you'd run daily:

```sql
-- Find all 5xx errors in application logs
fields @timestamp, @message
| filter @message like /5\d{2}/
| sort @timestamp desc
| limit 50

-- Find Lambda cold starts
fields @timestamp, @duration, @billedDuration
| filter @message like /REPORT/
| filter @initDuration > 0
| stats avg(@initDuration) as avgColdStart,
        max(@initDuration) as maxColdStart,
        count(*) as coldStartCount
  by bin(1h)

-- Find IAM access denied events
fields @timestamp, @message
| filter @message like /AccessDenied/
| parse @message "User: *" as user
| stats count(*) as denied_count by user
| sort denied_count desc
```

---

## Memory Technique: "SELECT WHERE GROUP" 

Remember the query order with this story:

**S**elect what you want to see (columns)
**F**rom where the data lives (table)
**W**here to filter rows (conditions)
**G**roup by to summarize (aggregation)
**H**aving to filter groups (post-aggregation filter)
**O**rder by to sort results (ascending/descending)
**L**imit to cap results (top N)

Mnemonic: **"Security Folks Watch Guards Handle Ordered Logs"**

---

## Common Mistakes

1. **Not using parameterized queries** — SQL injection is still the #1 web vulnerability
2. **SELECT * in production** — Specify columns; * is slow and exposes unnecessary data
3. **No time bounds** — Always filter by time range or you'll scan entire tables
4. **Ignoring indexes** — Queries on non-indexed columns are slow at scale
5. **Not aggregating** — Raw logs are useless; patterns matter

---

## Interview Insight

**Q: "How would you use SQL to detect a security incident?"**

"I'd approach it in layers:

1. **Baseline query** — What does normal look like? Average logins per hour,
   typical source IPs, normal data access patterns.

2. **Anomaly detection** — Compare current activity against baseline.
   Flag anything 3+ standard deviations from normal.

3. **Correlation** — Join multiple data sources. A failed login alone isn't
   alarming. A failed login followed by a successful login from the same IP,
   followed by privilege escalation, followed by data download — that's a breach.

4. **Timeline reconstruction** — Once I identify a suspicious entity (IP, user),
   I query ALL their activity chronologically to understand the full attack chain.

Example: At [company], I wrote a query that correlated CloudTrail IAM events
with VPC Flow Logs to detect lateral movement — an attacker using stolen
credentials to access resources they shouldn't. This caught an active
intrusion within 15 minutes."
