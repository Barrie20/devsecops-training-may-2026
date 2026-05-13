-- ============================================================
-- Phase 4 — SQL Practice Exercises
-- Run these against the database from 02-security-db-setup.sql
-- ============================================================
-- TRY TO WRITE THESE YOURSELF FIRST before looking at answers!
-- ============================================================


-- ============================================================
-- EXERCISE 1: Find the brute force attack
-- Question: Which IP addresses had more than 5 failed logins?
-- ============================================================

-- YOUR ANSWER HERE:



-- SOLUTION:
SELECT 
    ip_address,
    COUNT(*) as failed_attempts,
    COUNT(DISTINCT username) as unique_users,
    MIN(timestamp) as first_attempt,
    MAX(timestamp) as last_attempt
FROM login_events
WHERE status = 'FAILED'
GROUP BY ip_address
HAVING COUNT(*) > 5
ORDER BY failed_attempts DESC;

-- Expected result: 185.220.101.45 with 12 failed attempts


-- ============================================================
-- EXERCISE 2: Identify the compromised account
-- Question: Which users had a successful login from an IP
--           that also had failed attempts?
-- ============================================================

-- YOUR ANSWER HERE:



-- SOLUTION:
SELECT DISTINCT
    s.username,
    s.ip_address,
    s.timestamp as compromise_time,
    s.country
FROM login_events s
WHERE s.status = 'SUCCESS'
AND s.ip_address IN (
    SELECT ip_address
    FROM login_events
    WHERE status = 'FAILED'
    GROUP BY ip_address
    HAVING COUNT(*) > 5
);

-- Expected: charlie from 185.220.101.45 (Russia)


-- ============================================================
-- EXERCISE 3: Detect data exfiltration
-- Question: Which users downloaded more than 1MB of data
--           in a single session?
-- ============================================================

-- YOUR ANSWER HERE:



-- SOLUTION:
SELECT 
    username,
    ip_address,
    SUM(bytes_transferred) as total_bytes,
    ROUND(SUM(bytes_transferred) / 1048576.0, 2) as total_mb,
    COUNT(*) as request_count,
    MIN(timestamp) as session_start,
    MAX(timestamp) as session_end
FROM api_access_logs
WHERE method = 'GET'
GROUP BY username, ip_address
HAVING SUM(bytes_transferred) > 1048576
ORDER BY total_bytes DESC;

-- Expected: charlie from 185.220.101.45 with ~24MB


-- ============================================================
-- EXERCISE 4: Find unusual login times
-- Question: Who logged in between midnight and 6am?
-- ============================================================

-- YOUR ANSWER HERE:



-- SOLUTION:
SELECT 
    username,
    ip_address,
    timestamp,
    country,
    EXTRACT(HOUR FROM timestamp) as login_hour
FROM login_events
WHERE status = 'SUCCESS'
AND EXTRACT(HOUR FROM timestamp) BETWEEN 0 AND 6
ORDER BY timestamp;

-- Expected: charlie's compromised sessions at 2am


-- ============================================================
-- EXERCISE 5: Detect privilege escalation in cloud
-- Question: Who created new IAM users or attached admin policies?
-- ============================================================

-- YOUR ANSWER HERE:



-- SOLUTION:
SELECT 
    event_time,
    event_name,
    user_name,
    source_ip,
    resource_type,
    resource_id
FROM cloud_audit_log
WHERE event_name IN (
    'CreateUser',
    'AttachUserPolicy',
    'CreateAccessKey',
    'PutUserPolicy'
)
ORDER BY event_time;

-- Expected: charlie creating backdoor-user with admin access


-- ============================================================
-- EXERCISE 6: Build a complete attack timeline
-- Question: Reconstruct the full attack from start to finish
-- ============================================================

-- YOUR ANSWER HERE:



-- SOLUTION:
-- Combine all activity from the attacker IP into a timeline
SELECT 
    timestamp as event_time,
    'LOGIN_ATTEMPT' as event_type,
    username,
    ip_address,
    status as detail
FROM login_events
WHERE ip_address = '185.220.101.45'

UNION ALL

SELECT 
    timestamp,
    'API_ACCESS',
    username,
    ip_address,
    CONCAT(method, ' ', endpoint, ' (', bytes_transferred, ' bytes)') as detail
FROM api_access_logs
WHERE ip_address = '185.220.101.45'

UNION ALL

SELECT 
    event_time,
    'CLOUD_CHANGE',
    user_name,
    source_ip,
    CONCAT(event_name, ': ', resource_id) as detail
FROM cloud_audit_log
WHERE source_ip = '185.220.101.45'

ORDER BY event_time;

-- This gives you the complete attack chain!


-- ============================================================
-- EXERCISE 7: Find users without MFA (vulnerability)
-- Question: Which users don't have MFA and have logged in?
-- ============================================================

-- YOUR ANSWER HERE:



-- SOLUTION:
SELECT 
    u.username,
    u.department,
    u.role,
    u.mfa_enabled,
    COUNT(l.id) as login_count
FROM users u
LEFT JOIN login_events l ON u.username = l.username
WHERE u.mfa_enabled = FALSE
GROUP BY u.username, u.department, u.role, u.mfa_enabled;

-- Expected: charlie and eve — charlie was compromised because no MFA!


-- ============================================================
-- EXERCISE 8: Security dashboard query
-- Question: Create a summary of all security alerts by severity
-- ============================================================

-- YOUR ANSWER HERE:



-- SOLUTION:
SELECT 
    severity,
    COUNT(*) as alert_count,
    COUNT(CASE WHEN resolved = FALSE THEN 1 END) as unresolved,
    STRING_AGG(DISTINCT alert_type, ', ') as alert_types
FROM security_alerts
WHERE timestamp > NOW() - INTERVAL '7 days'
GROUP BY severity
ORDER BY 
    CASE severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 4
    END;


-- ============================================================
-- BONUS: Write a query that would have PREVENTED this attack
-- ============================================================

-- This query could run every 5 minutes as an automated check:
-- "Alert if any IP has 5+ failed logins in the last 10 minutes"

SELECT 
    ip_address,
    COUNT(*) as attempts,
    COUNT(DISTINCT username) as users_targeted
FROM login_events
WHERE status = 'FAILED'
    AND timestamp > NOW() - INTERVAL '10 minutes'
GROUP BY ip_address
HAVING COUNT(*) >= 5;

-- If this returns results → BLOCK THE IP IMMEDIATELY
-- This is how automated security response works!
