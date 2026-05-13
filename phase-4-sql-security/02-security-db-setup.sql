-- ============================================================
-- Phase 4 — Security Monitoring Database
-- Practice Lab: Set up tables and insert sample data
-- ============================================================
-- Run this in PostgreSQL, MySQL, or SQLite to practice
-- Install: https://www.postgresql.org/download/
-- Or use online: https://www.db-fiddle.com/
-- ============================================================

-- Create the security events database schema

-- Table 1: Login Events
CREATE TABLE login_events (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    username VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    status VARCHAR(20) NOT NULL,  -- 'SUCCESS' or 'FAILED'
    method VARCHAR(50),           -- 'password', 'ssh_key', 'mfa'
    user_agent TEXT,
    country VARCHAR(50),
    city VARCHAR(100)
);

-- Table 2: Users
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255),
    department VARCHAR(100),
    role VARCHAR(50) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT NOW(),
    last_login TIMESTAMP,
    mfa_enabled BOOLEAN DEFAULT FALSE
);

-- Table 3: API Access Logs
CREATE TABLE api_access_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    ip_address VARCHAR(45) NOT NULL,
    username VARCHAR(100),
    method VARCHAR(10) NOT NULL,   -- GET, POST, PUT, DELETE
    endpoint VARCHAR(500) NOT NULL,
    status_code INTEGER NOT NULL,
    response_time_ms INTEGER,
    bytes_transferred BIGINT DEFAULT 0
);

-- Table 4: Security Alerts
CREATE TABLE security_alerts (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    alert_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,  -- CRITICAL, HIGH, MEDIUM, LOW
    source_ip VARCHAR(45),
    target_resource VARCHAR(255),
    description TEXT,
    resolved BOOLEAN DEFAULT FALSE,
    resolved_by VARCHAR(100),
    resolved_at TIMESTAMP
);

-- Table 5: Cloud Resource Changes (simulates CloudTrail)
CREATE TABLE cloud_audit_log (
    id SERIAL PRIMARY KEY,
    event_time TIMESTAMP NOT NULL DEFAULT NOW(),
    event_name VARCHAR(100) NOT NULL,
    user_name VARCHAR(100) NOT NULL,
    source_ip VARCHAR(45),
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    request_parameters TEXT,
    response_status VARCHAR(20)
);

-- ============================================================
-- INSERT SAMPLE DATA — Simulates a real security scenario
-- Scenario: Brute force attack followed by account compromise
-- ============================================================

-- Normal users
INSERT INTO users (username, email, department, role, mfa_enabled) VALUES
('alice', 'alice@company.com', 'Engineering', 'admin', TRUE),
('bob', 'bob@company.com', 'Engineering', 'developer', TRUE),
('charlie', 'charlie@company.com', 'Finance', 'user', FALSE),
('diana', 'diana@company.com', 'Security', 'admin', TRUE),
('eve', 'eve@company.com', 'Marketing', 'user', FALSE);

-- Normal login activity (past week)
INSERT INTO login_events (timestamp, username, ip_address, status, method, country) VALUES
('2026-05-05 09:00:00', 'alice', '10.0.1.50', 'SUCCESS', 'ssh_key', 'US'),
('2026-05-05 09:15:00', 'bob', '10.0.1.51', 'SUCCESS', 'mfa', 'US'),
('2026-05-05 09:30:00', 'charlie', '10.0.2.10', 'SUCCESS', 'password', 'US'),
('2026-05-06 08:45:00', 'alice', '10.0.1.50', 'SUCCESS', 'ssh_key', 'US'),
('2026-05-06 09:00:00', 'bob', '10.0.1.51', 'SUCCESS', 'mfa', 'US'),
('2026-05-07 09:10:00', 'diana', '10.0.3.5', 'SUCCESS', 'mfa', 'US'),
('2026-05-07 14:00:00', 'eve', '10.0.2.20', 'SUCCESS', 'password', 'US');

-- ATTACK: Brute force from external IP (May 10, 2am - unusual time)
INSERT INTO login_events (timestamp, username, ip_address, status, method, country) VALUES
('2026-05-10 02:01:00', 'admin', '185.220.101.45', 'FAILED', 'password', 'Russia'),
('2026-05-10 02:01:05', 'root', '185.220.101.45', 'FAILED', 'password', 'Russia'),
('2026-05-10 02:01:10', 'alice', '185.220.101.45', 'FAILED', 'password', 'Russia'),
('2026-05-10 02:01:15', 'bob', '185.220.101.45', 'FAILED', 'password', 'Russia'),
('2026-05-10 02:01:20', 'charlie', '185.220.101.45', 'FAILED', 'password', 'Russia'),
('2026-05-10 02:01:25', 'test', '185.220.101.45', 'FAILED', 'password', 'Russia'),
('2026-05-10 02:01:30', 'deploy', '185.220.101.45', 'FAILED', 'password', 'Russia'),
('2026-05-10 02:01:35', 'jenkins', '185.220.101.45', 'FAILED', 'password', 'Russia'),
('2026-05-10 02:01:40', 'charlie', '185.220.101.45', 'FAILED', 'password', 'Russia'),
('2026-05-10 02:01:45', 'charlie', '185.220.101.45', 'FAILED', 'password', 'Russia'),
('2026-05-10 02:01:50', 'charlie', '185.220.101.45', 'FAILED', 'password', 'Russia'),
('2026-05-10 02:01:55', 'charlie', '185.220.101.45', 'FAILED', 'password', 'Russia'),
-- ATTACKER SUCCEEDS (charlie has no MFA!)
('2026-05-10 02:02:00', 'charlie', '185.220.101.45', 'SUCCESS', 'password', 'Russia');

-- ATTACK: Attacker uses charlie's account for lateral movement
INSERT INTO login_events (timestamp, username, ip_address, status, method, country) VALUES
('2026-05-10 02:05:00', 'charlie', '185.220.101.45', 'SUCCESS', 'password', 'Russia'),
('2026-05-10 02:10:00', 'charlie', '185.220.101.45', 'SUCCESS', 'password', 'Russia');

-- ATTACK: Suspicious API activity from compromised account
INSERT INTO api_access_logs (timestamp, ip_address, username, method, endpoint, status_code, bytes_transferred) VALUES
('2026-05-10 02:06:00', '185.220.101.45', 'charlie', 'GET', '/api/users', 200, 45000),
('2026-05-10 02:07:00', '185.220.101.45', 'charlie', 'GET', '/api/users/export', 200, 5242880),
('2026-05-10 02:08:00', '185.220.101.45', 'charlie', 'GET', '/api/finance/reports', 200, 10485760),
('2026-05-10 02:09:00', '185.220.101.45', 'charlie', 'GET', '/api/finance/payroll', 200, 8388608),
('2026-05-10 02:10:00', '185.220.101.45', 'charlie', 'POST', '/api/users', 201, 500),
('2026-05-10 02:11:00', '185.220.101.45', 'charlie', 'PUT', '/api/users/charlie/role', 200, 200);

-- Normal API activity for comparison
INSERT INTO api_access_logs (timestamp, ip_address, username, method, endpoint, status_code, bytes_transferred) VALUES
('2026-05-10 09:00:00', '10.0.2.10', 'charlie', 'GET', '/api/finance/dashboard', 200, 5000),
('2026-05-10 09:30:00', '10.0.1.50', 'alice', 'GET', '/api/deployments', 200, 3000),
('2026-05-10 10:00:00', '10.0.1.51', 'bob', 'POST', '/api/deployments', 201, 1500);

-- ATTACK: Cloud resource changes (privilege escalation)
INSERT INTO cloud_audit_log (event_time, event_name, user_name, source_ip, resource_type, resource_id, response_status) VALUES
('2026-05-10 02:12:00', 'CreateUser', 'charlie', '185.220.101.45', 'IAM::User', 'backdoor-user', 'Success'),
('2026-05-10 02:13:00', 'AttachUserPolicy', 'charlie', '185.220.101.45', 'IAM::Policy', 'arn:aws:iam::aws:policy/AdministratorAccess', 'Success'),
('2026-05-10 02:14:00', 'CreateAccessKey', 'charlie', '185.220.101.45', 'IAM::AccessKey', 'AKIA1234567890EXAMPLE', 'Success'),
('2026-05-10 02:15:00', 'AuthorizeSecurityGroupIngress', 'charlie', '185.220.101.45', 'EC2::SecurityGroup', 'sg-0123456789', 'Success');

-- Security alerts generated
INSERT INTO security_alerts (timestamp, alert_type, severity, source_ip, target_resource, description) VALUES
('2026-05-10 02:02:00', 'BRUTE_FORCE', 'HIGH', '185.220.101.45', 'auth-service', '12 failed login attempts in 60 seconds'),
('2026-05-10 02:06:00', 'DATA_EXFILTRATION', 'CRITICAL', '185.220.101.45', 'api-gateway', 'Unusual data download volume: 24MB in 5 minutes'),
('2026-05-10 02:12:00', 'PRIVILEGE_ESCALATION', 'CRITICAL', '185.220.101.45', 'iam', 'New IAM user created with admin access'),
('2026-05-10 02:15:00', 'SECURITY_GROUP_CHANGE', 'HIGH', '185.220.101.45', 'vpc', 'Security group opened to 0.0.0.0/0');
