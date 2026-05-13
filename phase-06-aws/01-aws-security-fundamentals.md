# Phase 6 — AWS Cloud Mastery for DevSecOps

---

## The AWS Learning Order (Production Priority)

Learn AWS services in this order — it mirrors how production systems are built:

```
1. IAM (Identity) → Who can do what?
2. VPC (Network) → How is traffic controlled?
3. EC2 (Compute) → Where does code run?
4. S3 (Storage) → Where is data stored?
5. CloudWatch (Monitoring) → How do we see what's happening?
6. Lambda (Serverless) → Event-driven compute
7. ECS/EKS (Containers) → Container orchestration
8. RDS (Database) → Managed databases
```

---

## 1. IAM — Identity & Access Management

IAM is the MOST IMPORTANT AWS service for security. Every breach starts with
compromised or overly permissive credentials.

### Core Concepts:

| Concept | What it is | Example |
|---------|-----------|---------|
| User | A person or service | `alice`, `ci-pipeline` |
| Group | Collection of users | `developers`, `admins` |
| Role | Temporary identity | `ec2-app-role`, `lambda-role` |
| Policy | Permission document | "Allow S3 read on bucket X" |

### The Principle of Least Privilege

**Rule:** Give the MINIMUM permissions needed to do the job. Nothing more.

```json
// BAD — Too permissive (admin access to everything)
{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
}

// GOOD — Specific permissions for specific resources
{
    "Effect": "Allow",
    "Action": [
        "s3:GetObject",
        "s3:ListBucket"
    ],
    "Resource": [
        "arn:aws:s3:::my-app-data",
        "arn:aws:s3:::my-app-data/*"
    ]
}
```

### IAM Best Practices (FAANG Standard):

1. **Never use root account** — Create IAM users, lock root with MFA
2. **Use roles, not long-lived keys** — Roles rotate credentials automatically
3. **Enable MFA everywhere** — Especially for console access
4. **Use permission boundaries** — Limit what even admins can grant
5. **Review access regularly** — Use IAM Access Analyzer
6. **Use conditions** — Restrict by IP, time, MFA status

```json
// Policy with conditions — only allow from corporate network with MFA
{
    "Effect": "Allow",
    "Action": "ec2:*",
    "Resource": "*",
    "Condition": {
        "IpAddress": {
            "aws:SourceIp": "203.0.113.0/24"
        },
        "Bool": {
            "aws:MultiFactorAuthPresent": "true"
        }
    }
}
```

---

## 2. VPC — Virtual Private Cloud (Network Security)

A VPC is your private network in AWS. Think of it as your own data center
in the cloud with complete control over traffic flow.

### Architecture:
```
VPC (10.0.0.0/16) — Your private network
├── Public Subnet (10.0.1.0/24) — Internet-facing
│   ├── Load Balancer
│   └── NAT Gateway
├── Private Subnet (10.0.2.0/24) — Application tier
│   ├── App Server 1
│   └── App Server 2
└── Private Subnet (10.0.3.0/24) — Data tier
    ├── Database (RDS)
    └── Cache (ElastiCache)
```

### Security Controls:

| Control | Level | Stateful? | Use Case |
|---------|-------|-----------|----------|
| Security Group | Instance | Yes | Allow specific ports/IPs |
| NACL | Subnet | No | Block known bad IPs |
| Route Table | Subnet | N/A | Control traffic flow |
| VPC Flow Logs | VPC | N/A | Monitor all traffic |

### Security Group Example:
```json
// Web server — only allow HTTP/HTTPS from load balancer
{
    "Inbound": [
        {"Port": 443, "Source": "sg-loadbalancer"},
        {"Port": 80, "Source": "sg-loadbalancer"}
    ],
    "Outbound": [
        {"Port": 443, "Destination": "0.0.0.0/0"},
        {"Port": 5432, "Destination": "sg-database"}
    ]
}

// Database — only allow from app servers
{
    "Inbound": [
        {"Port": 5432, "Source": "sg-appserver"}
    ],
    "Outbound": []
}
```

### VPC Security Best Practices:
1. **No public IPs on app/data servers** — Use load balancers and NAT
2. **Enable VPC Flow Logs** — Monitor all network traffic
3. **Use private subnets** — Only load balancers in public subnets
4. **Restrict NACL defaults** — Deny all, then allow specific
5. **Use VPC endpoints** — Access AWS services without internet
6. **Enable DNS logging** — Detect data exfiltration via DNS

---

## 3. S3 — Simple Storage Service

S3 is where data lives. It's also the #1 source of AWS data breaches
(misconfigured public buckets).

### Security Checklist:
```bash
# Check if any buckets are public
aws s3api list-buckets --query 'Buckets[].Name' --output text | \
while read bucket; do
    echo "Checking: $bucket"
    aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null || \
        echo "  WARNING: No public access block!"
done
```

### S3 Security Best Practices:
1. **Block all public access** (account-level setting)
2. **Enable encryption** (SSE-S3 minimum, SSE-KMS for sensitive data)
3. **Enable versioning** (recover from accidental deletion or ransomware)
4. **Enable access logging** (audit who accessed what)
5. **Use bucket policies** (restrict access by IP, VPC, or condition)
6. **Enable MFA Delete** (prevent accidental/malicious deletion)

### Secure Bucket Policy:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyUnencryptedUploads",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::my-bucket/*",
            "Condition": {
                "StringNotEquals": {
                    "s3:x-amz-server-side-encryption": "aws:kms"
                }
            }
        },
        {
            "Sid": "DenyNonHTTPS",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": "arn:aws:s3:::my-bucket/*",
            "Condition": {
                "Bool": {
                    "aws:SecureTransport": "false"
                }
            }
        }
    ]
}
```

---

## 4. CloudWatch — Monitoring & Alerting

CloudWatch is your eyes and ears in AWS. Without it, you're flying blind.

### What to Monitor:

| Metric | Alert Threshold | Why |
|--------|----------------|-----|
| Failed API calls | >10/min | Possible attack |
| Root account usage | Any | Should never happen |
| Security group changes | Any | Unauthorized access |
| IAM policy changes | Any | Privilege escalation |
| S3 bucket policy changes | Any | Data exposure risk |
| Unusual data transfer | >1GB/hour | Data exfiltration |

### CloudWatch Alarm Example (Terraform):
```hcl
resource "aws_cloudwatch_metric_alarm" "root_usage" {
  alarm_name          = "root-account-usage"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "RootAccountUsage"
  namespace           = "CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "CRITICAL: Root account was used!"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}
```

---

## 5. AWS Security Services

| Service | Purpose | When to Use |
|---------|---------|-------------|
| GuardDuty | Threat detection | Always on (ML-based) |
| Security Hub | Centralized findings | Aggregate all security data |
| Config | Compliance monitoring | Track resource configurations |
| CloudTrail | API audit logging | Always on (who did what) |
| Inspector | Vulnerability scanning | Scan EC2/containers |
| Macie | Data classification | Find sensitive data in S3 |
| WAF | Web application firewall | Protect APIs/websites |
| KMS | Key management | Encrypt everything |

### Enable These Day 1:
```bash
# Enable CloudTrail (audit all API calls)
aws cloudtrail create-trail \
    --name security-trail \
    --s3-bucket-name my-cloudtrail-logs \
    --is-multi-region-trail \
    --enable-log-file-validation

# Enable GuardDuty (threat detection)
aws guardduty create-detector --enable

# Enable Security Hub
aws securityhub enable-security-hub

# Enable Config (compliance)
aws configservice put-configuration-recorder \
    --configuration-recorder name=default,roleARN=arn:aws:iam::ACCOUNT:role/config-role
```

---

## Memory Technique: "IAM VPC S3 WATCH"

The four pillars of AWS security:
- **I**dentity (IAM) — Who are you? What can you do?
- **V**irtual network (VPC) — Where can traffic flow?
- **S**torage (S3) — Is data encrypted and private?
- **W**atch (CloudWatch/Trail) — Can we see everything?

If all four are locked down, you've covered 90% of AWS security.

---

## Common Mistakes

1. **Using root account for daily work** — Create IAM users
2. **Wildcard permissions (`*`)** — Always be specific
3. **Public S3 buckets** — Block public access at account level
4. **No CloudTrail** — You can't investigate what you didn't log
5. **Security groups with 0.0.0.0/0** — Restrict to known IPs
6. **Hardcoded credentials in code** — Use IAM roles
7. **Single AZ deployment** — Use multiple AZs for resilience
8. **No encryption** — Encrypt at rest AND in transit

---

## Interview Insight

**Q: "Design a secure AWS architecture for a web application."**

"I'd design a three-tier architecture with defense in depth:

**Network Layer:**
- VPC with public, private app, and private data subnets across 2+ AZs
- ALB in public subnet (only thing internet-facing)
- NAT Gateway for outbound-only internet access from private subnets
- VPC Flow Logs enabled, sent to CloudWatch

**Compute Layer:**
- ECS Fargate in private subnets (no SSH access needed)
- IAM roles with least privilege (no access keys)
- Container images scanned before deployment
- Auto-scaling based on load

**Data Layer:**
- RDS in private subnet, encrypted at rest (KMS)
- Security group allows only app tier on port 5432
- Automated backups with point-in-time recovery
- No public accessibility

**Security Services:**
- CloudTrail for API auditing
- GuardDuty for threat detection
- WAF on ALB (OWASP rules, rate limiting)
- Config for compliance monitoring
- Secrets Manager for database credentials

**Monitoring:**
- CloudWatch alarms for anomalies
- SNS notifications to security team
- Dashboard for real-time visibility

This gives us: encryption everywhere, no direct internet access to compute/data,
full audit trail, automated threat detection, and least privilege access."
