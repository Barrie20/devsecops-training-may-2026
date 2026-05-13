# Phase 13 — FAANG Interview Preparation

---

## Interview Structure at FAANG Companies

| Round | Duration | Focus |
|-------|----------|-------|
| Phone Screen | 45 min | Technical fundamentals + behavioral |
| System Design | 60 min | Architecture + security design |
| Coding/Automation | 45 min | Python/Bash scripting for DevOps |
| Security Deep Dive | 60 min | Incident response, threat modeling |
| Behavioral | 45 min | Leadership principles, conflict resolution |
| Bar Raiser | 60 min | Cross-functional assessment |

---

## System Design Questions

### Question 1: "Design a secure CI/CD platform for 500 microservices"

**Framework: Requirements → Architecture → Security → Scale → Trade-offs**

```
ANSWER STRUCTURE:

1. CLARIFY REQUIREMENTS (2 min)
   - How many developers? (1000+)
   - Deployment frequency? (multiple per day per service)
   - Compliance requirements? (SOC2, PCI?)
   - Multi-cloud or single cloud?

2. HIGH-LEVEL ARCHITECTURE (10 min)
   
   [Developer] → [Git] → [Pipeline Engine] → [Registry] → [Deploy]
                    ↓           ↓                  ↓           ↓
              [Branch Protect] [Security Scans] [Image Sign] [Canary]
   
   Components:
   - Source: GitHub Enterprise (branch protection, CODEOWNERS)
   - Pipeline: GitHub Actions / Tekton on Kubernetes
   - Registry: ECR with image scanning + signing
   - Deploy: ArgoCD (GitOps) to EKS clusters
   - Secrets: HashiCorp Vault with OIDC
   - Monitoring: Prometheus + Grafana + PagerDuty

3. SECURITY CONTROLS (15 min)
   - Pre-commit: Secret scanning, signed commits
   - Build: SAST, SCA, container scan (mandatory gates)
   - Deploy: Image signature verification (admission controller)
   - Runtime: Falco, network policies, audit logging
   - Access: OIDC everywhere, no long-lived credentials
   - Supply chain: SBOM generation, dependency pinning

4. SCALABILITY (5 min)
   - Auto-scaling runner pools (Kubernetes-based)
   - Caching: Docker layers, dependencies, test results
   - Parallel stages within pipelines
   - Shared pipeline templates (DRY)

5. TRADE-OFFS (5 min)
   - Speed vs Security: Parallel scans minimize impact
   - Flexibility vs Governance: Templates with escape hatches
   - Cost vs Coverage: Tier scanning (critical services get more)
```

---

### Question 2: "Design a system to detect and respond to security incidents"

```
ANSWER:

1. DATA COLLECTION
   ├── CloudTrail (API calls)
   ├── VPC Flow Logs (network traffic)
   ├── Application logs (business logic)
   ├── Container runtime (Falco events)
   ├── WAF logs (web attacks)
   └── DNS logs (C2 communication)

2. PROCESSING PIPELINE
   Sources → Kinesis/Kafka → Lambda/Flink → Elasticsearch
                                  ↓
                          Detection Rules
                          ML Anomaly Detection
                                  ↓
                          Alert Generation

3. DETECTION RULES
   - Threshold: >10 failed logins in 5 min
   - Pattern: Login from new country + sensitive data access
   - Anomaly: Traffic volume 3σ above baseline
   - Correlation: Failed auth + success + privilege escalation

4. RESPONSE AUTOMATION (SOAR)
   - Low confidence: Create ticket, enrich with context
   - Medium confidence: Alert on-call, auto-gather evidence
   - High confidence: Auto-block IP, isolate resource, page team

5. METRICS
   - MTTD: <5 minutes (detection)
   - MTTR: <30 minutes (response)
   - False positive rate: <10%
```

---

### Question 3: "A production Kubernetes cluster is under attack"

```
ANSWER (Incident Response):

MINUTE 0-5: DETECT
- Falco alert: "Shell spawned in container"
- Unusual network traffic from pod to external IP
- kubectl: Check events, pod status, recent deployments

MINUTE 5-15: CONTAIN
- Apply deny-all NetworkPolicy to affected namespace
- kubectl scale deployment/compromised --replicas=0
- Revoke service account tokens
- Block attacker IP at ingress/WAF
- Preserve evidence: kubectl logs, describe pod

MINUTE 15-60: INVESTIGATE
- How did they get in? (vulnerable image? exposed service? stolen creds?)
- What did they access? (audit logs, network flows)
- Did they move laterally? (check other namespaces)
- Did they persist? (new pods, modified configs, cron jobs)

HOUR 1-4: ERADICATE
- Rebuild affected images from clean source
- Rotate ALL secrets in affected namespaces
- Patch the vulnerability that allowed entry
- Redeploy from GitOps (known-good state)

HOUR 4-24: RECOVER
- Verify clean state with security scans
- Gradually restore traffic
- Monitor closely for re-compromise

POST-INCIDENT:
- Write post-mortem (blameless)
- Add detection rules for this attack pattern
- Harden: admission controllers, network policies
- Update runbooks
```

---

## Behavioral Questions (STAR Method)

### "Tell me about a time you disagreed with a team about security."

```
SITUATION: Our development team wanted to skip security scanning to meet
a product deadline. They argued the feature was low-risk.

TASK: I needed to maintain security standards without blocking the team
or damaging the relationship.

ACTION: I proposed a compromise:
1. Ran a quick risk assessment (15 min) to identify actual risk level
2. Offered to run scans in parallel (not blocking their pipeline)
3. Agreed to a time-boxed exception: deploy now, fix findings within 48 hours
4. Created a lightweight "fast-track" pipeline for urgent deploys that
   still ran critical scans (secrets, critical CVEs) but skipped lower-priority ones

RESULT:
- Team shipped on time
- We found 2 medium-severity issues, fixed within 24 hours
- The "fast-track" pipeline became a standard offering
- Team started proactively asking for security reviews earlier
- Built trust: security team seen as enabler, not blocker
```

### "Describe a production incident you handled."

```
SITUATION: At 2am, our monitoring detected unusual API traffic patterns.
A service was making thousands of requests to our user data endpoint.

TASK: Determine if this was an attack or a bug, and respond appropriately.

ACTION:
1. Checked dashboards: 50x normal request volume from one service account
2. Identified the source: a recently deployed microservice with a bug
   (infinite retry loop hitting user API)
3. But during investigation, I noticed the service account had MORE
   permissions than needed (could access ALL user data, not just its own)
4. Immediately: scaled down the buggy service
5. Then: restricted the service account to minimum required permissions
6. Filed a security finding for the over-permissioned service account
7. Added rate limiting to the user data API

RESULT:
- Incident resolved in 23 minutes
- No data breach (bug, not attack)
- But we found a real security gap (over-permissioned account)
- Added automated checks for service account permissions
- Reduced blast radius for future incidents
```

---

## Technical Deep Dive Questions

### "Explain how TLS works"

```
Simple version:
1. Client says hello, lists supported encryption methods
2. Server responds with its certificate (contains public key)
3. Client verifies certificate against trusted CAs
4. Client generates a random session key, encrypts it with server's public key
5. Server decrypts with its private key
6. Both sides now have the session key → all traffic encrypted

Security implications:
- Certificate expiry → service outage (automate renewal with cert-manager)
- Weak ciphers → vulnerable to attacks (enforce TLS 1.3)
- Certificate pinning → prevents MITM even with compromised CA
- mTLS → both sides verify each other (zero trust)
```

### "What's the difference between authentication and authorization?"

```
Authentication (AuthN): WHO are you?
- Proving identity: password, MFA, certificate, biometric
- "I am Alice"

Authorization (AuthZ): WHAT can you do?
- Checking permissions: roles, policies, ACLs
- "Alice can read S3 bucket X but cannot delete it"

In AWS:
- AuthN: IAM user/role credentials, STS tokens
- AuthZ: IAM policies, resource policies, SCPs

In Kubernetes:
- AuthN: Certificates, OIDC tokens, service accounts
- AuthZ: RBAC (Role, ClusterRole, RoleBinding)
```

### "How would you secure a REST API?"

```
1. Authentication: OAuth 2.0 / JWT tokens (not API keys)
2. Authorization: Check permissions per endpoint
3. Input validation: Reject malformed requests
4. Rate limiting: Prevent abuse (per user, per IP)
5. HTTPS only: Redirect HTTP → HTTPS
6. CORS: Restrict allowed origins
7. Headers: HSTS, X-Content-Type-Options, CSP
8. Logging: Log all requests with correlation IDs
9. Versioning: Deprecate insecure old versions
10. WAF: Block common attack patterns (SQLi, XSS)
```

---

## Salary Negotiation

### DevSecOps Salary Ranges (2026, US):

| Level | Range | Companies |
|-------|-------|-----------|
| Junior (0-2 yr) | $90K-$130K | Startups, mid-size |
| Mid (2-5 yr) | $130K-$180K | Enterprise, tech |
| Senior (5-8 yr) | $180K-$250K | FAANG, fintech |
| Staff/Principal (8+ yr) | $250K-$400K+ | FAANG (total comp) |

### Negotiation Tips:
1. **Never give a number first** — "I'm focused on finding the right fit"
2. **Research market rate** — levels.fyi, Glassdoor, Blind
3. **Negotiate total comp** — Base + bonus + equity + signing
4. **Have competing offers** — Leverage creates options
5. **Ask for time** — "I'd like 48 hours to consider"
6. **Negotiate non-salary** — Remote work, PTO, learning budget, title

---

## Memory Technique: Interview Answer Framework

**"STAR + Security"**

For every answer, include:
- **S**ituation — Context
- **T**ask — Your responsibility
- **A**ction — What YOU did (not the team)
- **R**esult — Measurable outcome
- **+Security** — What was the security implication?

This shows you think about security in everything, which is exactly
what FAANG interviewers want from DevSecOps candidates.
