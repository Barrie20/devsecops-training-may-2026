# Phase 1 — FAANG Interview Questions & Answers

---

## Q1: "Explain the CI/CD pipeline you would design for a microservices application."

### Strong Answer:

"I'd design a pipeline with security gates at every stage:

**Trigger:** Developer pushes to a feature branch.

**Stage 1 — Pre-commit (local):**
- Secret detection (git-secrets or trufflehog)
- Linting and formatting
- Unit tests

**Stage 2 — CI (automated on push):**
- SAST scan (SonarQube/Semgrep) — blocks on critical findings
- Dependency vulnerability scan (Snyk) — blocks on high/critical CVEs
- Build container image with pinned base image
- Container image scan (Trivy) — blocks on critical vulns
- Unit + integration tests with coverage threshold

**Stage 3 — CD to Staging:**
- Deploy to staging via GitOps (ArgoCD)
- DAST scan (OWASP ZAP) against staging
- Performance/load testing
- Smoke tests

**Stage 4 — Production Deploy:**
- Canary deployment (5% traffic)
- Monitor error rates, latency, security signals
- Progressive rollout (25% → 50% → 100%)
- Automated rollback on anomaly detection

**Observability:**
- Centralized logging (ELK/CloudWatch)
- Metrics (Prometheus/Grafana)
- Distributed tracing (Jaeger/X-Ray)
- Security alerting (GuardDuty, Falco)"

---

## Q2: "What is Infrastructure as Code and why is it critical for security?"

### Strong Answer:

"IaC means defining all infrastructure — servers, networks, databases,
permissions — in version-controlled code files rather than manual configuration.

**Security benefits:**

1. **Audit trail** — Every change is a Git commit with author, timestamp, and reason
2. **Peer review** — Infrastructure changes go through pull requests
3. **Consistency** — No configuration drift between environments
4. **Compliance** — Policies can be enforced automatically (OPA, Sentinel)
5. **Disaster recovery** — Rebuild entire infrastructure from code in minutes
6. **Drift detection** — Alert when actual state differs from desired state

**Real example:** At [company], we caught a misconfigured S3 bucket
(public access enabled) during PR review of a Terraform change.
Without IaC, that would have gone to production unnoticed."

---

## Q3: "A developer wants to deploy directly to production. How do you handle this?"

### Strong Answer:

"I'd approach this collaboratively, not as a blocker:

1. **Understand the urgency** — Is this a critical hotfix?
2. **Explain the risk** — Skipping gates means unscanned code in production
3. **Offer a fast path** — Emergency pipeline that still runs critical scans
   but skips non-essential checks (e.g., skip performance tests, keep security scans)
4. **Document the exception** — Log who approved, why, and what was skipped
5. **Follow up** — Run full scans post-deploy, create ticket for any findings

The goal is to enable velocity while maintaining security guardrails.
A good DevSecOps engineer never says 'no' — they say 'here's how we do it safely.'"

---

## Q4: "What's the difference between mutable and immutable infrastructure?"

### Strong Answer:

"**Mutable:** You update servers in place (SSH in, run apt upgrade, change configs).
Over time, each server becomes unique — 'snowflake servers.'

**Immutable:** You never modify running servers. Instead:
1. Build a new image with the change
2. Deploy new instances from that image
3. Destroy old instances

**Security implications:**
- Mutable: Hard to audit what changed, configuration drift, persistent threats
- Immutable: Known-good state, no drift, attackers can't persist (server gets replaced)

At Netflix, every EC2 instance is immutable. If compromised, it's terminated
and replaced from a clean AMI within minutes. Attackers lose their foothold."

---

## Q5: "How would you secure a CI/CD pipeline itself?"

### Strong Answer:

"The pipeline is a high-value target — if compromised, attackers can inject
malicious code into every deployment. I'd secure it with:

1. **Access control** — Least privilege for pipeline service accounts
2. **Secrets management** — No secrets in code; use Vault or cloud secrets manager
3. **Signed commits** — Verify code authenticity with GPG signatures
4. **Immutable build environments** — Fresh containers for each build
5. **Artifact signing** — Sign built artifacts, verify before deploy
6. **Audit logging** — Log all pipeline executions and config changes
7. **Network isolation** — Pipeline runs in isolated network segment
8. **Dependency pinning** — Lock all tool versions to prevent supply chain attacks
9. **Branch protection** — Require reviews, no force pushes to main
10. **Self-hosted runners** — Control the build environment (for sensitive workloads)"

---

## Behavioral Questions

### "Tell me about a time you improved security in a development process."

**Framework:** Use STAR (Situation, Task, Action, Result)

**Example answer:**
"**Situation:** Our team was deploying 20+ times per day but had no automated
security scanning. Vulnerabilities were found in production by external researchers.

**Task:** Implement security scanning without slowing down deployments.

**Action:** I introduced a three-tier scanning approach:
- Pre-commit hooks for secrets (instant feedback)
- SAST + dependency scan in CI (2-minute addition to pipeline)
- Weekly deep DAST scans against staging

I made critical findings block the pipeline but medium/low findings
created tickets without blocking.

**Result:** 
- 85% reduction in production vulnerabilities within 3 months
- Zero increase in deployment time (scans run in parallel)
- Developers started fixing issues proactively because feedback was immediate"
