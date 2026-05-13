# DevSecOps Training — Beginner to FAANG-Level

> A complete, hands-on training program to transform you into a FAANG-level DevSecOps engineer capable of designing, securing, and operating production systems at global scale.

---

## How to Use This Repo

Follow the phases in order. Each phase builds on the previous one.
Every folder contains theory, hands-on code, practice exercises, and interview preparation.

---

## Phase 1 — DevSecOps Foundations

**What you'll learn:** DevOps, DevSecOps, CI/CD, shift-left security, modern delivery pipelines.

| File | Description |
|------|-------------|
| `phase-1-foundations/01-setup-guide.md` | Install Git, Docker, AWS CLI, configure your workstation |
| `phase-1-foundations/02-first-pipeline.yml` | Your first secure GitHub Actions CI/CD pipeline |
| `phase-1-foundations/03-concepts-cheatsheet.md` | Key terms, tools map, memory techniques |
| `phase-1-foundations/04-interview-questions.md` | FAANG interview Q&A with answer frameworks |

---

## Phase 2 — Linux & Bash Mastery

**What you'll learn:** Filesystem, permissions, processes, networking, scripting for security.

| File | Description |
|------|-------------|
| `phase-2-linux-bash/01-linux-essentials.md` | Essential commands grouped by purpose (grep, awk, sed, find, chmod) |
| `phase-2-linux-bash/02-log-monitor-advanced.sh` | Advanced security monitoring script (brute force, sudo, SSH, ports) |
| `log_monitor.sh` | Your first log monitor script (starter version) |

---

## Phase 3 — Python for DevSecOps

**What you'll learn:** Automation, API interaction, log parsing, security scripting with boto3, requests, argparse.

| File | Description |
|------|-------------|
| `phase-3-python/01-aws-inventory.py` | AWS resource inventory with security audit (EC2, S3, IAM, Security Groups) |
| `phase-3-python/02-log-analyzer.py` | Security log analyzer — detects brute force, credential stuffing, compromised accounts |
| `phase-3-python/03-vulnerability-scanner.py` | Dependency vulnerability scanner using OSV API |

---

## Phase 4 — SQL for Security & Monitoring

**What you'll learn:** Querying logs, detecting attacks, building security dashboards with SQL.

| File | Description |
|------|-------------|
| `phase-4-sql-security/01-sql-for-devsecops.md` | SQL fundamentals + real-world security queries (brute force, exfiltration, CloudWatch) |
| `phase-4-sql-security/02-security-db-setup.sql` | Complete database schema + simulated attack scenario data |
| `phase-4-sql-security/03-practice-exercises.sql` | 8 hands-on exercises — investigate a breach using SQL |

---

## Phase 5 — Java Foundations for DevSecOps

**What you'll learn:** JVM, Maven, Gradle, dependency scanning, securing Java applications, Log4Shell response.

| File | Description |
|------|-------------|
| `phase-5-java/01-java-for-devsecops.md` | Build systems, dependency scanning, secure Dockerfiles for Java, zero-day response |

---

## Phase 6 — AWS Cloud Mastery

**What you'll learn:** IAM, VPC, S3, CloudWatch, security services, least privilege, network segmentation.

| File | Description |
|------|-------------|
| `phase-6-aws/01-aws-security-fundamentals.md` | IAM policies, VPC architecture, S3 hardening, GuardDuty, Security Hub |
| `phase-6-aws/02-secure-infrastructure.tf` | Production Terraform: 3-tier VPC, flow logs, security groups, NAT gateway |

---

## Phase 7 — Infrastructure as Code

**What you'll learn:** Terraform deep dive, state management, modules, security scanning, CloudFormation.

| File | Description |
|------|-------------|
| `phase-7-iac/01-terraform-deep-dive.md` | State security, secrets handling, Checkov scanning, drift detection |
| `phase-7-iac/02-complete-stack.tf` | Full stack: KMS, ECS Fargate, RDS encrypted, IAM least privilege, CloudWatch alarms |

---

## Phase 8 — Containers & Kubernetes Security

**What you'll learn:** Docker hardening, image scanning, K8s RBAC, network policies, runtime security, Falco.

| File | Description |
|------|-------------|
| `phase-8-containers-k8s/01-docker-security.md` | Secure Dockerfile (14 rules), Docker Compose hardening, K8s security architecture, incident response |
| `phase-8-containers-k8s/02-k8s-security-configs.yaml` | 12 production configs: Pod Security Standards, NetworkPolicies, RBAC, Kyverno policies |

---

## Phase 9 — CI/CD Pipelines

**What you'll learn:** GitHub Actions, GitLab CI, Jenkins, secrets management, pipeline hardening.

| File | Description |
|------|-------------|
| `phase-9-cicd/01-cicd-security.md` | Pipeline threat model, security controls, complete pipelines for 3 platforms |
| `phase-9-cicd/02-github-actions-complete.yml` | Production-ready 7-stage pipeline with all security gates |
| `phase-9-cicd/03-secrets-management.md` | OIDC, Vault integration, pre-commit detection, leak response playbook |

---

## Phase 10 — DevSecOps Security Tools

**What you'll learn:** SAST (SonarQube, Semgrep), DAST (OWASP ZAP), SCA (Trivy, Snyk), IaC scanning (Checkov).

| File | Description |
|------|-------------|
| `phase-10-security-tools/01-security-tools-guide.md` | Complete tool guide with commands, CI/CD integration, custom rules |

---

## Phase 11 — Observability & Monitoring

**What you'll learn:** Prometheus, Grafana, ELK stack, CloudWatch, security alerting, incident detection patterns.

| File | Description |
|------|-------------|
| `phase-11-observability/01-monitoring-guide.md` | PromQL for security, Grafana dashboards, Fluent Bit, CloudWatch Logs Insights |

---

## Phase 12 — Advanced DevSecOps Concepts

**What you'll learn:** Zero Trust, threat modeling (STRIDE), supply chain security, Vault, OPA, Kyverno.

| File | Description |
|------|-------------|
| `phase-12-advanced/01-advanced-devsecops.md` | Service mesh mTLS, SLSA framework, Vault policies, OPA/Kyverno policy-as-code |

---

## Phase 13 — FAANG Interview Preparation

**What you'll learn:** System design, security architecture, behavioral questions, salary negotiation.

| File | Description |
|------|-------------|
| `phase-13-interview-prep/01-faang-interview-guide.md` | 3 full system design answers, STAR method examples, technical deep dives |

---

## Phase 14 — Networking & Industry Influence

**What you'll learn:** LinkedIn strategy, message templates, community engagement, open source contributions.

| File | Description |
|------|-------------|
| `phase-14-networking/01-networking-strategy.md` | Content calendar, connection templates, community list, conference speaking |

---

## Phase 15 — Personal Branding Strategy

**What you'll learn:** GitHub portfolio, technical blogging, speaking progression, 90-day brand plan.

| File | Description |
|------|-------------|
| `phase-15-branding/01-personal-brand.md` | Profile README template, blog post ideas, contribution roadmap |

---

## Phase 16 — Real-World DevSecOps Scenarios

**What you'll learn:** Incident response for cloud breaches, pipeline compromise, container escapes, secret leaks, zero-days.

| File | Description |
|------|-------------|
| `phase-16-scenarios/01-real-world-scenarios.md` | 5 complete scenarios with detection, mitigation, prevention, and interview application |

---

## Bonus Resources

| File | Description |
|------|-------------|
| `90-day-training-plan.md` | Day-by-day learning roadmap with daily routine template |

---

## Quick Start

```bash
# Clone this repo
git clone https://github.com/Barrie20/devsecops-training-may-2026.git
cd devsecops-training-may-2026

# Start with Phase 1
# Open phase-1-foundations/01-setup-guide.md and follow the instructions
```

---

## Prerequisites

- Windows, Mac, or Linux machine
- Internet connection
- Git installed
- Willingness to learn daily (1-3 hours)

---

## Tech Stack Covered

| Category | Tools |
|----------|-------|
| Version Control | Git, GitHub |
| Containers | Docker, Kubernetes, ECS, EKS |
| Cloud | AWS (IAM, VPC, S3, EC2, Lambda, CloudWatch) |
| IaC | Terraform, CloudFormation |
| CI/CD | GitHub Actions, GitLab CI, Jenkins |
| Security Scanning | Trivy, Snyk, SonarQube, Semgrep, OWASP ZAP, Checkov |
| Monitoring | Prometheus, Grafana, ELK, CloudWatch |
| Secrets | HashiCorp Vault, AWS Secrets Manager, OIDC |
| Policy | OPA, Kyverno, Sentinel |
| Runtime Security | Falco, GuardDuty |
| Languages | Python, Bash, SQL, HCL (Terraform) |
