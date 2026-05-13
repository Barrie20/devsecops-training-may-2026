# Phase 1 — Concepts Cheatsheet

## Mental Model: The DevSecOps Infinity Loop

```
    PLAN → CODE → BUILD → TEST
     ↑                        ↓
  MONITOR ← OPERATE ← RELEASE ← DEPLOY
```

Security wraps around EVERY stage like armor.

---

## Key Terms to Memorize

| Term | Simple Definition | Security Angle |
|------|-------------------|----------------|
| CI | Auto-build & test on every commit | Catches vulns before merge |
| CD | Auto-deploy after tests pass | No manual errors in deploys |
| IaC | Infrastructure defined in code files | Auditable, reviewable infra |
| Container | Lightweight app package | Isolated, scannable, immutable |
| Microservice | Small independent service | Blast radius limited |
| Shift Left | Find problems earlier | Cheaper, faster fixes |
| Zero Trust | Never trust, always verify | No implicit network trust |
| Least Privilege | Minimum permissions needed | Limits breach damage |
| Immutable | Replace, never patch | No drift, clean state |
| GitOps | Git as single source of truth | Full audit trail |

---

## Memory Technique: "SECURE PIPELINE" Acronym

**S** - Scan code for secrets
**E** - Evaluate dependencies
**C** - Compile and build
**U** - Unit test everything
**R** - Review container images
**E** - Enforce policies

**P** - Push to staging
**I** - Integration test
**P** - Penetration test (DAST)
**E** - Environment validation
**L** - Launch to production
**I** - Instrument monitoring
**N** - Notify on anomalies
**E** - Evaluate and improve

---

## Common Mistakes (Beginners)

1. **Committing secrets to Git** — Use .gitignore and secret scanners
2. **Running containers as root** — Always use non-root users
3. **Using `latest` tag** — Pin specific versions for reproducibility
4. **No branch protection** — Always require PR reviews
5. **Hardcoding credentials** — Use secrets managers (Vault, AWS Secrets Manager)
6. **Skipping security scans** — Make them mandatory pipeline gates
7. **No monitoring** — You can't secure what you can't see

---

## Interview Insight

**Q: "What is DevSecOps and why is it important?"**

**Strong answer framework (STAR method):**

"DevSecOps integrates security practices into every phase of the software
delivery lifecycle. Instead of security being a gate at the end, it's
embedded from the first line of code.

At [company], I implemented this by:
- Adding SAST scanning in pre-commit hooks (catches issues in seconds)
- Integrating dependency scanning in CI (blocks vulnerable libraries)
- Running DAST against staging environments (finds runtime vulns)
- Implementing runtime security monitoring (detects active threats)

The result was a 70% reduction in production vulnerabilities and
deployment frequency increased from weekly to multiple times per day
because security was no longer a bottleneck."

**Key phrases interviewers want to hear:**
- "Shift left"
- "Automated security gates"
- "Defense in depth"
- "Least privilege"
- "Continuous compliance"

---

## Tools Map — What Goes Where

```
CODE PHASE:
  - IDE security plugins (SonarLint, Snyk)
  - Pre-commit hooks (detect secrets, lint)
  - Git (version control)

BUILD PHASE:
  - SAST (SonarQube, Semgrep, CodeQL)
  - Dependency scan (Snyk, Dependabot, OWASP Dep Check)
  - Container build (Docker, Buildah)

TEST PHASE:
  - Container scan (Trivy, Grype)
  - DAST (OWASP ZAP, Burp Suite)
  - IaC scan (Checkov, tfsec)

DEPLOY PHASE:
  - Kubernetes (EKS, GKE)
  - GitOps (ArgoCD, Flux)
  - Policy enforcement (OPA, Kyverno)

RUN PHASE:
  - Monitoring (Prometheus, Grafana)
  - Logging (ELK, CloudWatch)
  - Runtime security (Falco, GuardDuty)
  - Secrets management (Vault, AWS Secrets Manager)
```

---

## Daily Practice Questions

1. What's the difference between SAST and DAST?
2. Why should you never use `latest` as a container tag?
3. What is "least privilege" and give an example?
4. Name 3 things that should NEVER be in a Git repository.
5. What happens if you don't scan dependencies?
