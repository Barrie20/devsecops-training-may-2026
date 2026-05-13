# Phase 9 — Secrets Management in CI/CD

---

## The #1 Rule of Secrets

**If a secret is in your code, it's already compromised.**

GitHub scans every public commit. Bots harvest exposed credentials within
seconds. AWS keys posted to GitHub are exploited in under 5 minutes.

---

## Secrets Hierarchy (Best to Worst)

| Method | Security Level | Use Case |
|--------|---------------|----------|
| OIDC / Workload Identity | ★★★★★ | Cloud access from CI/CD |
| External Secrets Manager | ★★★★☆ | Application secrets |
| CI/CD Platform Secrets | ★★★☆☆ | Pipeline-specific secrets |
| Encrypted files in repo | ★★☆☆☆ | Last resort (SOPS, age) |
| Environment variables | ★☆☆☆☆ | Avoid (visible in logs) |
| Hardcoded in code | ☆☆☆☆☆ | NEVER |

---

## OIDC — The Gold Standard (No Secrets at All!)

Instead of storing AWS credentials in GitHub, use OIDC:

```yaml
# GitHub Actions trusts AWS, AWS trusts GitHub
# No long-lived credentials anywhere!

permissions:
  id-token: write  # Required for OIDC

steps:
  - name: Configure AWS credentials
    uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::123456789:role/github-actions-role
      aws-region: us-east-1
      # No access key! No secret key! Just a role.
```

AWS IAM Role trust policy:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::123456789:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
      },
      "StringLike": {
        "token.actions.githubusercontent.com:sub": "repo:myorg/myrepo:ref:refs/heads/main"
      }
    }
  }]
}
```

---

## HashiCorp Vault Integration

```yaml
# Fetch secrets from Vault in pipeline
steps:
  - name: Import Secrets from Vault
    uses: hashicorp/vault-action@v2
    with:
      url: https://vault.company.com
      method: jwt
      role: github-actions
      secrets: |
        secret/data/production/db password | DB_PASSWORD ;
        secret/data/production/api key | API_KEY

  - name: Use secrets (they're masked in logs)
    run: |
      echo "Connecting to database..."
      # $DB_PASSWORD is available but masked in logs
```

---

## Pre-commit Secret Detection

```bash
# Install git-secrets
git secrets --install
git secrets --register-aws

# Or use pre-commit framework
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
```

---

## What to Do If a Secret is Leaked

1. **Rotate immediately** — Change the credential NOW
2. **Revoke the old one** — Don't just create a new one
3. **Check for usage** — Was it exploited? Check CloudTrail/logs
4. **Remove from Git history** — `git filter-branch` or BFG Repo-Cleaner
5. **Add scanning** — Prevent it from happening again
6. **Post-mortem** — How did it get committed?

```bash
# Remove secret from Git history (BFG is faster than filter-branch)
bfg --replace-text passwords.txt my-repo.git
git reflog expire --expire=now --all
git gc --prune=now --aggressive
git push --force
```

---

## Memory Technique: "NEVER STORE, ALWAYS ROTATE"

- **N**ever hardcode secrets
- **E**ncrypt at rest and in transit
- **V**ault or secrets manager for storage
- **E**xpire credentials automatically
- **R**otate on schedule (90 days max)

- **S**can for leaks continuously
- **T**oken-based auth over passwords
- **O**IDC over long-lived keys
- **R**evoke immediately on exposure
- **E**nforce with automation (not humans)
