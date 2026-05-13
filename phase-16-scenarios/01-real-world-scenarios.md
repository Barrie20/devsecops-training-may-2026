# Phase 16 — Real-World DevSecOps Scenarios

---

## Scenario 1: Cloud Breach Investigation

### Situation:
AWS GuardDuty alerts: "Unusual API calls from IAM user 'deploy-bot'
to regions your organization doesn't use (ap-southeast-1)."

### Detection:
```bash
# Check CloudTrail for the user's recent activity
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=deploy-bot \
    --start-time "2026-05-10T00:00:00Z" \
    --max-results 50

# Check what resources were created in unusual region
aws ec2 describe-instances --region ap-southeast-1
aws ec2 describe-security-groups --region ap-southeast-1
```

### Investigation Findings:
- deploy-bot's access key was exposed in a public GitHub commit 3 hours ago
- Attacker used the key to launch 20 EC2 instances (crypto mining)
- Attacker created a new IAM user with admin access
- Attacker opened security group to 0.0.0.0/0

### Mitigation:
```bash
# 1. Disable the compromised access key IMMEDIATELY
aws iam update-access-key --user-name deploy-bot \
    --access-key-id AKIA... --status Inactive

# 2. Delete the attacker's IAM user
aws iam delete-user --user-name attacker-user

# 3. Terminate unauthorized EC2 instances
aws ec2 terminate-instances --region ap-southeast-1 \
    --instance-ids i-xxx i-yyy i-zzz

# 4. Revert security group changes
aws ec2 revoke-security-group-ingress --region ap-southeast-1 \
    --group-id sg-xxx --protocol tcp --port 0-65535 --cidr 0.0.0.0/0

# 5. Rotate ALL credentials for the affected user
aws iam create-access-key --user-name deploy-bot
# Update all systems using the old key

# 6. Enable SCP to block unused regions
# (Prevents future attacks in regions you don't use)
```

### Prevention:
- Use OIDC instead of long-lived access keys
- Enable GitHub secret scanning
- Use AWS Organizations SCPs to restrict regions
- Set up billing alerts for unexpected charges
- Implement credential rotation every 90 days

---

## Scenario 2: Compromised CI/CD Pipeline

### Situation:
A developer reports that a production deployment included code changes
that weren't in any pull request. The deployed artifact contains a
cryptocurrency miner.

### Detection:
```bash
# Check pipeline execution history
# Who triggered the last deployment?
gh run list --workflow=deploy.yml --limit=10

# Compare deployed artifact with expected
# Check image digest vs what was built
docker inspect registry.com/app:latest | jq '.[0].Id'

# Check for modified workflow files
git log --oneline --all -- .github/workflows/
```

### Investigation Findings:
- Attacker compromised a developer's GitHub token (phishing)
- Modified the workflow file to inject malicious code during build
- The modification bypassed branch protection (token had admin access)
- Malicious code was added as a build step, not in source code

### Mitigation:
```bash
# 1. Revoke compromised token
# GitHub Settings → Developer Settings → Personal Access Tokens → Revoke

# 2. Roll back deployment
kubectl rollout undo deployment/app --namespace=production

# 3. Rebuild from known-good commit
git revert HEAD
git push origin main

# 4. Audit all recent pipeline runs
# Check for any other modified workflows

# 5. Rotate all secrets that the pipeline had access to
# (The attacker may have exfiltrated them)
```

### Prevention:
- Require signed commits
- Use environment protection rules (require approval for production)
- Pin all GitHub Actions to specific SHA (not tags)
- Enable audit logging for all repository changes
- Use CODEOWNERS for workflow files (require security team review)
- Implement SLSA provenance verification

---

## Scenario 3: Container Escape Attack

### Situation:
Falco alert: "Container attempted to mount host filesystem.
Process 'nsenter' detected in container 'web-app'."

### Detection:
```bash
# Check Falco alerts
kubectl logs -n falco daemonset/falco | grep "Critical"

# Check the suspicious pod
kubectl describe pod web-app-xyz -n production
kubectl logs web-app-xyz -n production

# Check if attacker reached the host
# Look for processes that shouldn't exist
kubectl exec -it NODE_DEBUG_POD -- ps aux | grep -v "normal-process"
```

### Investigation Findings:
- Attacker exploited a known vulnerability in the application (RCE)
- Container was running as root (misconfiguration)
- Container had `privileged: true` (should never be in production)
- Attacker used `nsenter` to escape to the host node
- From the host, attacker accessed other containers' secrets

### Mitigation:
```bash
# 1. Isolate the node
kubectl cordon NODE_NAME
kubectl drain NODE_NAME --force --ignore-daemonsets

# 2. Kill the compromised pod
kubectl delete pod web-app-xyz -n production --force

# 3. Apply emergency network policy
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: emergency-isolate
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: web-app
  policyTypes:
  - Ingress
  - Egress
EOF

# 4. Rotate all secrets on the affected node
# 5. Rebuild the node from clean image
# 6. Redeploy with proper security context
```

### Prevention:
- Never run containers as root
- Never use `privileged: true`
- Drop ALL capabilities
- Use Pod Security Standards (restricted)
- Implement admission controllers (Kyverno/OPA)
- Enable seccomp and AppArmor profiles
- Regular vulnerability scanning of images

---

## Scenario 4: Secrets Leak in GitHub

### Situation:
GitHub Secret Scanning alert: "AWS access key detected in commit
abc123 on repository 'company/backend-api'."

### Detection:
```bash
# Check when the secret was committed
git log --all --oneline -- | head -20
git show abc123

# Check if the key has been used
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA...
```

### Response Timeline:

**Minute 0-5:**
```bash
# IMMEDIATELY rotate the credential
aws iam update-access-key --user-name SERVICE_USER \
    --access-key-id AKIA... --status Inactive
aws iam create-access-key --user-name SERVICE_USER
# Update the service with new key
```

**Minute 5-15:**
```bash
# Check for unauthorized usage
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA... \
    --start-time "2026-05-01T00:00:00Z"

# Look for: unusual regions, unusual services, unusual times
```

**Minute 15-60:**
```bash
# Remove from Git history
# Option 1: BFG Repo-Cleaner (faster)
bfg --replace-text secrets.txt repo.git

# Option 2: git filter-repo
git filter-repo --invert-paths --path-match "file-with-secret"

# Force push (coordinate with team!)
git push --force --all
```

**Hour 1-24:**
- Audit all services using that credential
- Check for data access during exposure window
- Implement pre-commit hooks to prevent recurrence
- Add the pattern to secret scanning custom patterns

### Prevention:
- Pre-commit hooks (git-secrets, detect-secrets)
- GitHub secret scanning (enabled by default on public repos)
- Use OIDC/IAM roles instead of access keys
- .gitignore for all credential files
- Developer training on secret hygiene

---

## Scenario 5: Zero-Day Vulnerability Response

### Situation:
A critical zero-day CVE is published for a library your organization
uses extensively (like Log4Shell, Spring4Shell, or similar).

### Response Framework:

**Hour 0-1: Assessment**
```bash
# Identify all affected systems
# Search all repositories for the vulnerable dependency
grep -r "vulnerable-library" --include="pom.xml" --include="package.json" \
    --include="requirements.txt" /path/to/all/repos/

# Search container registry
trivy image --vuln-type library registry.com/app1:latest | grep "CVE-XXXX"
trivy image --vuln-type library registry.com/app2:latest | grep "CVE-XXXX"

# Generate list of affected services
# Prioritize by: internet-facing > internal > dev
```

**Hour 1-4: Immediate Mitigation**
```bash
# Apply WAF rules to block known exploit patterns
aws wafv2 update-rule-group \
    --name "emergency-block" \
    --rules '[{"Name":"block-exploit","Priority":1,...}]'

# Apply temporary workaround if available
# (e.g., for Log4Shell: -Dlog4j2.formatMsgNoLookups=true)

# Increase monitoring sensitivity
# Lower alert thresholds for affected services
```

**Hour 4-24: Patching**
```bash
# Update dependency version
# For each affected project:
cd project-dir
# Update version in dependency file
# Run tests
# Build new container image
# Deploy to staging → verify → deploy to production

# Track progress
# Spreadsheet: Service | Version | Status | Owner | ETA
```

**Hour 24-72: Verification**
```bash
# Scan ALL systems to confirm no vulnerable versions remain
for image in $(aws ecr list-images --repository-name app --output text); do
    trivy image $image | grep "CVE-XXXX" && echo "STILL VULNERABLE: $image"
done

# Review logs for exploitation attempts during exposure window
# Check CloudTrail, application logs, WAF logs
```

**Post-Incident:**
- Generate SBOM for all services (know your dependencies)
- Implement automated alerting for new critical CVEs
- Add the specific CVE check to all pipelines permanently
- Conduct retrospective: How fast were we? Where were gaps?
- Update incident response runbook

---

## Scenario Summary Table

| Scenario | Detection Time Target | Response Time Target | Key Tool |
|----------|----------------------|---------------------|----------|
| Cloud breach | <15 min | <1 hour | GuardDuty + CloudTrail |
| Pipeline compromise | <1 hour | <2 hours | Audit logs + SLSA |
| Container escape | <5 min | <15 min | Falco + Network Policies |
| Secret leak | <1 min | <5 min | GitHub Scanning + rotation |
| Zero-day | <1 hour | <4 hours (mitigate) | Trivy + SBOM + WAF |

---

## Memory Technique: "DETECT CONTAIN INVESTIGATE RECOVER"

Every incident follows this pattern:
1. **DETECT** — How did we find out? (monitoring, alerts, reports)
2. **CONTAIN** — Stop the bleeding (isolate, block, disable)
3. **INVESTIGATE** — What happened? (logs, forensics, timeline)
4. **RECOVER** — Return to normal (patch, redeploy, verify)
5. **LEARN** — Prevent recurrence (post-mortem, automation, training)

---

## Interview Application

When asked about any security scenario in an interview:

1. **Stay calm** — Methodical response shows experience
2. **Prioritize** — Containment before investigation
3. **Communicate** — Who needs to know? (management, legal, customers?)
4. **Document** — Everything you do, with timestamps
5. **Prevent** — Always end with "here's how I'd prevent this next time"

This framework works for ANY incident question they throw at you.
