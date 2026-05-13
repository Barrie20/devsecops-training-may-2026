# Phase 10 — DevSecOps Security Tools

---

## The Security Toolchain Map

```
CODE TIME          BUILD TIME         DEPLOY TIME        RUN TIME
─────────────      ─────────────      ─────────────      ─────────────
IDE Plugins        SAST               Image Scan         RASP
Pre-commit hooks   SCA/Dependency     IaC Scan           WAF
Secret Detection   License Check      Admission Ctrl     Runtime Monitor
                   SBOM Generation    Policy Check       SIEM/SOAR
                                                         Threat Detection
```

---

## SAST — Static Application Security Testing

SAST scans source code WITHOUT running it. Finds bugs like:
- SQL injection
- Cross-site scripting (XSS)
- Buffer overflows
- Hardcoded credentials
- Insecure cryptography

### SonarQube

The most widely used SAST tool in enterprise.

```bash
# Run SonarQube locally with Docker
docker run -d --name sonarqube \
    -p 9000:9000 \
    -v sonarqube_data:/opt/sonarqube/data \
    sonarqube:community

# Scan a project
# Install sonar-scanner first
sonar-scanner \
    -Dsonar.projectKey=my-app \
    -Dsonar.sources=./src \
    -Dsonar.host.url=http://localhost:9000 \
    -Dsonar.token=YOUR_TOKEN \
    -Dsonar.qualitygate.wait=true  # Fail if quality gate fails
```

**Quality Gate Example (block deployment if):**
- New code coverage < 80%
- Any new critical/blocker issues
- Security hotspots not reviewed
- Duplicated lines > 3%

### Semgrep

Lightweight, fast, pattern-based scanner. Great for custom rules.

```bash
# Install
pip install semgrep

# Run with built-in security rules
semgrep --config=p/security-audit .
semgrep --config=p/owasp-top-ten .
semgrep --config=p/secrets .

# Custom rule example: detect SQL injection in Python
# .semgrep/sql-injection.yml
rules:
  - id: sql-injection-python
    patterns:
      - pattern: |
          cursor.execute(f"... {$VAR} ...")
      - pattern-not: |
          cursor.execute("...", (...))
    message: "Possible SQL injection. Use parameterized queries."
    severity: ERROR
    languages: [python]
```

---

## DAST — Dynamic Application Security Testing

DAST tests the RUNNING application from the outside (like an attacker would).

### OWASP ZAP

Free, open-source web application security scanner.

```bash
# Quick scan (baseline)
docker run -t ghcr.io/zaproxy/zaproxy:stable \
    zap-baseline.py -t https://your-app.com

# Full scan (comprehensive but slow)
docker run -t ghcr.io/zaproxy/zaproxy:stable \
    zap-full-scan.py -t https://your-app.com

# API scan (for REST APIs)
docker run -t ghcr.io/zaproxy/zaproxy:stable \
    zap-api-scan.py -t https://your-app.com/openapi.json -f openapi

# What ZAP finds:
# - SQL Injection
# - XSS (Cross-Site Scripting)
# - CSRF (Cross-Site Request Forgery)
# - Directory traversal
# - Insecure headers
# - Cookie issues
# - Information disclosure
```

---

## Dependency Scanning (SCA — Software Composition Analysis)

80% of your code is third-party libraries. They contain vulnerabilities.

### Trivy (Most Popular Open-Source)

```bash
# Install
# Windows: choco install trivy
# Mac: brew install trivy
# Linux: apt install trivy

# Scan container image
trivy image nginx:latest

# Scan filesystem (project dependencies)
trivy fs .

# Scan with severity filter (CI/CD gate)
trivy image --severity CRITICAL,HIGH --exit-code 1 my-app:latest

# Scan for secrets
trivy fs --scanners secret .

# Scan IaC (Terraform, CloudFormation, Kubernetes)
trivy config ./terraform/

# Scan everything at once
trivy fs --scanners vuln,secret,misconfig .

# Generate SBOM (Software Bill of Materials)
trivy image --format spdx-json -o sbom.json my-app:latest
```

### Snyk

Commercial tool with generous free tier. Deep integration with CI/CD.

```bash
# Install
npm install -g snyk

# Authenticate
snyk auth

# Test project for vulnerabilities
snyk test

# Monitor project (continuous alerts)
snyk monitor

# Test container image
snyk container test my-app:latest

# Test IaC
snyk iac test ./terraform/

# Fix vulnerabilities automatically
snyk fix
```

### Grype (Alternative to Trivy)

```bash
# Install
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh

# Scan image
grype my-app:latest

# Fail on high severity
grype my-app:latest --fail-on high
```

---

## Container Scanning

### Image Scanning Workflow

```bash
# 1. Build image
docker build -t my-app:1.0.0 .

# 2. Scan with Trivy
trivy image --severity CRITICAL,HIGH my-app:1.0.0

# 3. If clean, push to registry
docker push registry.com/my-app:1.0.0

# 4. Scan in registry (continuous)
# Most registries (ECR, GCR, ACR) have built-in scanning
aws ecr start-image-scan \
    --repository-name my-app \
    --image-id imageTag=1.0.0
```

### What Scanners Find in Images:
- OS package vulnerabilities (CVEs in alpine, debian packages)
- Application dependency vulnerabilities
- Embedded secrets (API keys, passwords)
- Misconfigurations (running as root, world-writable files)
- Malware signatures

---

## IaC Scanning

### Checkov

```bash
# Install
pip install checkov

# Scan Terraform
checkov -d ./terraform/

# Scan Kubernetes manifests
checkov -d ./k8s/ --framework kubernetes

# Scan Dockerfile
checkov --dockerfile-path ./Dockerfile

# Scan CloudFormation
checkov -d ./cloudformation/ --framework cloudformation

# Custom policy example
# checkov/custom_policy.py
from checkov.common.models.enums import CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

class S3BucketEncryption(BaseResourceCheck):
    def __init__(self):
        name = "Ensure S3 bucket uses KMS encryption"
        id = "CUSTOM_001"
        supported_resources = ['aws_s3_bucket']
        super().__init__(name=name, id=id, categories=[], supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        # Check for KMS encryption
        if 'server_side_encryption_configuration' in conf:
            return CheckResult.PASSED
        return CheckResult.FAILED
```

---

## Putting It All Together — Security Scanning Pipeline

```yaml
# Complete scanning stage in GitHub Actions
security-scan:
  runs-on: ubuntu-latest
  steps:
    # SAST
    - name: Semgrep
      run: semgrep --config=auto --sarif -o semgrep.sarif .

    # Dependency Scan
    - name: Trivy Filesystem
      run: trivy fs --severity HIGH,CRITICAL --exit-code 1 .

    # Secret Scan
    - name: TruffleHog
      run: trufflehog git file://. --only-verified --fail

    # IaC Scan
    - name: Checkov
      run: checkov -d ./terraform/ --soft-fail false

    # Container Scan (after build)
    - name: Trivy Image
      run: trivy image --severity CRITICAL --exit-code 1 my-app:${{ github.sha }}

    # DAST (after deploy to staging)
    - name: OWASP ZAP
      run: zap-baseline.py -t https://staging.example.com
```

---

## Memory Technique: "SAST SCA DAST RUNTIME"

The four layers of application security testing:
- **SAST** — Scan the code (before it runs)
- **SCA** — Scan the dependencies (what you import)
- **DAST** — Scan the running app (from outside)
- **RUNTIME** — Monitor in production (detect active attacks)

Each catches different things. You need ALL FOUR.

---

## Common Mistakes

1. **Only running SAST** — Misses runtime vulnerabilities
2. **Ignoring findings** — Every "false positive" should be triaged
3. **Not failing the pipeline** — Scans without enforcement are useless
4. **Scanning only on main** — Scan on every PR (shift left!)
5. **No baseline** — Track findings over time, not just point-in-time
6. **Too many tools** — Start with Trivy + Semgrep, add more as needed

---

## Interview Insight

**Q: "How would you implement a security scanning strategy for a large organization?"**

"I'd implement a tiered approach:

**Tier 1 — Developer Workstation (instant feedback):**
- IDE plugins (SonarLint, Snyk)
- Pre-commit hooks (secret detection, basic linting)
- Feedback in seconds, not minutes

**Tier 2 — Pull Request (gate before merge):**
- SAST (Semgrep/SonarQube) — blocks on critical
- SCA (Snyk/Trivy) — blocks on high/critical CVEs
- Secret scanning — blocks on any finding
- IaC scanning — blocks on high-risk misconfigs

**Tier 3 — Build Pipeline (gate before deploy):**
- Container image scanning
- SBOM generation
- Image signing
- Compliance checks

**Tier 4 — Post-Deploy (continuous):**
- DAST against staging
- Runtime monitoring (Falco)
- Continuous vulnerability scanning of deployed images
- Threat detection (GuardDuty)

**Key principles:**
- Fast feedback (developers fix issues in minutes, not days)
- Clear ownership (team owns their findings)
- Exceptions are documented and time-boxed
- Metrics tracked: mean time to remediate, scan pass rate, vulnerability density"
