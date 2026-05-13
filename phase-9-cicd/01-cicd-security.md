# Phase 9 — Secure CI/CD Pipeline Design

---

## Why CI/CD Security Matters

Your CI/CD pipeline has:
- Access to source code (intellectual property)
- Access to secrets (API keys, credentials)
- Access to production (deployment permissions)
- Access to artifact registries (supply chain)

**If an attacker compromises your pipeline, they own everything.**

Real-world attacks:
- **SolarWinds (2020)** — Attackers injected malware into the build pipeline
- **Codecov (2021)** — Compromised CI script exfiltrated secrets from 29,000 repos
- **ua-parser-js (2021)** — Malicious code injected into npm package via CI

---

## Secure Pipeline Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    SECURE CI/CD PIPELINE                  │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  [Developer] → [Git Push] → [Pipeline Triggers]         │
│                                                          │
│  Stage 1: PRE-BUILD SECURITY                            │
│  ├── Secret scanning (TruffleHog)                       │
│  ├── Commit signature verification                       │
│  └── Branch protection enforcement                       │
│                                                          │
│  Stage 2: BUILD                                          │
│  ├── Isolated build environment (ephemeral)              │
│  ├── Dependency resolution (locked versions)             │
│  ├── SAST scanning (SonarQube/Semgrep)                  │
│  └── Dependency vulnerability scan (Snyk)               │
│                                                          │
│  Stage 3: CONTAINER                                      │
│  ├── Build image (multi-stage, non-root)                │
│  ├── Image scanning (Trivy)                             │
│  ├── Image signing (Cosign)                             │
│  └── Push to private registry                           │
│                                                          │
│  Stage 4: TEST                                           │
│  ├── Unit tests                                          │
│  ├── Integration tests                                   │
│  ├── DAST scanning (OWASP ZAP)                          │
│  └── Infrastructure scanning (Checkov)                   │
│                                                          │
│  Stage 5: DEPLOY                                         │
│  ├── Deploy to staging (GitOps/ArgoCD)                  │
│  ├── Smoke tests                                         │
│  ├── Canary deployment (5% → 25% → 100%)               │
│  └── Automated rollback on failure                       │
│                                                          │
│  Stage 6: POST-DEPLOY                                    │
│  ├── Runtime security monitoring                         │
│  ├── Performance baseline comparison                     │
│  └── Security alert correlation                          │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

---

## Pipeline Security Controls

### 1. Secrets Management

**NEVER do this:**
```yaml
# BAD — Secrets in pipeline code
env:
  AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE
  DB_PASSWORD: supersecret123
```

**ALWAYS do this:**
```yaml
# GOOD — Secrets from secure store
env:
  AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
  DB_PASSWORD: ${{ secrets.DB_PASSWORD }}

# BETTER — Use OIDC (no long-lived secrets at all)
permissions:
  id-token: write
steps:
  - uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::ACCOUNT:role/github-actions
      aws-region: us-east-1
```

### 2. Immutable Build Environments

```yaml
# Each build runs in a fresh container — no persistence
jobs:
  build:
    runs-on: ubuntu-latest  # Fresh VM every time
    container:
      image: node:20.11-alpine  # Pinned version
      options: --read-only      # Can't modify container
```

### 3. Artifact Signing

```bash
# Sign container images with Cosign
cosign sign --key cosign.key registry.com/app:1.0.0

# Verify before deployment
cosign verify --key cosign.pub registry.com/app:1.0.0
```

### 4. Pipeline Access Control

```yaml
# Require approval for production deployments
deploy-production:
  environment:
    name: production
    url: https://app.company.com
  # Requires manual approval from security team
  # Configure in GitHub Settings → Environments → Required reviewers
```

---

## Complete GitHub Actions Pipeline

```yaml
# .github/workflows/secure-pipeline.yml
name: Secure CI/CD Pipeline

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

# Security: Minimal permissions by default
permissions:
  contents: read
  security-events: write
  id-token: write  # For OIDC

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  # ============================================================
  # Stage 1: Security Scanning
  # ============================================================
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for secret scanning

      - name: TruffleHog Secret Scan
        uses: trufflesecurity/trufflehog@main
        with:
          extra_args: --only-verified --results=verified

  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Semgrep SAST
        uses: semgrep/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/secrets
            p/owasp-top-ten

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: semgrep.sarif

  dependency-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Snyk Dependency Check
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high

  # ============================================================
  # Stage 2: Build & Test
  # ============================================================
  build:
    needs: [secret-scan, sast, dependency-scan]
    runs-on: ubuntu-latest
    outputs:
      image-digest: ${{ steps.build.outputs.digest }}
    steps:
      - uses: actions/checkout@v4

      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Run unit tests
        run: npm test -- --coverage

      - name: Build application
        run: npm run build

      # Container build
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to registry
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push image
        id: build
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: |
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:latest
          cache-from: type=gha
          cache-to: type=gha,mode=max

  # ============================================================
  # Stage 3: Container Security
  # ============================================================
  image-scan:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - name: Trivy Image Scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'

      - name: Upload Trivy results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'trivy-results.sarif'

  # ============================================================
  # Stage 4: Infrastructure Scanning
  # ============================================================
  iac-scan:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Checkov IaC Scan
        uses: bridgecrewio/checkov-action@master
        with:
          directory: ./terraform
          framework: terraform
          output_format: sarif
          soft_fail: false

  # ============================================================
  # Stage 5: Deploy to Staging
  # ============================================================
  deploy-staging:
    needs: [image-scan, iac-scan]
    runs-on: ubuntu-latest
    environment: staging
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_STAGING }}
          aws-region: us-east-1

      - name: Deploy to ECS Staging
        run: |
          aws ecs update-service \
            --cluster staging-cluster \
            --service app-service \
            --force-new-deployment

      - name: Wait for deployment
        run: |
          aws ecs wait services-stable \
            --cluster staging-cluster \
            --services app-service

      - name: Run smoke tests
        run: |
          curl -f https://staging.company.com/health || exit 1

  # ============================================================
  # Stage 6: DAST (Dynamic Application Security Testing)
  # ============================================================
  dast:
    needs: deploy-staging
    runs-on: ubuntu-latest
    steps:
      - name: OWASP ZAP Scan
        uses: zaproxy/action-full-scan@v0.10.0
        with:
          target: 'https://staging.company.com'
          rules_file_name: '.zap/rules.tsv'
          allow_issue_writing: false

  # ============================================================
  # Stage 7: Deploy to Production
  # ============================================================
  deploy-production:
    needs: dast
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    environment:
      name: production
      url: https://app.company.com
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_PRODUCTION }}
          aws-region: us-east-1

      - name: Canary deployment (5%)
        run: |
          # Update task definition with new image
          # Deploy to 5% of traffic
          echo "Deploying canary..."

      - name: Monitor canary (5 minutes)
        run: |
          # Check error rates, latency, security signals
          sleep 300
          # If metrics are healthy, continue

      - name: Full deployment
        run: |
          aws ecs update-service \
            --cluster production-cluster \
            --service app-service \
            --force-new-deployment

      - name: Verify deployment
        run: |
          aws ecs wait services-stable \
            --cluster production-cluster \
            --services app-service
          curl -f https://app.company.com/health || exit 1
```

---

## GitLab CI Equivalent

```yaml
# .gitlab-ci.yml
stages:
  - security
  - build
  - test
  - deploy-staging
  - dast
  - deploy-production

variables:
  DOCKER_IMAGE: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA

# Security scanning
secret-detection:
  stage: security
  image: trufflesecurity/trufflehog:latest
  script:
    - trufflehog git file://. --only-verified --fail

sast:
  stage: security
  image: semgrep/semgrep:latest
  script:
    - semgrep --config=p/security-audit --sarif -o semgrep.sarif .
  artifacts:
    reports:
      sast: semgrep.sarif

dependency-scan:
  stage: security
  image: snyk/snyk:node
  script:
    - snyk test --severity-threshold=high

# Build
build:
  stage: build
  image: docker:24
  services:
    - docker:24-dind
  script:
    - docker build -t $DOCKER_IMAGE .
    - docker push $DOCKER_IMAGE

# Container scan
trivy-scan:
  stage: test
  image: aquasec/trivy:latest
  script:
    - trivy image --exit-code 1 --severity CRITICAL,HIGH $DOCKER_IMAGE

# Deploy staging
deploy-staging:
  stage: deploy-staging
  environment:
    name: staging
    url: https://staging.company.com
  script:
    - kubectl set image deployment/app app=$DOCKER_IMAGE
    - kubectl rollout status deployment/app

# DAST
zap-scan:
  stage: dast
  image: ghcr.io/zaproxy/zaproxy:stable
  script:
    - zap-full-scan.py -t https://staging.company.com -r report.html
  artifacts:
    paths:
      - report.html

# Production (manual approval required)
deploy-production:
  stage: deploy-production
  environment:
    name: production
    url: https://app.company.com
  when: manual  # Requires click to deploy
  only:
    - main
  script:
    - kubectl set image deployment/app app=$DOCKER_IMAGE --namespace=production
    - kubectl rollout status deployment/app --namespace=production
```

---

## Jenkins Pipeline (Declarative)

```groovy
// Jenkinsfile
pipeline {
    agent {
        kubernetes {
            yaml '''
            spec:
              containers:
              - name: builder
                image: node:20-alpine
                command: ['sleep', 'infinity']
              - name: docker
                image: docker:24-dind
                securityContext:
                  privileged: true
            '''
        }
    }

    environment {
        REGISTRY = 'registry.company.com'
        IMAGE = "${REGISTRY}/app:${env.BUILD_NUMBER}"
        SNYK_TOKEN = credentials('snyk-token')
    }

    stages {
        stage('Security Scan') {
            parallel {
                stage('Secret Scan') {
                    steps {
                        sh 'trufflehog git file://. --only-verified --fail'
                    }
                }
                stage('SAST') {
                    steps {
                        sh 'semgrep --config=p/security-audit .'
                    }
                }
                stage('Dependency Check') {
                    steps {
                        sh 'snyk test --severity-threshold=high'
                    }
                }
            }
        }

        stage('Build') {
            steps {
                container('builder') {
                    sh 'npm ci'
                    sh 'npm test'
                    sh 'npm run build'
                }
                container('docker') {
                    sh "docker build -t ${IMAGE} ."
                    sh "docker push ${IMAGE}"
                }
            }
        }

        stage('Image Scan') {
            steps {
                sh "trivy image --exit-code 1 --severity CRITICAL,HIGH ${IMAGE}"
            }
        }

        stage('Deploy Staging') {
            steps {
                sh "kubectl set image deployment/app app=${IMAGE} -n staging"
                sh 'kubectl rollout status deployment/app -n staging --timeout=300s'
            }
        }

        stage('DAST') {
            steps {
                sh 'zap-full-scan.py -t https://staging.company.com'
            }
        }

        stage('Deploy Production') {
            when { branch 'main' }
            input {
                message 'Deploy to production?'
                submitter 'security-team,platform-team'
            }
            steps {
                sh "kubectl set image deployment/app app=${IMAGE} -n production"
                sh 'kubectl rollout status deployment/app -n production --timeout=300s'
            }
        }
    }

    post {
        failure {
            slackSend channel: '#security-alerts',
                      message: "Pipeline failed: ${env.JOB_NAME} #${env.BUILD_NUMBER}"
        }
    }
}
```

---

## Pipeline Hardening Checklist

| Control | Why | How |
|---------|-----|-----|
| Pin action versions | Prevent supply chain attacks | `uses: actions/checkout@v4.1.1` not `@main` |
| Minimal permissions | Limit blast radius | `permissions: contents: read` |
| OIDC authentication | No long-lived secrets | AWS/GCP/Azure OIDC providers |
| Ephemeral runners | No persistent state | Fresh VM/container per job |
| Signed commits | Verify code authenticity | GPG signing required |
| Branch protection | Prevent direct pushes | Require PR + reviews |
| Audit logging | Track all changes | GitHub audit log / CloudTrail |
| Network isolation | Limit outbound access | Self-hosted runners in VPC |
| Dependency lockfiles | Reproducible builds | `package-lock.json`, `Pipfile.lock` |
| SBOM generation | Supply chain visibility | Syft, Trivy SBOM |

---

## Memory Technique: "SCAN BUILD SHIP WATCH"

Every pipeline stage in four words:
- **SCAN** — Find problems before they spread (SAST, secrets, dependencies)
- **BUILD** — Create artifacts securely (isolated, reproducible, signed)
- **SHIP** — Deploy safely (canary, rollback, approval gates)
- **WATCH** — Monitor continuously (alerts, anomalies, drift)

---

## Common Mistakes

1. **Secrets in pipeline logs** — Use `::add-mask::` or `sensitive: true`
2. **Using `@latest` for actions** — Pin to specific SHA or version
3. **No branch protection** — Anyone can push to main
4. **Pipeline runs as admin** — Use least-privilege service accounts
5. **No artifact signing** — Can't verify what you're deploying
6. **Skipping scans for speed** — Run them in parallel instead
7. **No rollback plan** — Always have automated rollback
8. **Shared runners for sensitive repos** — Use dedicated/self-hosted

---

## Interview Insight

**Q: "Design a CI/CD platform for 1000 developers across 500 microservices."**

"I'd design a platform with these principles:

**Architecture:**
- Centralized pipeline templates (shared library/reusable workflows)
- Self-service for teams (they configure, platform enforces guardrails)
- Mandatory security stages that can't be skipped

**Security Controls:**
- OIDC for all cloud access (zero long-lived secrets)
- Mandatory scanning gates: SAST, SCA, container scan, IaC scan
- Image signing with Cosign (only signed images can deploy)
- Admission controllers verify signatures at deploy time

**Scalability:**
- Auto-scaling runner pools (Kubernetes-based)
- Caching layers (dependencies, Docker layers, test results)
- Parallel execution of independent stages
- Queue management for resource-intensive jobs

**Governance:**
- All pipelines generate SBOM (Software Bill of Materials)
- Compliance reports auto-generated per deployment
- Break-glass procedure for emergency deploys (logged, alerted)
- Monthly access reviews for pipeline secrets

**Metrics:**
- Deployment frequency per team
- Lead time from commit to production
- Mean time to recovery (MTTR)
- Security scan pass rate
- Vulnerability remediation time

This gives us velocity (developers ship fast) with guardrails (security is
non-negotiable) at scale (works for 1000+ developers)."
