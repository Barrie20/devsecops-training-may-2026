# Phase 12 — Advanced DevSecOps Concepts

---

## Zero Trust Architecture

### The Old Model (Castle & Moat)
```
INTERNET ──── [Firewall] ──── TRUSTED INTERNAL NETWORK
                                    Everything inside is trusted
                                    (This is how breaches spread)
```

### Zero Trust Model
```
NOTHING IS TRUSTED. EVER.
Every request is authenticated, authorized, and encrypted.
Even internal service-to-service communication.
```

### Zero Trust Principles:
1. **Never trust, always verify** — Every request needs authentication
2. **Least privilege access** — Minimum permissions, time-limited
3. **Assume breach** — Design as if attackers are already inside
4. **Verify explicitly** — Check identity, device, location, behavior
5. **Micro-segmentation** — Network divided into tiny zones

### Implementation:

```yaml
# Service Mesh (Istio) — Zero Trust for microservices
# Every service gets a certificate, all traffic is mTLS encrypted

apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: production
spec:
  mtls:
    mode: STRICT  # All traffic MUST be encrypted

---
# Authorization Policy — Service A can ONLY call Service B
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: allow-frontend-to-api
  namespace: production
spec:
  selector:
    matchLabels:
      app: api-service
  rules:
    - from:
        - source:
            principals: ["cluster.local/ns/production/sa/frontend-sa"]
      to:
        - operation:
            methods: ["GET", "POST"]
            paths: ["/api/v1/*"]
```

---

## Threat Modeling

Threat modeling is thinking like an attacker BEFORE building the system.

### STRIDE Framework:

| Threat | Description | Example | Mitigation |
|--------|-------------|---------|------------|
| **S**poofing | Pretending to be someone else | Stolen credentials | MFA, certificate auth |
| **T**ampering | Modifying data | Man-in-the-middle | Encryption, signing |
| **R**epudiation | Denying actions | "I didn't delete that" | Audit logging |
| **I**nformation Disclosure | Data leaks | Exposed S3 bucket | Encryption, access control |
| **D**enial of Service | Making system unavailable | DDoS attack | Rate limiting, CDN |
| **E**levation of Privilege | Gaining unauthorized access | Container escape | Least privilege, sandboxing |

### Threat Modeling Process:

```
1. WHAT are we building? (Architecture diagram)
2. WHAT can go wrong? (STRIDE per component)
3. WHAT are we doing about it? (Mitigations)
4. DID we do a good job? (Validation)
```

### Example: Threat Model for a Payment Service

```
Component: Payment API
├── Threat: Spoofing (attacker impersonates user)
│   └── Mitigation: JWT tokens + MFA for high-value transactions
├── Threat: Tampering (modify payment amount)
│   └── Mitigation: Request signing, server-side validation
├── Threat: Information Disclosure (credit card numbers leaked)
│   └── Mitigation: Tokenization, PCI DSS compliance, encryption
├── Threat: Denial of Service (flood payment endpoint)
│   └── Mitigation: Rate limiting, WAF, auto-scaling
└── Threat: Elevation of Privilege (access other users' payments)
    └── Mitigation: Row-level security, authorization checks
```

---

## Supply Chain Security

Your software supply chain includes everything that goes into your build:
- Source code
- Dependencies (npm, pip, maven packages)
- Base container images
- Build tools
- CI/CD pipeline itself

### Attacks on Supply Chain:
- **Dependency confusion** — Malicious package with same name as internal one
- **Typosquatting** — `lodash` vs `l0dash` (zero instead of 'o')
- **Compromised maintainer** — Legitimate package gets malicious update
- **Build system compromise** — Attacker modifies build pipeline (SolarWinds)

### Defenses:

```bash
# 1. Lock dependencies (exact versions)
npm ci                    # Uses package-lock.json (exact versions)
pip install -r requirements.txt  # Pin with ==

# 2. Verify package integrity
npm audit signatures      # Verify npm package signatures
pip install --require-hashes -r requirements.txt

# 3. Generate SBOM (Software Bill of Materials)
syft packages my-app:latest -o spdx-json > sbom.json
trivy image --format spdx-json my-app:latest > sbom.json

# 4. Sign artifacts
cosign sign --key cosign.key registry.com/my-app:1.0.0

# 5. Verify before deploy
cosign verify --key cosign.pub registry.com/my-app:1.0.0

# 6. Use private registry with approved packages
# Only allow packages from your vetted registry
```

### SLSA Framework (Supply-chain Levels for Software Artifacts):

| Level | Requirement | What it Prevents |
|-------|-------------|-----------------|
| SLSA 1 | Build process documented | Unknown build process |
| SLSA 2 | Hosted build, signed provenance | Tampered builds |
| SLSA 3 | Hardened build platform | Compromised build env |
| SLSA 4 | Two-person review, hermetic builds | Insider threats |

---

## Secrets Management with HashiCorp Vault

```bash
# Start Vault (dev mode for learning)
vault server -dev

# Store a secret
vault kv put secret/production/database \
    username="app_user" \
    password="super-secret-password"

# Read a secret
vault kv get secret/production/database

# Dynamic secrets (Vault generates temporary credentials!)
vault read database/creds/app-role
# Returns: username=v-app-role-abc123, password=xyz789
# These auto-expire after TTL!

# Kubernetes integration
vault write auth/kubernetes/role/app-role \
    bound_service_account_names=app-sa \
    bound_service_account_namespaces=production \
    policies=app-policy \
    ttl=1h
```

### Vault Policy (Least Privilege):
```hcl
# policy/app-policy.hcl
# App can only read its own secrets
path "secret/data/production/app/*" {
  capabilities = ["read"]
}

# App can generate database credentials
path "database/creds/app-role" {
  capabilities = ["read"]
}

# App CANNOT access other environments
path "secret/data/staging/*" {
  capabilities = ["deny"]
}
```

---

## Policy as Code — OPA & Kyverno

### OPA (Open Policy Agent)

Write policies in Rego language, enforce everywhere:

```rego
# policy/kubernetes.rego
# Deny pods without resource limits
package kubernetes.admission

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    not container.resources.limits
    msg := sprintf("Container '%v' must have resource limits", [container.name])
}

# Deny images from untrusted registries
deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    not startswith(container.image, "registry.company.com/")
    msg := sprintf("Image '%v' is not from approved registry", [container.image])
}

# Deny services with type LoadBalancer (must use Ingress)
deny[msg] {
    input.request.kind.kind == "Service"
    input.request.object.spec.type == "LoadBalancer"
    msg := "LoadBalancer services are not allowed. Use Ingress instead."
}
```

### Kyverno (Kubernetes-Native Policy Engine)

```yaml
# Mutate: Auto-add security labels
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: add-security-labels
spec:
  rules:
    - name: add-labels
      match:
        any:
          - resources:
              kinds: [Pod]
      mutate:
        patchStrategicMerge:
          metadata:
            labels:
              security-scan: required
              compliance: enforced

---
# Validate: Require non-root containers
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-non-root
spec:
  validationFailureAction: Enforce
  rules:
    - name: check-non-root
      match:
        any:
          - resources:
              kinds: [Pod]
      validate:
        message: "Containers must run as non-root"
        pattern:
          spec:
            containers:
              - securityContext:
                  runAsNonRoot: true

---
# Generate: Auto-create NetworkPolicy for new namespaces
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: default-deny-network
spec:
  rules:
    - name: generate-netpol
      match:
        any:
          - resources:
              kinds: [Namespace]
      generate:
        kind: NetworkPolicy
        name: default-deny
        namespace: "{{request.object.metadata.name}}"
        data:
          spec:
            podSelector: {}
            policyTypes:
              - Ingress
              - Egress
```

---

## Memory Technique: "ZERO THREAT SUPPLY VAULT POLICY"

The five advanced concepts:
- **ZERO** trust — Verify everything, trust nothing
- **THREAT** model — Think like an attacker before building
- **SUPPLY** chain — Secure what goes into your build
- **VAULT** — Manage secrets properly (never hardcode)
- **POLICY** as code — Automate security enforcement

---

## Interview Insight

**Q: "Design a Zero Trust architecture for a microservices platform."**

"I'd implement Zero Trust across five layers:

**1. Identity:**
- Every service has a cryptographic identity (mTLS certificates via service mesh)
- Every human uses SSO + MFA + short-lived tokens
- No shared credentials, no long-lived tokens

**2. Network:**
- Default deny all traffic (network policies)
- Service mesh encrypts all inter-service communication
- Micro-segmentation: each service can only reach what it needs
- No VPN = no implicit trust from 'being on the network'

**3. Application:**
- Every API call is authenticated AND authorized
- Authorization is context-aware (who, what, when, where, how)
- Rate limiting and anomaly detection per identity

**4. Data:**
- Encryption at rest and in transit (always)
- Data classification and access controls
- DLP (Data Loss Prevention) at egress points

**5. Monitoring:**
- Log every access decision (allow AND deny)
- Behavioral analytics (detect anomalies)
- Continuous verification (re-authenticate on risk change)

The key insight: Zero Trust isn't a product you buy. It's an architecture
principle that requires changes across identity, network, application, and
data layers. You implement it incrementally, starting with the highest-risk
services."
