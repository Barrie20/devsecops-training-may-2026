# Phase 8 — Containers & Kubernetes Security

---

## Container Security — The Full Picture

Containers are the building blocks of modern infrastructure. But they introduce
new attack surfaces that traditional security doesn't cover.

### The Container Threat Model

```
ATTACK SURFACE:
┌─────────────────────────────────────────────┐
│ Container Image                              │
│  - Vulnerable base OS packages               │
│  - Vulnerable application dependencies       │
│  - Embedded secrets/credentials              │
│  - Malicious code in layers                  │
├─────────────────────────────────────────────┤
│ Container Runtime                            │
│  - Container escape (breakout to host)       │
│  - Privilege escalation                      │
│  - Resource abuse (crypto mining)            │
│  - Network lateral movement                  │
├─────────────────────────────────────────────┤
│ Container Orchestration (Kubernetes)         │
│  - Misconfigured RBAC                        │
│  - Exposed API server                        │
│  - Secrets in etcd (unencrypted)             │
│  - Malicious admission                       │
├─────────────────────────────────────────────┤
│ Supply Chain                                 │
│  - Compromised base images                   │
│  - Typosquatting (fake images)               │
│  - Unsigned images                           │
└─────────────────────────────────────────────┘
```

---

## Docker Security Best Practices

### 1. Secure Dockerfile

```dockerfile
# ============================================================
# SECURE Dockerfile — Production Ready
# ============================================================

# Rule 1: Use specific version tags (never :latest)
# Rule 2: Use minimal base images (alpine, distroless)
FROM node:20.11-alpine AS builder

# Rule 3: Set working directory
WORKDIR /app

# Rule 4: Copy dependency files first (layer caching)
COPY package.json package-lock.json ./

# Rule 5: Install dependencies with exact versions
RUN npm ci --only=production

# Copy application code
COPY src/ ./src/

# ---- Production Stage ----
# Rule 6: Multi-stage build (smaller image, no build tools)
FROM node:20.11-alpine AS production

# Rule 7: Install security updates
RUN apk update && apk upgrade && rm -rf /var/cache/apk/*

# Rule 8: Create non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

WORKDIR /app

# Rule 9: Copy only what's needed from builder
COPY --from=builder --chown=appuser:appgroup /app/node_modules ./node_modules
COPY --from=builder --chown=appuser:appgroup /app/src ./src
COPY --chown=appuser:appgroup package.json ./

# Rule 10: Run as non-root user
USER appuser

# Rule 11: Use read-only filesystem where possible
# (set in docker-compose or K8s, not Dockerfile)

# Rule 12: Expose only necessary ports
EXPOSE 8080

# Rule 13: Use exec form (not shell form) for signals
ENTRYPOINT ["node", "src/server.js"]

# Rule 14: Add health check
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1
```

### 2. .dockerignore (Security)
```
# Never include these in images
.git
.env
*.pem
*.key
node_modules
.aws
secrets/
*.log
docker-compose*.yml
Dockerfile
.dockerignore
```

### 3. Image Scanning

```bash
# Trivy — Most popular open-source scanner
trivy image my-app:latest

# Scan with severity filter (CI/CD gate)
trivy image --severity CRITICAL,HIGH --exit-code 1 my-app:latest

# Scan filesystem (before building)
trivy fs --scanners vuln,secret,misconfig .

# Grype — Alternative scanner
grype my-app:latest

# Docker Scout (built into Docker)
docker scout cves my-app:latest
```

### 4. Docker Compose Security

```yaml
# docker-compose.yml — Secure configuration
version: '3.8'

services:
  app:
    build: .
    image: my-app:1.0.0
    
    # Security: Run as non-root
    user: "1001:1001"
    
    # Security: Read-only filesystem
    read_only: true
    tmpfs:
      - /tmp
    
    # Security: Drop all capabilities
    cap_drop:
      - ALL
    
    # Security: No privilege escalation
    security_opt:
      - no-new-privileges:true
    
    # Security: Resource limits (prevent DoS)
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 256M
    
    # Security: Network isolation
    networks:
      - frontend
    
    # Security: No unnecessary ports
    ports:
      - "8080:8080"
    
    # Security: Health check
    healthcheck:
      test: ["CMD", "wget", "--spider", "http://localhost:8080/health"]
      interval: 30s
      timeout: 5s
      retries: 3

  database:
    image: postgres:16.1-alpine
    
    # Security: Not accessible from outside
    # No ports exposed to host!
    
    # Security: Network isolation
    networks:
      - backend
    
    # Security: Encrypted volume
    volumes:
      - db-data:/var/lib/postgresql/data
    
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    
    secrets:
      - db_password

networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
    internal: true  # No internet access for DB network

volumes:
  db-data:
    driver: local

secrets:
  db_password:
    file: ./secrets/db_password.txt
```

---

## Kubernetes Security

### Kubernetes Architecture (Security View)

```
┌─────────────────────────────────────────────────────┐
│ CONTROL PLANE (must be heavily secured)              │
│  ├── API Server (authentication, authorization)      │
│  ├── etcd (encrypted secrets storage)                │
│  ├── Scheduler                                       │
│  └── Controller Manager                              │
├─────────────────────────────────────────────────────┤
│ WORKER NODES                                         │
│  ├── kubelet (node agent)                            │
│  ├── Container Runtime (containerd)                  │
│  └── Pods (your applications)                        │
├─────────────────────────────────────────────────────┤
│ SECURITY LAYERS                                      │
│  ├── Network Policies (micro-segmentation)           │
│  ├── RBAC (who can do what)                          │
│  ├── Pod Security Standards (how pods run)           │
│  ├── Admission Controllers (what's allowed in)       │
│  └── Secrets Management (how secrets are stored)     │
└─────────────────────────────────────────────────────┘
```

### Secure Pod Specification

```yaml
# secure-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
  namespace: production
  labels:
    app: secure-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secure-app
  template:
    metadata:
      labels:
        app: secure-app
    spec:
      # Security: Use a service account with minimal permissions
      serviceAccountName: app-service-account
      automountServiceAccountToken: false  # Don't mount token unless needed
      
      # Security: Pod-level security context
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      
      containers:
        - name: app
          image: registry.company.com/app:1.2.3  # Pinned version!
          
          # Security: Container-level security context
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          
          # Security: Resource limits (prevent resource abuse)
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
          
          ports:
            - containerPort: 8080
              protocol: TCP
          
          # Health checks (K8s restarts unhealthy pods)
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 30
            periodSeconds: 10
          
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 5
          
          # Security: Mount secrets from external source
          env:
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: app-secrets
                  key: db-password
          
          # Security: Writable temp directory only
          volumeMounts:
            - name: tmp
              mountPath: /tmp
      
      volumes:
        - name: tmp
          emptyDir:
            sizeLimit: 100Mi
```

### Network Policies (Micro-Segmentation)

```yaml
# network-policy.yaml
# Rule: App can only talk to its own database, nothing else
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: app-network-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: secure-app
  policyTypes:
    - Ingress
    - Egress
  
  # Only allow traffic FROM the ingress controller
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-system
        - podSelector:
            matchLabels:
              app: nginx-ingress
      ports:
        - protocol: TCP
          port: 8080
  
  # Only allow traffic TO the database and DNS
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: postgres
      ports:
        - protocol: TCP
          port: 5432
    - to:  # Allow DNS resolution
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53

---
# Default deny all traffic in namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

### RBAC — Role-Based Access Control

```yaml
# rbac.yaml
# Developer role: can view pods and logs, but NOT secrets or exec
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: developer
  namespace: production
rules:
  - apiGroups: [""]
    resources: ["pods", "pods/log", "services", "configmaps"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments", "replicasets"]
    verbs: ["get", "list", "watch"]
  # NOTE: No access to secrets, no exec, no delete

---
# Security team role: full access for incident response
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: security-responder
rules:
  - apiGroups: [""]
    resources: ["pods", "pods/log", "pods/exec", "secrets", "events"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["delete"]  # Can kill compromised pods
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["*"]  # Can isolate compromised workloads

---
# Bind role to user
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: developer-binding
  namespace: production
subjects:
  - kind: User
    name: alice@company.com
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: developer
  apiGroup: rbac.authorization.k8s.io
```

### Runtime Security with Falco

```yaml
# Falco rule: Detect container escape attempts
- rule: Container Escape via Mount
  desc: Detect attempts to mount host filesystem
  condition: >
    spawned_process and container and
    proc.name in (mount, umount) and
    not proc.pname in (dockerd, containerd)
  output: >
    Container escape attempt detected
    (user=%user.name command=%proc.cmdline container=%container.name
     image=%container.image.repository)
  priority: CRITICAL
  tags: [container, escape]

- rule: Crypto Mining Detection
  desc: Detect crypto mining processes
  condition: >
    spawned_process and container and
    (proc.name in (xmrig, minerd, cpuminer) or
     proc.cmdline contains "stratum+tcp")
  output: >
    Crypto miner detected in container
    (process=%proc.name container=%container.name)
  priority: CRITICAL
  tags: [crypto, mining]
```

---

## Memory Technique: "BUILD SCAN DEPLOY DETECT"

Container security lifecycle:
1. **BUILD** — Secure Dockerfile (non-root, minimal, multi-stage)
2. **SCAN** — Image scanning (Trivy, before deployment)
3. **DEPLOY** — Secure K8s config (RBAC, network policies, pod security)
4. **DETECT** — Runtime monitoring (Falco, audit logs)

---

## Common Mistakes

1. **Running as root** — 80% of container images run as root by default
2. **Using `:latest` tag** — No reproducibility, no audit trail
3. **No resource limits** — One pod can starve the entire node
4. **No network policies** — All pods can talk to all pods by default
5. **Secrets in environment variables** — Visible in `kubectl describe pod`
6. **No image scanning** — Deploying known vulnerabilities
7. **Mounting Docker socket** — Gives container full host access
8. **No seccomp/AppArmor** — Containers can make dangerous syscalls

---

## Interview Insight

**Q: "A production Kubernetes cluster is under attack. Walk through detection and mitigation."**

"I'd follow this incident response process:

**Detection (first 5 minutes):**
1. Check Falco alerts — what triggered? Container escape? Unusual process?
2. Check `kubectl get events -A` — any unusual pod creation?
3. Check network policies — any unexpected traffic in flow logs?
4. Check `kubectl get pods -A` — any unknown pods running?

**Containment (next 10 minutes):**
1. Apply deny-all network policy to affected namespace
2. Scale down compromised deployments to 0 replicas
3. Revoke compromised service account tokens
4. Block attacker IP at ingress/WAF level

**Investigation (next hour):**
1. Collect pod logs before termination: `kubectl logs POD --previous`
2. Check audit logs: who created/modified resources?
3. Review RBAC: was there privilege escalation?
4. Check image digests: was an image tampered with?

**Recovery:**
1. Rebuild affected images from known-good source
2. Rotate all secrets in affected namespaces
3. Redeploy from clean state (GitOps)
4. Verify with security scan

**Post-incident:**
1. Add Falco rules for the specific attack pattern
2. Tighten RBAC and network policies
3. Add admission controller to prevent recurrence
4. Update runbook with lessons learned"
