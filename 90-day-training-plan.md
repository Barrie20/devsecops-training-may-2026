# 90-Day DevSecOps Training Plan — Beginner to FAANG-Ready

## Overview
- Days 1–30: Foundations (Linux, Git, Docker, Python, AWS basics)
- Days 31–60: Core Skills (IaC, Kubernetes, CI/CD, Security Tools)
- Days 61–90: Advanced + Interview Prep (Architecture, Scenarios, Branding)

---

## WEEK 1 — Setup & Foundations

### Day 1: Environment Setup
- Theory: What is DevSecOps? (Phase 1 notes)
- Practice: Install Git, Docker, AWS CLI, VS Code
- Project: Create GitHub repo with secure .gitignore
- Review: Can you explain DevSecOps in 30 seconds?

### Day 2: Git Mastery
- Theory: Git workflow (branches, PRs, merge strategies)
- Practice: Create branch, make changes, open PR
- Project: Set up branch protection rules
- Review: What's the security risk of force-pushing to main?

### Day 3: Linux Basics Part 1
- Theory: Filesystem, navigation, file operations
- Practice: Navigate /var/log, read system logs
- Project: Find all SUID files on a system
- Review: What does chmod 600 mean?

### Day 4: Linux Basics Part 2
- Theory: Permissions, users, processes
- Practice: Create users, set permissions, manage services
- Project: Lock down a fresh Linux server (SSH hardening)
- Review: Why should you never run services as root?

### Day 5: Bash Scripting
- Theory: Variables, loops, conditionals, functions
- Practice: Write the log monitor script (Phase 2)
- Project: Automate security checks with cron
- Review: Run your log monitor and interpret results

### Day 6: Docker Fundamentals
- Theory: Containers vs VMs, images, layers
- Practice: Build your first Docker image
- Project: Containerize a simple web app
- Review: What's the security risk of using `latest` tag?

### Day 7: Week 1 Review
- Review all concepts from the week
- Quiz yourself on key terms
- Update your GitHub with all projects
- Write a LinkedIn post about what you learned

---

## WEEK 2 — Python & Cloud Basics

### Day 8: Python Basics for DevOps
- Theory: Variables, functions, file I/O
- Practice: Write a script that parses a log file
- Project: Start the log analyzer (Phase 3, Project 2)
- Review: Why is Python the #1 DevOps language?

### Day 9: Python APIs & Automation
- Theory: requests library, JSON, REST APIs
- Practice: Query a public API, parse response
- Project: Build AWS inventory script (Phase 3, Project 1)
- Review: How do you handle API authentication securely?

### Day 10: Python — boto3 & AWS
- Theory: AWS SDK, IAM, programmatic access
- Practice: List EC2 instances, S3 buckets with boto3
- Project: Extend inventory script with security checks
- Review: Why use IAM roles instead of access keys?

### Day 11: AWS IAM Deep Dive
- Theory: Users, roles, policies, least privilege
- Practice: Create IAM policies with minimum permissions
- Project: Audit your AWS account for overly permissive policies
- Review: Explain the difference between identity and resource policies

### Day 12: AWS Networking (VPC)
- Theory: VPCs, subnets, security groups, NACLs
- Practice: Create a VPC with public/private subnets
- Project: Design a network that isolates databases from internet
- Review: What's the difference between SG and NACL?

### Day 13: AWS EC2 & Security
- Theory: Instance types, AMIs, key pairs, user data
- Practice: Launch an EC2 instance securely
- Project: Harden an EC2 instance (disable root, configure firewall)
- Review: How would you detect a compromised EC2 instance?

### Day 14: Week 2 Review
- Complete all unfinished exercises
- Push all code to GitHub
- Practice explaining concepts out loud
- Write a blog post draft about Python for security

---

## WEEK 3 — Infrastructure as Code

### Day 15: Terraform Basics
- Theory: Providers, resources, state, plan/apply
- Practice: Create an S3 bucket with Terraform
- Project: Build a VPC with Terraform
- Review: Why is Terraform state sensitive?

### Day 16: Terraform Security
- Theory: Remote state, encryption, secrets handling
- Practice: Configure remote state with encryption
- Project: Add security scanning to Terraform (tfsec/checkov)
- Review: What happens if someone gets your state file?

### Day 17: Terraform Modules
- Theory: Reusable modules, input/output variables
- Practice: Create a reusable "secure VPC" module
- Project: Build a complete infrastructure stack
- Review: How do modules enforce security standards?

### Day 18: CloudFormation Basics
- Theory: Templates, stacks, drift detection
- Practice: Deploy a stack with CloudFormation
- Project: Compare Terraform vs CloudFormation approaches
- Review: When would you choose one over the other?

### Day 19: IaC Security Scanning
- Theory: Policy as Code, compliance automation
- Practice: Run Checkov on your Terraform code
- Project: Fix all findings and achieve clean scan
- Review: How does IaC scanning fit in CI/CD?

### Day 20: SQL for Security
- Theory: Basic queries, JOINs, aggregation
- Practice: Query CloudWatch Logs Insights
- Project: Write queries to detect suspicious activity (Phase 4)
- Review: How do security teams use SQL daily?

### Day 21: Week 3 Review
- Complete infrastructure project end-to-end
- Document your architecture decisions
- Practice terraform plan/apply workflow
- Update portfolio with IaC projects

---

## WEEK 4 — Containers & Kubernetes

### Day 22: Docker Security
- Theory: Image layers, multi-stage builds, non-root users
- Practice: Build a secure Dockerfile (no root, minimal base)
- Project: Scan images with Trivy, fix findings
- Review: What are the top 5 Docker security mistakes?

### Day 23: Docker Compose & Networking
- Theory: Multi-container apps, networks, volumes
- Practice: Deploy a multi-service app with compose
- Project: Implement network isolation between services
- Review: How do containers communicate securely?

### Day 24: Kubernetes Basics
- Theory: Pods, deployments, services, namespaces
- Practice: Deploy an app to minikube/kind
- Project: Create namespace isolation
- Review: What is a Pod Security Standard?

### Day 25: Kubernetes Security
- Theory: RBAC, network policies, pod security
- Practice: Implement RBAC for different teams
- Project: Create network policies that restrict traffic
- Review: How would you detect a container escape?

### Day 26: Kubernetes in Production
- Theory: EKS/GKE, ingress, secrets, service mesh
- Practice: Deploy to EKS with proper IAM
- Project: Implement secrets management with external-secrets
- Review: Why shouldn't you store secrets in etcd unencrypted?

### Day 27: Container Runtime Security
- Theory: Falco, runtime detection, syscall monitoring
- Practice: Install Falco, trigger alerts
- Project: Create custom Falco rules for your app
- Review: What's the difference between build-time and runtime security?

### Day 28: Week 4 Review
- Deploy complete app to Kubernetes securely
- Document security controls implemented
- Practice explaining K8s security architecture
- Prepare for mock interview questions

---

## WEEK 5–6 — CI/CD & Security Tools

### Day 29–30: GitHub Actions
- Build complete pipeline with security gates
- Implement secret scanning, SAST, container scanning

### Day 31–32: GitLab CI / Jenkins
- Compare pipeline tools
- Implement equivalent pipeline in GitLab CI

### Day 33–34: SAST Tools (SonarQube, Semgrep)
- Set up SonarQube, scan real code
- Write custom Semgrep rules

### Day 35–36: DAST Tools (OWASP ZAP)
- Run ZAP against test applications
- Interpret and fix findings

### Day 37–38: Dependency Scanning (Snyk, Trivy)
- Integrate into pipeline
- Create policy for blocking deployments

### Day 39–42: Complete Pipeline Project
- Build end-to-end secure pipeline
- Document every security control
- Create runbook for pipeline failures

---

## WEEK 7–8 — Observability & Advanced Topics

### Day 43–45: Prometheus & Grafana
- Deploy monitoring stack
- Create security-focused dashboards

### Day 46–48: ELK Stack / CloudWatch
- Centralized logging
- Security event correlation

### Day 49–51: Secrets Management (Vault)
- Deploy HashiCorp Vault
- Integrate with Kubernetes and CI/CD

### Day 52–54: Policy as Code (OPA/Kyverno)
- Write admission controllers
- Enforce security policies automatically

### Day 55–56: Zero Trust Architecture
- Design zero trust network
- Implement service mesh (Istio)

---

## WEEK 9–10 — Interview Preparation

### Day 57–60: System Design Practice
- Design secure microservices architecture
- Design CI/CD platform for 1000 developers
- Design incident response system

### Day 61–64: Scenario-Based Questions
- Practice all 16 real-world scenarios
- Time yourself (45 minutes per scenario)

### Day 65–68: Behavioral Questions
- Prepare 10 STAR stories
- Practice with a friend or recording

### Day 69–72: Mock Interviews
- Do 3 mock interviews
- Get feedback, iterate

---

## WEEK 11–12 — Portfolio & Networking

### Day 73–76: GitHub Portfolio
- Clean up all projects
- Write professional READMEs
- Add architecture diagrams

### Day 77–80: Technical Blog
- Write 3 technical articles
- Publish on Medium/Dev.to/personal blog

### Day 81–84: Networking
- Connect with 20 DevSecOps professionals
- Engage in 5 technical discussions
- Attend 1 virtual meetup/conference

### Day 85–88: Job Applications
- Update resume with projects
- Apply to 10 positions
- Customize cover letters

### Day 89–90: Final Review
- Review all phases
- Identify weak areas
- Create ongoing learning plan
- Celebrate your progress! 🎉

---

## Daily Routine Template

```
Morning (1 hour):
  - Review yesterday's concepts (spaced repetition)
  - Read one security article/blog post

Afternoon (2 hours):
  - Hands-on lab work
  - Build/extend projects

Evening (1 hour):
  - Document what you learned
  - Push code to GitHub
  - Prepare tomorrow's topics
```

---

## Memory Techniques

### Spaced Repetition Schedule
- Day 1: Learn concept
- Day 2: Review
- Day 4: Review
- Day 7: Review
- Day 14: Review
- Day 30: Review (now it's permanent)

### Mental Model: "The Security Onion"
Each layer adds protection:
```
Layer 1: Code (SAST, secrets scanning)
Layer 2: Dependencies (SCA, vulnerability scanning)
Layer 3: Container (image scanning, minimal base)
Layer 4: Cluster (RBAC, network policies, admission control)
Layer 5: Cloud (IAM, VPC, encryption)
Layer 6: Runtime (monitoring, alerting, incident response)
```

### Concept Linking
Connect new concepts to ones you already know:
- Docker container = shipping container (isolated, portable, standardized)
- Kubernetes = orchestra conductor (manages many containers)
- Terraform = blueprint (defines what to build)
- CI/CD = assembly line (automated, consistent, quality-checked)
- Zero Trust = airport security (verify everyone, every time)

---

## Career Acceleration Tips

1. **Contribute to open source** — Even documentation fixes count
2. **Get certified** — AWS SAA, CKA, HashiCorp Terraform Associate
3. **Build in public** — Share your learning journey on LinkedIn
4. **Solve real problems** — Automate something at your current job
5. **Network strategically** — Connect with hiring managers, not just peers
