# Phase 1 — DevSecOps Workstation Setup

## Step 1: Install Git

Git is the foundation of everything in DevSecOps. Every tool, every pipeline,
every infrastructure change starts with Git.

### Windows:
```bash
# Download from: https://git-scm.com/download/win
# Or use winget:
winget install Git.Git
```

### After installation, configure:
```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
git config --global init.defaultBranch main
```

### Security note:
- Never commit secrets (passwords, API keys, tokens) to Git
- Use .gitignore to exclude sensitive files
- Enable signed commits for production repos

---

## Step 2: Install Docker

Docker lets you package applications into containers — lightweight, portable,
and identical everywhere they run.

### Windows:
```
Download Docker Desktop: https://www.docker.com/products/docker-desktop/
```

### Verify installation:
```bash
docker --version
docker run hello-world
```

### Security note:
- Docker runs with root privileges by default
- Always use official base images
- Scan images for vulnerabilities before deploying
- Never run containers as root in production

---

## Step 3: Install AWS CLI

AWS CLI lets you manage cloud resources from the command line.
In DevSecOps, you'll use it daily.

### Windows:
```bash
# Download MSI installer from:
# https://awscli.amazonaws.com/AWSCLIV2.msi
# Or use winget:
winget install Amazon.AWSCLI
```

### Configure:
```bash
aws configure
# Enter: Access Key ID, Secret Key, Region (us-east-1), Output (json)
```

### Security note:
- NEVER use root account credentials
- Create an IAM user with minimal permissions
- Enable MFA on your AWS account
- Rotate access keys every 90 days
- Use aws-vault or similar tool to protect credentials

---

## Step 4: Install VS Code Extensions for DevSecOps

Recommended extensions:
- Docker
- HashiCorp Terraform
- YAML
- GitLens
- AWS Toolkit
- Kubernetes
- ShellCheck (for Bash linting)

---

## Step 5: Create Your First Secure GitHub Repository

```bash
# Create project directory
mkdir devsecops-lab
cd devsecops-lab

# Initialize Git
git init

# Create .gitignore (SECURITY FIRST!)
echo "*.env" > .gitignore
echo ".aws/" >> .gitignore
echo "*.pem" >> .gitignore
echo "*.key" >> .gitignore
echo "secrets/" >> .gitignore

# Create README
echo "# My DevSecOps Lab" > README.md

# First commit
git add .
git commit -m "Initial commit with security-first .gitignore"

# Push to GitHub
# First create repo on github.com, then:
git remote add origin https://github.com/YOUR_USERNAME/devsecops-lab.git
git push -u origin main
```

### Security note:
- Enable branch protection on main
- Require pull request reviews
- Enable secret scanning on the repository
- Enable Dependabot for dependency updates

---

## Verification Checklist

After setup, verify everything works:

```bash
git --version          # Should show 2.x+
docker --version       # Should show 24.x+ or 27.x+
aws --version          # Should show 2.x+
python --version       # Should show 3.10+
```
