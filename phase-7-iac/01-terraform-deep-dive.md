# Phase 7 — Infrastructure as Code Deep Dive

---

## Why IaC is Non-Negotiable in DevSecOps

At FAANG companies, NO infrastructure is created manually. Everything is code.
If it's not in code, it doesn't exist. If it's not reviewed, it doesn't deploy.

**The IaC security promise:**
- Every change is peer-reviewed (PR process)
- Every change is auditable (Git history)
- Every change is scannable (automated policy checks)
- Every environment is identical (no drift)
- Recovery is instant (rebuild from code)

---

## Terraform — The Industry Standard

### Core Workflow
```
terraform init      → Download providers and modules
terraform plan      → Preview what will change (ALWAYS review this!)
terraform apply     → Make the changes
terraform destroy   → Tear everything down
```

### State Management (CRITICAL for Security)

Terraform state contains ALL your infrastructure details, including secrets.

**NEVER do this:**
- Store state locally (lost laptop = lost infrastructure)
- Store state in Git (secrets exposed)
- Share state without encryption

**ALWAYS do this:**
```hcl
# Remote state with encryption and locking
terraform {
  backend "s3" {
    bucket         = "company-terraform-state"
    key            = "env/production/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true                    # Encrypt at rest
    dynamodb_table = "terraform-state-locks" # Prevent concurrent changes
    
    # Additional security
    kms_key_id     = "arn:aws:kms:us-east-1:ACCOUNT:key/KEY_ID"
  }
}
```

### Variables & Secrets

```hcl
# NEVER hardcode secrets
variable "db_password" {
  description = "Database password"
  type        = string
  sensitive   = true  # Prevents showing in logs
}

# Use environment variables or secrets manager
# export TF_VAR_db_password="from-vault-or-secrets-manager"

# Or reference AWS Secrets Manager directly
data "aws_secretsmanager_secret_version" "db_password" {
  secret_id = "production/database/password"
}

resource "aws_db_instance" "main" {
  password = data.aws_secretsmanager_secret_version.db_password.secret_string
}
```

### Modules — Reusable Security Patterns

```hcl
# modules/secure-s3-bucket/main.tf
# A reusable module that enforces security standards

variable "bucket_name" {
  type = string
}

variable "environment" {
  type = string
}

resource "aws_s3_bucket" "this" {
  bucket = var.bucket_name
  tags   = { Environment = var.environment }
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "this" {
  bucket        = aws_s3_bucket.this.id
  target_bucket = var.logging_bucket
  target_prefix = "s3-access-logs/${var.bucket_name}/"
}

# Usage:
# module "data_bucket" {
#   source      = "./modules/secure-s3-bucket"
#   bucket_name = "my-secure-data"
#   environment = "production"
# }
```

---

## IaC Security Scanning

### Tool Comparison

| Tool | What it Checks | Speed | Best For |
|------|---------------|-------|----------|
| Checkov | Terraform, CloudFormation, K8s | Fast | Comprehensive |
| tfsec | Terraform only | Very fast | Quick checks |
| Terrascan | Multi-framework | Medium | Policy enforcement |
| Sentinel | Terraform Enterprise | Fast | Enterprise governance |
| OPA/Conftest | Any structured data | Fast | Custom policies |

### Checkov Example
```bash
# Install
pip install checkov

# Scan Terraform directory
checkov -d ./terraform/

# Scan specific file
checkov -f main.tf

# Output as JSON (for CI/CD)
checkov -d . -o json > checkov-results.json

# Skip specific checks (with justification!)
checkov -d . --skip-check CKV_AWS_18  # S3 logging (handled elsewhere)
```

### Common Checkov Findings:
```
CKV_AWS_18: "Ensure the S3 bucket has access logging enabled"
CKV_AWS_19: "Ensure the S3 bucket has server-side-encryption enabled"
CKV_AWS_21: "Ensure the S3 bucket has versioning enabled"
CKV_AWS_23: "Ensure every security group rule has a description"
CKV_AWS_24: "Ensure no security group allows ingress from 0.0.0.0/0 to port 22"
CKV_AWS_145: "Ensure RDS instance is encrypted at rest"
```

### Integrating into CI/CD
```yaml
# GitHub Actions step
- name: Run Checkov
  uses: bridgecrewio/checkov-action@master
  with:
    directory: ./terraform
    framework: terraform
    soft_fail: false  # FAIL the pipeline on findings
    output_format: sarif
```

---

## CloudFormation — AWS Native IaC

```yaml
# cloudformation/secure-vpc.yml
AWSTemplateFormatVersion: '2010-09-09'
Description: Secure VPC with private subnets

Parameters:
  Environment:
    Type: String
    AllowedValues: [dev, staging, production]
  VpcCidr:
    Type: String
    Default: '10.0.0.0/16'

Resources:
  VPC:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: !Ref VpcCidr
      EnableDnsHostnames: true
      EnableDnsSupport: true
      Tags:
        - Key: Name
          Value: !Sub '${Environment}-vpc'

  # Security: VPC Flow Logs
  FlowLog:
    Type: AWS::EC2::FlowLog
    Properties:
      ResourceId: !Ref VPC
      ResourceType: VPC
      TrafficType: ALL
      LogDestinationType: cloud-watch-logs
      LogGroupName: !Sub '/aws/vpc/${Environment}-flow-logs'

  PrivateSubnet1:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref VPC
      CidrBlock: !Select [0, !Cidr [!Ref VpcCidr, 4, 8]]
      AvailabilityZone: !Select [0, !GetAZs '']
      MapPublicIpOnLaunch: false  # Security: No public IPs
      Tags:
        - Key: Name
          Value: !Sub '${Environment}-private-1'

Outputs:
  VpcId:
    Value: !Ref VPC
    Export:
      Name: !Sub '${Environment}-VpcId'
```

---

## Drift Detection — Catching Unauthorized Changes

```bash
# Terraform: Detect drift
terraform plan -detailed-exitcode
# Exit code 0 = no changes (good)
# Exit code 2 = changes detected (investigate!)

# AWS Config: Automatic drift detection
# Alerts when resources don't match their expected configuration

# CloudFormation: Built-in drift detection
aws cloudformation detect-stack-drift --stack-name my-stack
aws cloudformation describe-stack-drift-detection-status \
    --stack-drift-detection-id DETECTION_ID
```

---

## Memory Technique: "PLAN SCAN APPLY MONITOR"

Every IaC change follows this cycle:
1. **PLAN** — `terraform plan` (what will change?)
2. **SCAN** — `checkov -d .` (is it secure?)
3. **APPLY** — `terraform apply` (make the change)
4. **MONITOR** — drift detection (did anything change unexpectedly?)

---

## Common Mistakes

1. **No remote state** — Local state gets lost, corrupted, or leaked
2. **No state locking** — Two people apply simultaneously = corruption
3. **Secrets in .tf files** — Use variables with `sensitive = true`
4. **No scanning in pipeline** — Misconfigurations reach production
5. **`terraform apply -auto-approve`** — Always review the plan first
6. **Ignoring Checkov findings** — Each finding is a real security risk
7. **No tagging strategy** — Can't track ownership or cost

---

## Interview Insight

**Q: "How do you ensure Infrastructure as Code is secure?"**

"I implement security at four levels:

1. **Development time** — IDE plugins (tfsec in VS Code) give instant feedback
2. **Pre-commit** — Git hooks run Checkov before code is committed
3. **CI pipeline** — Automated scanning blocks insecure changes from merging
4. **Runtime** — AWS Config monitors for drift from desired state

Additionally:
- All state is encrypted and access-controlled
- Secrets are never in code (referenced from Secrets Manager/Vault)
- Modules enforce organizational standards (encryption, logging, tagging)
- Changes require PR approval from security team for sensitive resources
- We use Sentinel/OPA policies to enforce guardrails that can't be bypassed

This gives us defense in depth — even if one layer fails, others catch it."
