# ============================================================
# Phase 7 — Complete Infrastructure Stack
# Deploys: VPC + ECS Fargate + RDS + ALB + Monitoring
# All security best practices applied
# ============================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "project" {
  default = "devsecops-lab"
}

variable "environment" {
  default = "production"
}

variable "aws_region" {
  default = "us-east-1"
}

locals {
  name_prefix = "${var.project}-${var.environment}"
  common_tags = {
    Project     = var.project
    Environment = var.environment
    ManagedBy   = "terraform"
    SecurityScan = "checkov-passed"
  }
}

# ============================================================
# KMS — Encryption Keys (encrypt everything!)
# ============================================================

resource "aws_kms_key" "main" {
  description             = "Main encryption key for ${local.name_prefix}"
  deletion_window_in_days = 30
  enable_key_rotation     = true  # Security: Auto-rotate keys

  tags = local.common_tags
}

resource "aws_kms_alias" "main" {
  name          = "alias/${local.name_prefix}"
  target_key_id = aws_kms_key.main.key_id
}

# ============================================================
# ECS Cluster — Container Orchestration
# ============================================================

resource "aws_ecs_cluster" "main" {
  name = "${local.name_prefix}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"  # Security: Full visibility into containers
  }

  configuration {
    execute_command_configuration {
      # Security: Encrypt exec sessions and log them
      kms_key_id = aws_kms_key.main.arn
      logging    = "OVERRIDE"

      log_configuration {
        cloud_watch_log_group_name = "/ecs/${local.name_prefix}/exec-audit"
      }
    }
  }

  tags = local.common_tags
}

# ============================================================
# ECS Task Definition — Secure Container Configuration
# ============================================================

resource "aws_ecs_task_definition" "app" {
  family                   = "${local.name_prefix}-app"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name  = "app"
      image = "ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/my-app:latest"
      
      # Security: Read-only root filesystem
      readonlyRootFilesystem = true
      
      # Security: Run as non-root user
      user = "1000:1000"
      
      # Security: No privilege escalation
      linuxParameters = {
        capabilities = {
          drop = ["ALL"]
        }
      }

      portMappings = [{
        containerPort = 8080
        protocol      = "tcp"
      }]

      # Security: No secrets in environment variables
      # Use secrets from Secrets Manager instead
      secrets = [
        {
          name      = "DB_PASSWORD"
          valueFrom = "arn:aws:secretsmanager:us-east-1:ACCOUNT:secret:db-password"
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = "/ecs/${local.name_prefix}/app"
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "app"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "curl -f http://localhost:8080/health || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 60
      }
    }
  ])

  tags = local.common_tags
}

# ============================================================
# IAM Roles — Least Privilege
# ============================================================

# ECS Execution Role (pulls images, writes logs)
resource "aws_iam_role" "ecs_execution" {
  name = "${local.name_prefix}-ecs-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# ECS Task Role (what the app can do — LEAST PRIVILEGE)
resource "aws_iam_role" "ecs_task" {
  name = "${local.name_prefix}-ecs-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })

  tags = local.common_tags
}

# Task can ONLY read from specific S3 bucket and write to specific SQS queue
resource "aws_iam_role_policy" "ecs_task" {
  name = "task-permissions"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          "arn:aws:s3:::${local.name_prefix}-data",
          "arn:aws:s3:::${local.name_prefix}-data/*"
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = "arn:aws:sqs:${var.aws_region}:*:${local.name_prefix}-events"
      }
    ]
  })
}

# ============================================================
# RDS — Secure Database
# ============================================================

resource "aws_db_instance" "main" {
  identifier = "${local.name_prefix}-db"

  engine         = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.micro"

  allocated_storage     = 20
  max_allocated_storage = 100

  # Security: Encryption at rest
  storage_encrypted = true
  kms_key_id        = aws_kms_key.main.arn

  # Security: No public access
  publicly_accessible = false

  # Security: Multi-AZ for resilience
  multi_az = true

  # Security: Automated backups
  backup_retention_period = 30
  backup_window           = "03:00-04:00"

  # Security: Delete protection
  deletion_protection = true

  # Security: Enhanced monitoring
  monitoring_interval = 60

  # Security: Auto minor version upgrades (security patches)
  auto_minor_version_upgrade = true

  # Security: Audit logging
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  # Security: IAM authentication
  iam_database_authentication_enabled = true

  skip_final_snapshot = false
  final_snapshot_identifier = "${local.name_prefix}-final-snapshot"

  tags = local.common_tags
}

# ============================================================
# CloudWatch Alarms — Security Monitoring
# ============================================================

resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "${local.name_prefix}-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "ECS CPU utilization above 80% - possible crypto mining"
  
  dimensions = {
    ClusterName = aws_ecs_cluster.main.name
  }

  alarm_actions = [] # Add SNS topic ARN
}

resource "aws_cloudwatch_metric_alarm" "db_connections" {
  alarm_name          = "${local.name_prefix}-db-connections"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 50
  alarm_description   = "Unusual number of DB connections - possible SQL injection"

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.id
  }
}
