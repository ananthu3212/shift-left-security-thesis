# ============================================================
# KMS KEY - ECR ENCRYPTION
# ============================================================
resource "aws_kms_key" "ecr" {
  description             = "KMS key for ECR repository encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name = "${var.project_name}-ecr-kms"
  }
}

resource "aws_kms_alias" "ecr" {
  name          = "alias/${var.project_name}-ecr"
  target_key_id = aws_kms_key.ecr.key_id
}

# ============================================================
# KMS KEY - CLOUDWATCH LOGS ENCRYPTION
# Fix for AVD-AWS-0017: CloudWatch Log Group must be encrypted
# with a customer-managed key for auditability and key rotation.
# A dedicated key is used (not the ECR key) to follow the
# principle of key separation - different resources use
# different encryption keys to limit blast radius.
#
# The key policy grants the CloudWatch Logs service principal
# permission to use this key for log encryption/decryption.
# Without this policy, CloudWatch cannot access the key even
# if the log group specifies it.
# ============================================================
resource "aws_kms_key" "logs" {
  description             = "KMS key for CloudWatch Logs encryption - fix AVD-AWS-0017"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudWatchLogs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.aws_region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnEquals = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/ecs/${var.project_name}"
          }
        }
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-logs-kms"
  }
}

resource "aws_kms_alias" "logs" {
  name          = "alias/${var.project_name}-logs"
  target_key_id = aws_kms_key.logs.key_id
}

# ============================================================
# ECR REPOSITORY
# ============================================================
resource "aws_ecr_repository" "app" {
  name                 = "${var.project_name}/flask-webgoat"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.ecr.arn
  }

  tags = {
    Name = "${var.project_name}-ecr"
  }
}

resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Delete untagged images after 1 day"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 1
        }
        action = {
          type = "expire"
        }
      },
      {
        rulePriority = 2
        description  = "Keep only last 10 tagged images"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["v"]
          countType     = "imageCountMoreThan"
          countNumber   = 10
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

# ============================================================
# CLOUDWATCH LOG GROUP
# Fix for AVD-AWS-0017: encrypted with customer-managed KMS key.
# ============================================================
resource "aws_cloudwatch_log_group" "app" {
  name              = "/ecs/${var.project_name}"
  retention_in_days = 7
  kms_key_id        = aws_kms_key.logs.arn

  tags = {
    Name = "${var.project_name}-logs"
  }
}