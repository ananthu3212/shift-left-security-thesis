# ============================================================
# ECR REPOSITORY
# Stores the Docker image for the Flask application.
#
# Security hardening decisions:
# - IMMUTABLE tags: once an image is pushed with a tag,
#   it cannot be overwritten. This prevents supply chain
#   attacks where an attacker overwrites a trusted image.
# - scan_on_push: AWS Inspector scans every image for CVEs
#   automatically on push — a second layer of SCA beyond
#   the Trivy scan in the pipeline.
# - Encryption with KMS CMK: images are encrypted at rest
#   with a customer-managed key for auditability and
#   key rotation control.
# ============================================================

# KMS key for ECR encryption
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

# ECR Repository
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

# ============================================================
# ECR LIFECYCLE POLICY
# Keeps only the last 10 images to control storage costs.
# Untagged images (failed builds) are deleted after 1 day.
# ============================================================
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
          tagStatus   = "tagged"
          tagPrefixList = ["v"]
          countType   = "imageCountMoreThan"
          countNumber = 10
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
# Centralised logging for Fargate tasks.
# Retention set to 7 days to control costs.
# ============================================================
resource "aws_cloudwatch_log_group" "app" {
  name              = "/ecs/${var.project_name}"
  retention_in_days = 7

  tags = {
    Name = "${var.project_name}-logs"
  }
}