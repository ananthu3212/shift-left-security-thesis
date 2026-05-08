# ============================================================
# IAM — ECS TASK EXECUTION ROLE
# Used by ECS/Fargate ITSELF (not the app) to:
# - Pull the container image from ECR
# - Write logs to CloudWatch
# - Fetch secrets from Secrets Manager at startup
#
# This is SEPARATE from the task role below.
# Separating these two roles is a security hardening decision:
# the app cannot access ECR or CloudWatch directly.
# ============================================================
resource "aws_iam_role" "execution_role" {
  name        = "${var.project_name}-execution-role"
  description = "ECS task execution role — used by Fargate agent, not the app"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Scoped execution policy — least privilege
# Only allows access to THIS specific ECR repo, log group and secret
resource "aws_iam_role_policy" "execution_policy" {
  name = "${var.project_name}-execution-policy"
  role = aws_iam_role.execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ECRAuthorisation"
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken"
        ]
        Resource = "*"
      },
      {
        Sid    = "ECRImagePull"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage"
        ]
        Resource = aws_ecr_repository.app.arn
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.app.arn}:*"
      },
      {
        Sid    = "SecretsManager"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = aws_secretsmanager_secret.app_secret_key.arn
      }
    ]
  })
}

# ============================================================
# IAM — ECS TASK ROLE
# Used by the Flask APPLICATION itself at runtime.
# Currently empty — the Flask app does not need to call
# any AWS services directly.
#
# In production this would contain only the specific
# permissions the app needs (e.g. S3 read for uploads).
# Keeping it empty by default enforces least privilege.
# ============================================================
resource "aws_iam_role" "task_role" {
  name        = "${var.project_name}-task-role"
  description = "ECS task role — used by the Flask app at runtime"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# ============================================================
# IAM — GITHUB ACTIONS OIDC
# Allows GitHub Actions to assume an AWS role without
# storing long-lived AWS access keys in GitHub Secrets.
# This is a security hardening decision: OIDC federation
# means no static credentials that can be leaked or rotated.
# ============================================================
resource "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"

  client_id_list = ["sts.amazonaws.com"]

  # GitHub Actions OIDC thumbprint (stable, published by GitHub)
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

resource "aws_iam_role" "github_actions" {
  name        = "${var.project_name}-github-actions-role"
  description = "Role assumed by GitHub Actions via OIDC — no static keys"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.github.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringLike = {
            "token.actions.githubusercontent.com:sub" = "repo:ananthu3212/shift-left-security-thesis:*"
          }
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "github_actions_policy" {
  name = "${var.project_name}-github-actions-policy"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ECRAccess"
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload"
        ]
        Resource = [
          "*",
          aws_ecr_repository.app.arn
        ]
      },
      {
        Sid    = "ECSAccess"
        Effect = "Allow"
        Action = [
          "ecs:UpdateService",
          "ecs:DescribeServices",
          "ecs:DescribeTaskDefinition",
          "ecs:RegisterTaskDefinition"
        ]
        Resource = "*"
      },
      {
        Sid    = "PassRole"
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = [
          aws_iam_role.execution_role.arn,
          aws_iam_role.task_role.arn
        ]
      }
    ]
  })
}