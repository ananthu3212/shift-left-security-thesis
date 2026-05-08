# ============================================================
# SECRETS MANAGER
# Stores the Flask application secret key at runtime.
#
# Security hardening decision:
# This secret is injected into the Fargate task at startup
# via the task definition "secrets" block — NOT passed as a
# plain environment variable. This means:
# - The secret value never appears in the task definition
# - The secret never appears in CloudWatch logs
# - Access is controlled by IAM (execution role only)
# - All access is audited via CloudTrail
#
# This directly addresses the ground truth vulnerability V11
# (hardcoded secret key in __init__.py) by demonstrating
# the correct production pattern.
# ============================================================

resource "aws_secretsmanager_secret" "app_secret_key" {
  name        = "${var.project_name}/flask-secret-key"
  description = "Flask application SECRET_KEY — injected at runtime via ECS secrets block"

  recovery_window_in_days = 0

  tags = {
    Name = "${var.project_name}-secret-key"
  }
}

resource "aws_secretsmanager_secret_version" "app_secret_key" {
  secret_id = aws_secretsmanager_secret.app_secret_key.id

  secret_string = jsonencode({
    SECRET_KEY = "thesis-demo-secret-change-in-production"
  })
}