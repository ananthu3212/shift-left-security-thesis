# ============================================================
# KMS KEY - SECRETS MANAGER ENCRYPTION
# Fix for AVD-AWS-0098: Secrets Manager must use a customer-
# managed key instead of the AWS default key for:
# - Full auditability of secret access via CloudTrail
# - Ability to revoke access by disabling the key
# - Automatic annual key rotation
# ============================================================
resource "aws_kms_key" "secrets" {
  description             = "KMS key for Secrets Manager encryption - fix AVD-AWS-0098"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name = "${var.project_name}-secrets-kms"
  }
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/${var.project_name}-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}

# ============================================================
# SECRETS MANAGER
# Flask application secret key - injected at runtime via
# ECS task definition secrets block.
# Now encrypted with a customer-managed KMS key.
# ============================================================
resource "aws_secretsmanager_secret" "app_secret_key" {
  name        = "${var.project_name}/flask-secret-key"
  description = "Flask application SECRET_KEY - injected at runtime via ECS secrets block"
  kms_key_id  = aws_kms_key.secrets.arn

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