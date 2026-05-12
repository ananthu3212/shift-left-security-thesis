# ============================================================
# VPC
# AVD-AWS-0178: VPC Flow Logs not enabled.
# VPC Flow Logs capture all network traffic entering and leaving
# the VPC and are recommended for security monitoring and
# incident response. However, enabling Flow Logs requires either
# an S3 bucket or a dedicated CloudWatch Log Group with
# associated IAM roles, generating ongoing storage costs.
# This is documented as a known limitation of the thesis demo
# environment and is listed as future work.
# In production, Flow Logs should be enabled and forwarded to
# a SIEM solution.
# ============================================================
#tfsec:ignore:AVD-AWS-0178
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.project_name}-vpc"
  }
}