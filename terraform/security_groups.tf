# ============================================================
# SECURITY GROUPS - defined first without rules
# Rules are added separately to avoid circular references
# ============================================================

resource "aws_security_group" "alb" {
  name        = "${var.project_name}-sg-alb"
  description = "Security group for the Application Load Balancer"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-sg-alb"
  }
}

resource "aws_security_group" "tasks" {
  name        = "${var.project_name}-sg-tasks"
  description = "Security group for Fargate tasks - ingress from ALB only"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-sg-tasks"
  }
}

resource "aws_security_group" "vpce" {
  name        = "${var.project_name}-sg-vpce"
  description = "Security group for VPC endpoints - ingress from Fargate tasks only"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-sg-vpce"
  }
}

# ============================================================
# SECURITY GROUP RULES
# ============================================================

# AVD-AWS-0107: Public HTTP ingress on ALB is intentional.
# The ALB is the single public entry point. Fargate tasks run
# in private subnets with no public IP and are unreachable
# directly. Restricting ALB ingress would make the app
# inaccessible. Production should restrict to known IP ranges
# or add a WAF. Documented as future work.
#tfsec:ignore:AVD-AWS-0107
resource "aws_security_group_rule" "alb_ingress_http" {
  type              = "ingress"
  security_group_id = aws_security_group.alb.id
  description       = "HTTP from internet - ALB is intentional public entry point"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "alb_egress_tasks" {
  type                     = "egress"
  security_group_id        = aws_security_group.alb.id
  description              = "Forward to Fargate tasks only"
  from_port                = var.container_port
  to_port                  = var.container_port
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.tasks.id
}

resource "aws_security_group_rule" "tasks_ingress_alb" {
  type                     = "ingress"
  security_group_id        = aws_security_group.tasks.id
  description              = "From ALB only on container port"
  from_port                = var.container_port
  to_port                  = var.container_port
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.alb.id
}

resource "aws_security_group_rule" "tasks_egress_vpce" {
  type                     = "egress"
  security_group_id        = aws_security_group.tasks.id
  description              = "HTTPS to VPC endpoints only"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.vpce.id
}

# DNS resolution: the Fargate task must reach the VPC resolver
# (AmazonProvidedDNS, inside the VPC CIDR) on port 53 to resolve
# the interface-endpoint hostnames to their private IPs. Without
# this, ECR resolves to a public address the task cannot reach
# with no NAT, and the image pull fails.
resource "aws_security_group_rule" "tasks_egress_dns_udp" {
  type              = "egress"
  security_group_id = aws_security_group.tasks.id
  description       = "DNS resolution to VPC resolver (UDP)"
  from_port         = 53
  to_port           = 53
  protocol          = "udp"
  cidr_blocks       = [var.vpc_cidr]
}

resource "aws_security_group_rule" "tasks_egress_dns_tcp" {
  type              = "egress"
  security_group_id = aws_security_group.tasks.id
  description       = "DNS resolution to VPC resolver (TCP fallback)"
  from_port         = 53
  to_port           = 53
  protocol          = "tcp"
  cidr_blocks       = [var.vpc_cidr]
}

# ECR image layers are stored in S3 and fetched through the S3
# gateway endpoint. The gateway endpoint is reached by routing,
# but the task egress security group must still permit outbound
# 443 to the S3 service IP ranges via its managed prefix list.
# Without this rule the layer fetch is blocked at the security
# group even though the route exists, and the pull never starts.
resource "aws_security_group_rule" "tasks_egress_s3" {
  type              = "egress"
  security_group_id = aws_security_group.tasks.id
  description       = "HTTPS to S3 gateway endpoint for ECR image layers"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  prefix_list_ids   = ["pl-6ea54007"]
}

resource "aws_security_group_rule" "vpce_ingress_tasks" {
  type                     = "ingress"
  security_group_id        = aws_security_group.vpce.id
  description              = "HTTPS from Fargate tasks only"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.tasks.id
}

resource "aws_security_group_rule" "vpce_egress_vpc" {
  type              = "egress"
  security_group_id = aws_security_group.vpce.id
  description       = "Allow all outbound within VPC"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = [var.vpc_cidr]
}