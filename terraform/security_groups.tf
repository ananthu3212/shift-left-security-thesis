# ============================================================
# SECURITY GROUPS — defined first without rules
# Rules are added separately below to avoid circular references
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
  description = "Security group for Fargate tasks — ingress from ALB only"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-sg-tasks"
  }
}

resource "aws_security_group" "vpce" {
  name        = "${var.project_name}-sg-vpce"
  description = "Security group for VPC endpoints — ingress from Fargate tasks only"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-sg-vpce"
  }
}

# ============================================================
# SECURITY GROUP RULES — added after all groups are created
# ============================================================

# ALB — inbound HTTP from internet
resource "aws_security_group_rule" "alb_ingress_http" {
  type              = "ingress"
  security_group_id = aws_security_group.alb.id
  description       = "HTTP from internet"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
}

# ALB — outbound to Fargate tasks only
resource "aws_security_group_rule" "alb_egress_tasks" {
  type                     = "egress"
  security_group_id        = aws_security_group.alb.id
  description              = "Forward to Fargate tasks only"
  from_port                = var.container_port
  to_port                  = var.container_port
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.tasks.id
}

# Tasks — inbound from ALB only
resource "aws_security_group_rule" "tasks_ingress_alb" {
  type                     = "ingress"
  security_group_id        = aws_security_group.tasks.id
  description              = "From ALB only on container port"
  from_port                = var.container_port
  to_port                  = var.container_port
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.alb.id
}

# Tasks — outbound to VPC endpoints only
resource "aws_security_group_rule" "tasks_egress_vpce" {
  type                     = "egress"
  security_group_id        = aws_security_group.tasks.id
  description              = "HTTPS to VPC endpoints only"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.vpce.id
}

# VPC endpoints — inbound from Fargate tasks only
resource "aws_security_group_rule" "vpce_ingress_tasks" {
  type                     = "ingress"
  security_group_id        = aws_security_group.vpce.id
  description              = "HTTPS from Fargate tasks only"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.tasks.id
}

# VPC endpoints — outbound within VPC
resource "aws_security_group_rule" "vpce_egress_vpc" {
  type              = "egress"
  security_group_id = aws_security_group.vpce.id
  description       = "Allow all outbound within VPC"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = [var.vpc_cidr]
}