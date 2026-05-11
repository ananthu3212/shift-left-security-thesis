# ============================================================
# ECS CLUSTER
# ============================================================
resource "aws_ecs_cluster" "main" {
  name = "${var.project_name}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name = "${var.project_name}-cluster"
  }
}

# ============================================================
# ECS TASK DEFINITION
# ============================================================
resource "aws_ecs_task_definition" "app" {
  family                   = "${var.project_name}-task"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.fargate_cpu
  memory                   = var.fargate_memory
  execution_role_arn       = aws_iam_role.execution_role.arn
  task_role_arn            = aws_iam_role.task_role.arn

  container_definitions = jsonencode([
    {
      name  = "flask-webgoat"
      image = "${aws_ecr_repository.app.repository_url}:latest"

      portMappings = [
        {
          containerPort = var.container_port
          protocol      = "tcp"
        }
      ]

      secrets = [
        {
          name      = "SECRET_KEY"
          valueFrom = "${aws_secretsmanager_secret.app_secret_key.arn}:SECRET_KEY::"
        }
      ]

      # Security hardening: read-only root filesystem
      readonlyRootFilesystem = true

      # Security hardening: non-root user
      user = "10001:10001"

      # Security hardening: drop ALL Linux capabilities
      linuxParameters = {
        capabilities = {
          drop = ["ALL"]
        }
        initProcessEnabled = true
      }

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.app.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "flask-webgoat"
        }
      }

      essential = true
    }
  ])

  tags = {
    Name = "${var.project_name}-task"
  }
}

# ============================================================
# APPLICATION LOAD BALANCER
#
# tfsec findings — documented design decisions:
#
# AVD-AWS-0053: ALB is intentionally public-facing.
# The Fargate tasks run in private subnets with no public IP.
# The ALB is the single controlled entry point. Making the ALB
# internal would make the demo application unreachable.
#
# AVD-AWS-0054: HTTP (port 80) used instead of HTTPS.
# HTTPS requires a domain name and an ACM certificate, both of
# which are out of scope for this thesis demo environment.
# Production deployment must use HTTPS. Documented as future work.
#
# AVD-AWS-0052: FIXED — drop_invalid_header_fields = true added.
# Dropping invalid HTTP headers prevents HTTP request smuggling
# attacks where malformed headers could be used to bypass security
# controls or poison shared caches.
# ============================================================

#tfsec:ignore:AVD-AWS-0053
resource "aws_lb" "main" {
  name               = "${var.project_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  # Fix for AVD-AWS-0052: drop malformed HTTP headers
  # Prevents HTTP request smuggling attacks
  drop_invalid_header_fields = true

  enable_deletion_protection = false

  tags = {
    Name = "${var.project_name}-alb"
  }
}

resource "aws_lb_target_group" "app" {
  name        = "${var.project_name}-tg"
  port        = var.container_port
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    path                = "/"
    matcher             = "200"
  }

  tags = {
    Name = "${var.project_name}-tg"
  }
}

# tfsec:ignore:AVD-AWS-0054 -- HTTP intentional for thesis demo.
# Production requires HTTPS with ACM certificate. Future work.
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

# ============================================================
# ECS SERVICE
# ============================================================
resource "aws_ecs_service" "app" {
  name            = "${var.project_name}-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.tasks.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app.arn
    container_name   = "flask-webgoat"
    container_port   = var.container_port
  }

  depends_on = [
    aws_lb_listener.http,
    aws_iam_role_policy.execution_policy
  ]

  tags = {
    Name = "${var.project_name}-service"
  }
}