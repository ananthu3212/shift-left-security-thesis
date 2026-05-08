# ============================================================
# ECS CLUSTER
# ============================================================
resource "aws_ecs_cluster" "main" {
  name = "${var.project_name}-cluster"

  # Container Insights: enables CloudWatch metrics per task
  # CPU, memory, network — visible in CloudWatch dashboard
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
# Defines how the Flask container runs on Fargate.
#
# Security hardening decisions documented inline:
# - assign_public_ip = false (enforced in service below)
# - read_only_root_filesystem = true
# - non-root user (10001:10001)
# - drop ALL Linux capabilities
# - secret injected via secrets block, not environment
# ============================================================
resource "aws_ecs_task_definition" "app" {
  family                   = "${var.project_name}-task"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.fargate_cpu
  memory                   = var.fargate_memory

  # Execution role: used by Fargate agent to pull image + secrets
  execution_role_arn = aws_iam_role.execution_role.arn

  # Task role: used by the Flask app itself at runtime
  # Currently empty — Flask app needs no AWS permissions
  task_role_arn = aws_iam_role.task_role.arn

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

      # Secret injected via Secrets Manager — not plain env var
      # The value is fetched by the Fargate agent at startup
      # using the execution role. The app receives it as an
      # environment variable but it is never stored in plaintext
      # in the task definition or logs.
      secrets = [
        {
          name      = "SECRET_KEY"
          valueFrom = "${aws_secretsmanager_secret.app_secret_key.arn}:SECRET_KEY::"
        }
      ]

      # Security hardening: read-only root filesystem
      # Prevents any process inside the container from writing
      # to the filesystem — limits damage from RCE exploits
      readonlyRootFilesystem = true

      # Security hardening: non-root user
      # The Flask app runs as UID 10001, not root (UID 0)
      # Even if an attacker achieves RCE, they cannot escalate
      # to root inside the container
      user = "10001:10001"

      # Security hardening: drop ALL Linux capabilities
      # Fargate drops most capabilities by default; this makes
      # it explicit and documents the security decision
      linuxParameters = {
        capabilities = {
          drop = ["ALL"]
        }
        initProcessEnabled = true
      }

      # CloudWatch logging
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
# Lives in public subnets — the only public-facing component
# Fargate tasks are in private subnets with no public IP
# ============================================================
resource "aws_lb" "main" {
  name               = "${var.project_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  # Deletion protection off for thesis — easy teardown
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
# Runs and maintains the desired number of Fargate tasks.
#
# Key hardening decision: assign_public_ip = false
# Tasks run in private subnets with no public IP address.
# The only entry point is through the ALB.
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