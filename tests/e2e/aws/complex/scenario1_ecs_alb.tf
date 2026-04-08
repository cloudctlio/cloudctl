# ── Scenario 1: ECS + ALB — unhealthy targets from security group mismatch ───
# ECS tasks run nginx on port 80. The task security group intentionally has
# NO inbound rule allowing the ALB to reach port 80. ALB health checks fail →
# all targets report unhealthy → ALB returns 503 for every request.

# ALB security group — allows HTTP inbound from internet
resource "aws_security_group" "alb" {
  name        = "${local.name}-alb-sg"
  description = "ALB: allow inbound HTTP from internet"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP from internet"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.tags, { Name = "${local.name}-alb-sg" })
}

# ECS task security group — BUG: no inbound rule for port 80
# ALB tries to health-check on port 80 → blocked → targets unhealthy
resource "aws_security_group" "ecs_task" {
  name        = "${local.name}-ecs-task-sg"
  description = "ECS tasks: missing inbound 80 - intentional misconfiguration"
  vpc_id      = aws_vpc.main.id

  # Only port 8080 is open — but the app listens on 80
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
    description = "Wrong port - nginx listens on 80 not 8080"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.tags, { Name = "${local.name}-ecs-task-sg-misconfigured" })
}

# ALB
resource "aws_lb" "main" {
  name               = "${local.name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = [aws_subnet.public_a.id, aws_subnet.public_b.id]
  tags               = local.tags
}

# Target group — health check on port 80 (blocked by task SG)
resource "aws_lb_target_group" "ecs" {
  name        = "${local.name}-ecs-tg"
  port        = 80
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.main.id

  health_check {
    path                = "/"
    port                = "80"
    protocol            = "HTTP"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 10
    timeout             = 5
  }

  tags = local.tags
}

# Listener
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ecs.arn
  }
}

# ECS cluster
resource "aws_ecs_cluster" "main" {
  name = "${local.name}-cluster"
  tags = local.tags
}

# CloudWatch log group for ECS
resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/ecs/${local.name}-nginx"
  retention_in_days = 3
  tags              = local.tags
}

# ECS task definition — nginx, port 80
resource "aws_ecs_task_definition" "nginx" {
  family                   = "${local.name}-nginx"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.ecs_task_exec.arn

  container_definitions = jsonencode([{
    name      = "nginx"
    image     = "public.ecr.aws/docker/library/nginx:alpine"
    essential = true
    portMappings = [{ containerPort = 80, protocol = "tcp" }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.ecs.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "nginx"
      }
    }
  }])

  tags = local.tags
}

# ECS service — Fargate in public subnet (assign_public_ip to pull image)
resource "aws_ecs_service" "nginx" {
  name            = "${local.name}-nginx"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.nginx.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = [aws_subnet.public_a.id, aws_subnet.public_b.id]
    security_groups  = [aws_security_group.ecs_task.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.ecs.arn
    container_name   = "nginx"
    container_port   = 80
  }

  tags = local.tags
}
