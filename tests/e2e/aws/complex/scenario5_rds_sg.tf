# ── Scenario 5: Lambda ↔ RDS security group mismatch ─────────────────────────
# RDS inbound rule whitelists only `rds-access-sg`.
# Lambda uses `lambda-sg` (a different SG) — TCP handshake to port 5432 times out.
# Lambda logs the SG mismatch; handler raises TimeoutError.

# Security group that IS whitelisted on RDS (not attached to Lambda)
resource "aws_security_group" "rds_access" {
  name        = "${local.name}-rds-access-sg"
  description = "Whitelisted on RDS - intentionally NOT attached to the Lambda"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.tags, { Name = "${local.name}-rds-access-sg" })
}

# Security group attached to Lambda — NOT whitelisted on RDS
resource "aws_security_group" "lambda_rds" {
  name        = "${local.name}-lambda-sg"
  description = "Lambda SG - NOT in RDS inbound allow-list (intentional misconfiguration)"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.tags, { Name = "${local.name}-lambda-sg-misconfigured" })
}

# RDS security group — only allows inbound from rds-access-sg, NOT lambda-sg
resource "aws_security_group" "rds" {
  name        = "${local.name}-rds-sg"
  description = "RDS: allow port 5432 only from rds-access-sg"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.rds_access.id]
    description     = "PostgreSQL from rds-access-sg only - lambda-sg is blocked"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.tags, { Name = "${local.name}-rds-sg" })
}

# DB subnet group (uses private subnets)
resource "aws_db_subnet_group" "main" {
  name       = "${local.name}-db-subnet-group"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  tags       = local.tags
}

# RDS PostgreSQL (db.t3.micro — cheapest option)
resource "aws_db_instance" "main" {
  identifier             = "${local.name}-postgres"
  engine                 = "postgres"
  engine_version         = "16.3"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  storage_type           = "gp2"
  db_name                = "testdb"
  username               = "dbadmin"
  password               = "Change_Me_123!"   # non-sensitive — test env only
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  skip_final_snapshot    = true
  publicly_accessible    = false
  multi_az               = false
  deletion_protection    = false
  tags                   = local.tags
}

data "archive_file" "rds_connect" {
  type        = "zip"
  source_file = "${path.module}/handlers/rds_connect/handler.py"
  output_path = "${path.module}/.build/rds_connect.zip"
}

resource "aws_lambda_function" "rds_connect" {
  function_name    = "${local.name}-rds-connect"
  filename         = data.archive_file.rds_connect.output_path
  source_code_hash = data.archive_file.rds_connect.output_base64sha256
  handler          = "handler.handler"
  runtime          = "python3.12"
  role             = aws_iam_role.lambda_exec.arn
  timeout          = 15

  vpc_config {
    subnet_ids         = [aws_subnet.private_a.id, aws_subnet.private_b.id]
    security_group_ids = [aws_security_group.lambda_rds.id]
  }

  environment {
    variables = {
      DB_HOST = aws_db_instance.main.address
      DB_PORT = "5432"
    }
  }

  tags = local.tags
}

resource "aws_cloudwatch_log_group" "rds_connect" {
  name              = "/aws/lambda/${aws_lambda_function.rds_connect.function_name}"
  retention_in_days = 3
  tags              = local.tags
}

resource "aws_apigatewayv2_integration" "rds_connect" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.rds_connect.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "rds_connect" {
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "GET /rds-connect"
  target    = "integrations/${aws_apigatewayv2_integration.rds_connect.id}"
}

resource "aws_lambda_permission" "rds_connect" {
  statement_id  = "AllowAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.rds_connect.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*"
}
