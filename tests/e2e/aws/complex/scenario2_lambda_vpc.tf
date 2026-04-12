# ── Scenario 2: Lambda in private subnet with no NAT Gateway ─────────────────
# Lambda tries to reach the internet (checkip.amazonaws.com).
# Private subnets have NO default route → no NAT Gateway → connection fails.
# Lambda logs a timeout; CloudWatch shows errors. No 0.0.0.0/0 route in private RT.

data "archive_file" "vpc_no_nat" {
  type        = "zip"
  source_file = "${path.module}/handlers/vpc_no_nat/handler.py"
  output_path = "${path.module}/.build/vpc_no_nat.zip"
}

# Security group for the Lambda — allows all egress, but the route table has no IGW
resource "aws_security_group" "lambda_vpc_no_nat" {
  name        = "${local.name}-lambda-vpc-sg"
  description = "Lambda VPC: egress allowed but no NAT route exists"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.tags, { Name = "${local.name}-lambda-vpc-sg" })
}

resource "aws_lambda_function" "vpc_no_nat" {
  function_name    = "${local.name}-vpc-no-nat"
  filename         = data.archive_file.vpc_no_nat.output_path
  source_code_hash = data.archive_file.vpc_no_nat.output_base64sha256
  handler          = "handler.handler"
  runtime          = "python3.12"
  role             = aws_iam_role.lambda_exec.arn
  timeout          = 10

  vpc_config {
    subnet_ids         = [aws_subnet.private_a.id, aws_subnet.private_b.id]
    security_group_ids = [aws_security_group.lambda_vpc_no_nat.id]
  }

  environment {
    variables = {
      TARGET_URL = "https://checkip.amazonaws.com"
    }
  }

  tags = local.tags
}

resource "aws_cloudwatch_log_group" "vpc_no_nat" {
  name              = "/aws/lambda/${aws_lambda_function.vpc_no_nat.function_name}"
  retention_in_days = 3
  tags              = local.tags
}

# API GW integration
resource "aws_apigatewayv2_integration" "vpc_no_nat" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.vpc_no_nat.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "vpc_no_nat" {
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "GET /vpc-no-nat"
  target    = "integrations/${aws_apigatewayv2_integration.vpc_no_nat.id}"
}

resource "aws_lambda_permission" "vpc_no_nat" {
  statement_id  = "AllowAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.vpc_no_nat.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*"
}
