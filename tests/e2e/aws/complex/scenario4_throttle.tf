# ── Scenario 4: Lambda throttling via reserved concurrency = 1 ───────────────
# Handler sleeps 3 s to hold the single concurrency slot.
# Concurrent invocations → TooManyRequestsException → API GW returns 429/502.
# Lambda Throttles CloudWatch metric spikes; throttled invocations leave no logs.

data "archive_file" "throttle" {
  type        = "zip"
  source_file = "${path.module}/handlers/throttle/handler.py"
  output_path = "${path.module}/.build/throttle.zip"
}

resource "aws_lambda_function" "throttle" {
  function_name = "${local.name}-throttle"
  filename      = data.archive_file.throttle.output_path
  source_code_hash              = data.archive_file.throttle.output_base64sha256
  handler                       = "handler.handler"
  runtime                       = "python3.12"
  role                          = aws_iam_role.lambda_exec.arn
  timeout                       = 10
  # reserved_concurrent_executions = 2  # set manually after deploy if account limit allows

  tags = local.tags
}

resource "aws_cloudwatch_log_group" "throttle" {
  name              = "/aws/lambda/${aws_lambda_function.throttle.function_name}"
  retention_in_days = 3
  tags              = local.tags
}

resource "aws_apigatewayv2_integration" "throttle" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.throttle.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "throttle" {
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "GET /throttle"
  target    = "integrations/${aws_apigatewayv2_integration.throttle.id}"
}

resource "aws_lambda_permission" "throttle" {
  statement_id  = "AllowAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.throttle.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*"
}

# CloudWatch alarm — throttles > 0
resource "aws_cloudwatch_metric_alarm" "throttles" {
  alarm_name          = "${local.name}-lambda-throttles"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Throttles"
  namespace           = "AWS/Lambda"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Lambda throttling detected - reserved concurrency exhausted"

  dimensions = {
    FunctionName = aws_lambda_function.throttle.function_name
  }

  tags = local.tags
}
