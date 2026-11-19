data "archive_file" "api" {
  type        = "zip"
  source_file = "${path.module}/src/api.py"
  output_path = "${path.module}/.build/api.zip"
}

data "archive_file" "worker" {
  type        = "zip"
  source_file = "${path.module}/src/worker.py"
  output_path = "${path.module}/.build/worker.zip"
}

data "archive_file" "notifier" {
  type        = "zip"
  source_file = "${path.module}/src/notifier.py"
  output_path = "${path.module}/.build/notifier.zip"
}

# Log groups are created here (not by Lambda) so terraform destroy removes them.
resource "aws_cloudwatch_log_group" "api" {
  name              = "/aws/lambda/${var.prefix}-api"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "worker" {
  name              = "/aws/lambda/${var.prefix}-worker"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "notifier" {
  name              = "/aws/lambda/${var.prefix}-notifier"
  retention_in_days = var.log_retention_days
}

# ── api: POST /orders and GET /orders/{id} ────────────────────────────────────
resource "aws_lambda_function" "api" {
  function_name    = "${var.prefix}-api"
  role             = aws_iam_role.api.arn
  runtime          = "python3.12"
  handler          = "api.handler"
  filename         = data.archive_file.api.output_path
  source_code_hash = data.archive_file.api.output_base64sha256
  timeout          = 10
  memory_size      = 256

  environment {
    variables = {
      TABLE_NAME = aws_dynamodb_table.orders.name
      QUEUE_URL  = aws_sqs_queue.orders.url
    }
  }

  depends_on = [aws_cloudwatch_log_group.api, aws_iam_role_policy.api]
}

# ── worker: consumes the orders queue ─────────────────────────────────────────
resource "aws_lambda_function" "worker" {
  function_name    = "${var.prefix}-worker"
  role             = aws_iam_role.worker.arn
  runtime          = "python3.12"
  handler          = "worker.handler"
  filename         = data.archive_file.worker.output_path
  source_code_hash = data.archive_file.worker.output_base64sha256
  timeout          = 10
  memory_size      = 256

  reserved_concurrent_executions = var.worker_reserved_concurrency

  environment {
    variables = {
      TABLE_NAME     = aws_dynamodb_table.orders.name
      RECEIPT_BUCKET = aws_s3_bucket.receipts.id
      BUS_NAME       = aws_cloudwatch_event_bus.orders.name
      BASE_MS        = "200"
      ITEM_MS        = "300"
    }
  }

  depends_on = [aws_cloudwatch_log_group.worker, aws_iam_role_policy.worker]
}

resource "aws_lambda_event_source_mapping" "worker" {
  event_source_arn = aws_sqs_queue.orders.arn
  function_name    = aws_lambda_function.worker.arn
  batch_size       = 1
}

# ── notifier: EventBridge OrderProcessed -> marks the order notified ──────────
resource "aws_lambda_function" "notifier" {
  function_name    = "${var.prefix}-notifier"
  role             = aws_iam_role.notifier.arn
  runtime          = "python3.12"
  handler          = "notifier.handler"
  filename         = data.archive_file.notifier.output_path
  source_code_hash = data.archive_file.notifier.output_base64sha256
  timeout          = 10
  memory_size      = 128

  environment {
    variables = {
      TABLE_NAME = aws_dynamodb_table.orders.name
    }
  }

  depends_on = [aws_cloudwatch_log_group.notifier, aws_iam_role_policy.notifier]
}

resource "aws_lambda_permission" "notifier_events" {
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.notifier.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.order_processed.arn
}
