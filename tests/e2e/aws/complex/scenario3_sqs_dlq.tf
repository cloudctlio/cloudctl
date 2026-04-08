# ── Scenario 3: SQS → Lambda → DLQ (processor always fails) ─────────────────
# Lambda raises ValueError on every message → SQS retries (maxReceiveCount=2)
# → message lands in DLQ. DLQ depth grows; Lambda errors spike in CloudWatch.

resource "aws_sqs_queue" "dlq" {
  name                      = "${local.name}-dlq"
  message_retention_seconds = 86400
  tags                      = local.tags
}

resource "aws_sqs_queue" "main_queue" {
  name                       = "${local.name}-main"
  visibility_timeout_seconds = 30
  message_retention_seconds  = 86400

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq.arn
    maxReceiveCount     = 2
  })

  tags = local.tags
}

data "archive_file" "sqs_processor" {
  type        = "zip"
  source_file = "${path.module}/handlers/sqs_processor/handler.py"
  output_path = "${path.module}/.build/sqs_processor.zip"
}

resource "aws_lambda_function" "sqs_processor" {
  function_name    = "${local.name}-sqs-processor"
  filename         = data.archive_file.sqs_processor.output_path
  source_code_hash = data.archive_file.sqs_processor.output_base64sha256
  handler          = "handler.handler"
  runtime          = "python3.12"
  role             = aws_iam_role.lambda_exec.arn
  timeout          = 10

  tags = local.tags
}

resource "aws_cloudwatch_log_group" "sqs_processor" {
  name              = "/aws/lambda/${aws_lambda_function.sqs_processor.function_name}"
  retention_in_days = 3
  tags              = local.tags
}

resource "aws_lambda_event_source_mapping" "sqs_processor" {
  event_source_arn = aws_sqs_queue.main_queue.arn
  function_name    = aws_lambda_function.sqs_processor.arn
  batch_size       = 1
  enabled          = true
}

# CloudWatch alarm — DLQ depth > 0
resource "aws_cloudwatch_metric_alarm" "dlq_depth" {
  alarm_name          = "${local.name}-dlq-depth"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Messages are landing in the DLQ - processor is failing"

  dimensions = {
    QueueName = aws_sqs_queue.dlq.name
  }

  tags = local.tags
}
