resource "aws_sqs_queue" "orders_dlq" {
  name                      = "${var.prefix}-orders-dlq"
  message_retention_seconds = 86400
}

resource "aws_sqs_queue" "orders" {
  name                       = "${var.prefix}-orders"
  visibility_timeout_seconds = 30
  message_retention_seconds  = 86400

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.orders_dlq.arn
    maxReceiveCount     = 3
  })
}

# Custom bus: the worker publishes OrderProcessed, the notifier consumes it.
resource "aws_cloudwatch_event_bus" "orders" {
  name = "${var.prefix}-bus"
}

resource "aws_cloudwatch_event_rule" "order_processed" {
  name           = "${var.prefix}-order-processed"
  event_bus_name = aws_cloudwatch_event_bus.orders.name

  event_pattern = jsonencode({
    source        = ["cctl.orders"]
    "detail-type" = ["OrderProcessed"]
  })
}

resource "aws_cloudwatch_event_target" "notifier" {
  rule           = aws_cloudwatch_event_rule.order_processed.name
  event_bus_name = aws_cloudwatch_event_bus.orders.name
  arn            = aws_lambda_function.notifier.arn
}
