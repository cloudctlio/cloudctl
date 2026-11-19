output "api_url" {
  value = aws_apigatewayv2_stage.default.invoke_url
}

output "orders_table" {
  value = aws_dynamodb_table.orders.name
}

output "orders_queue_url" {
  value = aws_sqs_queue.orders.url
}

output "orders_dlq_url" {
  value = aws_sqs_queue.orders_dlq.url
}

output "worker_function" {
  value = aws_lambda_function.worker.function_name
}

output "worker_event_source_mapping" {
  value = aws_lambda_event_source_mapping.worker.uuid
}

output "receipts_bucket" {
  value = aws_s3_bucket.receipts.id
}

output "event_bus" {
  value = aws_cloudwatch_event_bus.orders.name
}
