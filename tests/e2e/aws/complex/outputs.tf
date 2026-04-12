output "api_gateway_url" {
  description = "API Gateway base URL"
  value       = aws_apigatewayv2_stage.default.invoke_url
}

output "alb_dns_name" {
  description = "ALB DNS name (scenario 1 — ECS/ALB unhealthy targets)"
  value       = aws_lb.main.dns_name
}

output "alb_url" {
  description = "ALB HTTP URL (scenario 1)"
  value       = "http://${aws_lb.main.dns_name}"
}

output "vpc_no_nat_url" {
  description = "Scenario 2 — Lambda VPC no NAT (returns 500/timeout)"
  value       = "${aws_apigatewayv2_stage.default.invoke_url}/vpc-no-nat"
}

output "throttle_url" {
  description = "Scenario 4 — Lambda throttle endpoint (concurrent hits → 429)"
  value       = "${aws_apigatewayv2_stage.default.invoke_url}/throttle"
}

output "rds_connect_url" {
  description = "Scenario 5 — Lambda → RDS SG mismatch (returns 500/timeout)"
  value       = "${aws_apigatewayv2_stage.default.invoke_url}/rds-connect"
}

output "sqs_main_queue_url" {
  description = "Scenario 3 — SQS main queue URL (send messages to trigger DLQ drain)"
  value       = aws_sqs_queue.main_queue.url
}

output "sqs_dlq_url" {
  description = "Scenario 3 — SQS DLQ URL"
  value       = aws_sqs_queue.dlq.url
}

output "rds_endpoint" {
  description = "RDS endpoint (scenario 5)"
  value       = aws_db_instance.main.address
}

output "ecs_cluster_name" {
  description = "ECS cluster name (scenario 1)"
  value       = aws_ecs_cluster.main.name
}
