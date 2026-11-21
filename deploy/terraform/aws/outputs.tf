output "service_role_arn" {
  description = "Put in values-eks.yaml as eks.amazonaws.com/role-arn."
  value       = aws_iam_role.service.arn
}

output "state_table" {
  value = aws_dynamodb_table.state.name
}

output "audit_bucket" {
  description = "audit.sink.bucket in the gate config (type: s3)."
  value       = aws_s3_bucket.audit.bucket
}

output "kms_key_arn" {
  description = "audit.sink.kms_key_id in the gate config."
  value       = aws_kms_key.cp.arn
}

output "ecr_repository_url" {
  value = aws_ecr_repository.image.repository_url
}

output "ci_role_arn" {
  description = "Set as the AWS_CI_ROLE_ARN variable on the GitHub environment."
  value       = aws_iam_role.ci.arn
}
