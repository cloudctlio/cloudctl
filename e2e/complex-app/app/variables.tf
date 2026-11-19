variable "region" {
  description = "AWS region for every resource."
  type        = string
  default     = "us-east-1"
}

variable "prefix" {
  description = "Name prefix for every resource."
  type        = string
  default     = "cctl-complexapp"
}

variable "worker_reserved_concurrency" {
  description = "Reserved concurrency for the order worker. -1 means no reservation (uses the account pool)."
  type        = number
  default     = -1
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the Lambda log groups."
  type        = number
  default     = 1
}
