variable "region" {
  type    = string
  default = "us-east-1"
}

variable "name" {
  description = "Prefix for every resource name."
  type        = string
  default     = "cctl-control-plane"
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "eks_oidc_provider_arn" {
  description = "ARN of the EKS cluster's IAM OIDC provider (for IRSA)."
  type        = string
}

variable "eks_oidc_issuer" {
  description = "EKS OIDC issuer host and path, without https:// (oidc.eks.<region>.amazonaws.com/id/<id>)."
  type        = string
  validation {
    condition     = !startswith(var.eks_oidc_issuer, "https://")
    error_message = "Give the issuer without https://."
  }
}

variable "k8s_namespace" {
  type    = string
  default = "cctl"
}

variable "k8s_service_account" {
  type    = string
  default = "cctl-control-plane"
}

variable "audit_retain_days" {
  description = "S3 Object Lock COMPLIANCE retention. Nobody, root included, can shorten it once objects are written."
  type        = number
  default     = 400
  validation {
    condition     = var.audit_retain_days >= 1
    error_message = "Retention must be at least one day."
  }
}

variable "target_role_arns" {
  description = "Roles (often in other accounts) the control plane may assume for plan/apply. Created by the target-role module in each account."
  type        = list(string)
  default     = []
}

variable "bedrock_model_arns" {
  description = "Bedrock model or inference-profile ARNs the compiler may call. Empty = no model access."
  type        = list(string)
  default     = []
}

variable "github_repository" {
  description = "owner/repo allowed to build and deploy through GitHub OIDC."
  type        = string
  default     = "cloudctlio/cloudctl"
}

variable "github_environment" {
  description = "GitHub environment name the deploy job runs in (protect it with required reviewers)."
  type        = string
  default     = "production"
}

variable "create_github_oidc_provider" {
  description = "false if the account already has token.actions.githubusercontent.com."
  type        = bool
  default     = true
}

variable "eks_cluster_arn" {
  description = "Cluster the CI role may describe (it deploys with helm via an EKS access entry you grant separately)."
  type        = string
}

variable "deletion_protection" {
  description = "DynamoDB deletion protection. Keep true in production; false for a trial you will destroy."
  type        = bool
  default     = true
}

variable "kms_deletion_window_days" {
  description = "Days a destroyed KMS key waits before AWS deletes it (7 to 30). It can be cancelled during that time."
  type        = number
  default     = 30
  validation {
    condition     = var.kms_deletion_window_days >= 7 && var.kms_deletion_window_days <= 30
    error_message = "7 to 30 days."
  }
}
