# Apply this in each account the control plane changes. It creates the role the
# gate assumes for 900-second sessions. Attach only the permissions your IaC needs.
terraform {
  required_version = ">= 1.10.5, < 2.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "name" {
  type    = string
  default = "cctl-apply"
}

variable "control_plane_role_arn" {
  description = "service_role_arn output of the control-plane stack."
  type        = string
}

variable "external_id" {
  description = "Confused-deputy guard (not a secret). Put the same value in the gate config as credentials.params.external_id."
  type        = string
}

variable "policy_arns" {
  description = "Managed policies the role gets. Nothing is attached by default: choose least privilege for your IaC."
  type        = list(string)
}

variable "permissions_boundary_arn" {
  type    = string
  default = null
}

provider "aws" {
  region = var.region
}

data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRole", "sts:SetSourceIdentity", "sts:TagSession"]
    principals {
      type        = "AWS"
      identifiers = [var.control_plane_role_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.external_id]
    }
  }
}

resource "aws_iam_role" "apply" {
  name                 = var.name
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
  permissions_boundary = var.permissions_boundary_arn
}

resource "aws_iam_role_policy_attachment" "apply" {
  for_each   = toset(var.policy_arns)
  role       = aws_iam_role.apply.name
  policy_arn = each.value
}

output "role_arn" {
  value = aws_iam_role.apply.arn
}
