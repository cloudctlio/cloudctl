terraform {
  required_version = ">= 1.10.5, < 2.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = merge({ "app" = "cctl-control-plane", "managed-by" = "terraform" }, var.tags)
  }
}
