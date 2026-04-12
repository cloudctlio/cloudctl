variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "aws_profile" {
  type    = string
  default = "default"
}

variable "stack_name" {
  type    = string
  default = "cloudctl-complex-e2e"
}
