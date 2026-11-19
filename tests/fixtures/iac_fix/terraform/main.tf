terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_dynamodb_table" "orders" {
  name           = var.table_name
  billing_mode   = "PROVISIONED"
  read_capacity  = 5
  write_capacity = var.orders_wcu
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }
}

resource "aws_iam_role" "writer" {
  name = "orders-writer-role"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "lambda.amazonaws.com" } }]
  })
}

resource "aws_lambda_function" "writer" {
  function_name = "orders-writer"
  role          = aws_iam_role.writer.arn
  runtime       = "python3.12"
  handler       = "app.handler"
  filename      = "lambda.zip"

  environment {
    variables = {
      TABLE_NAME = "orders"
    }
  }
}
