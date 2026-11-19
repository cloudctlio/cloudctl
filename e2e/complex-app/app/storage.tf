# Orders table: one item per order, status moves PENDING -> PROCESSED.
resource "aws_dynamodb_table" "orders" {
  name         = "${var.prefix}-orders"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "order_id"

  attribute {
    name = "order_id"
    type = "S"
  }
}

# Receipts bucket: the worker writes receipts/<order_id>.json for orders that ask for one.
resource "aws_s3_bucket" "receipts" {
  bucket        = "${var.prefix}-receipts-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "receipts" {
  bucket                  = aws_s3_bucket.receipts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
