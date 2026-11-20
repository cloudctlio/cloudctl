data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account = data.aws_caller_identity.current.account_id
  part    = data.aws_partition.current.partition
}

# ── encryption ───────────────────────────────────────────────────────────────
resource "aws_kms_key" "cp" {
  description             = "${var.name}: state table, audit bucket, images"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "cp" {
  name          = "alias/${var.name}"
  target_key_id = aws_kms_key.cp.key_id
}

# ── shared state: runs, approvals, drift events, rollbacks, leases ───────────
resource "aws_dynamodb_table" "state" {
  name                        = var.name
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "ns"
  range_key                   = "k"
  deletion_protection_enabled = true

  attribute {
    name = "ns"
    type = "S"
  }
  attribute {
    name = "k"
    type = "S"
  }
  ttl {
    attribute_name = "ttl" # only leases carry it
    enabled        = true
  }
  point_in_time_recovery {
    enabled = true
  }
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.cp.arn
  }
}

# ── immutable audit: hash-chained records under Object Lock COMPLIANCE ───────
resource "aws_s3_bucket" "audit" {
  bucket              = "${var.name}-audit-${local.account}"
  object_lock_enabled = true
}

resource "aws_s3_bucket_ownership_controls" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.audit_retain_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.audit]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cp.arn
    }
    bucket_key_enabled = true
  }
}

data "aws_iam_policy_document" "audit_bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.audit.arn, "${aws_s3_bucket.audit.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
  statement {
    sid       = "DenyRetentionBypass"
    effect    = "Deny"
    actions   = ["s3:BypassGovernanceRetention", "s3:PutBucketObjectLockConfiguration"]
    resources = [aws_s3_bucket.audit.arn, "${aws_s3_bucket.audit.arn}/*"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.service.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "audit" {
  bucket     = aws_s3_bucket.audit.id
  policy     = data.aws_iam_policy_document.audit_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.audit]
}

# ── the service's own identity (IRSA) ────────────────────────────────────────
data "aws_iam_policy_document" "irsa_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.eks_oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.eks_oidc_issuer}:sub"
      values   = ["system:serviceaccount:${var.k8s_namespace}:${var.k8s_service_account}"]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.eks_oidc_issuer}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "service" {
  name                 = "${var.name}-service"
  assume_role_policy   = data.aws_iam_policy_document.irsa_trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "service" {
  statement {
    sid = "State"
    actions = [
      "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:Query",
      "dynamodb:DescribeTable", "dynamodb:DescribeTimeToLive",
    ]
    resources = [aws_dynamodb_table.state.arn]
  }
  statement {
    sid       = "AuditWrite" # no DeleteObject*, no retention changes
    actions   = ["s3:PutObject", "s3:GetObject", "s3:PutObjectRetention", "s3:GetObjectRetention"]
    resources = ["${aws_s3_bucket.audit.arn}/*"]
  }
  statement {
    sid       = "AuditList"
    actions   = ["s3:ListBucket", "s3:GetBucketObjectLockConfiguration", "s3:GetBucketVersioning"]
    resources = [aws_s3_bucket.audit.arn]
  }
  statement {
    sid       = "Kms"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [aws_kms_key.cp.arn]
  }
  dynamic "statement" {
    for_each = length(var.target_role_arns) > 0 ? [1] : []
    content {
      sid       = "AssumeTargetRoles" # 900-second sessions, SourceIdentity = the requester
      actions   = ["sts:AssumeRole", "sts:SetSourceIdentity", "sts:TagSession"]
      resources = var.target_role_arns
    }
  }
  dynamic "statement" {
    for_each = length(var.bedrock_model_arns) > 0 ? [1] : []
    content {
      sid       = "Model"
      actions   = ["bedrock:InvokeModel"] # Converse is authorised by InvokeModel
      resources = var.bedrock_model_arns
    }
  }
}

resource "aws_iam_role_policy" "service" {
  name   = "control-plane"
  role   = aws_iam_role.service.id
  policy = data.aws_iam_policy_document.service.json
}

# ── image registry ───────────────────────────────────────────────────────────
resource "aws_ecr_repository" "image" {
  name                 = var.name
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.cp.arn
  }
}

# ── CI: GitHub Actions through OIDC, no stored keys ──────────────────────────
resource "aws_iam_openid_connect_provider" "github" {
  count          = var.create_github_oidc_provider ? 1 : 0
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_openid_connect_provider" "github" {
  count = var.create_github_oidc_provider ? 0 : 1
  url   = "https://token.actions.githubusercontent.com"
}

locals {
  github_oidc_arn = var.create_github_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : data.aws_iam_openid_connect_provider.github[0].arn
}

data "aws_iam_policy_document" "ci_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [local.github_oidc_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition { # only the protected environment of this repository
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repository}:environment:${var.github_environment}"]
    }
  }
}

resource "aws_iam_role" "ci" {
  name                 = "${var.name}-ci"
  assume_role_policy   = data.aws_iam_policy_document.ci_trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "ci" {
  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    actions = [
      "ecr:BatchCheckLayerAvailability", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload", "ecr:PutImage", "ecr:BatchGetImage", "ecr:DescribeImages",
    ]
    resources = [aws_ecr_repository.image.arn]
  }
  statement {
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [aws_kms_key.cp.arn]
  }
  statement {
    actions   = ["eks:DescribeCluster"]
    resources = [var.eks_cluster_arn]
  }
}

resource "aws_iam_role_policy" "ci" {
  name   = "build-and-deploy"
  role   = aws_iam_role.ci.id
  policy = data.aws_iam_policy_document.ci.json
}
