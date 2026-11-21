# cctl control plane on GKE: Firestore state, locked GCS audit bucket, workload identity.
terraform {
  required_version = ">= 1.10.5, < 2.0.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.14"
    }
  }
}

provider "google" {
  project = var.project
  region  = var.region
}

variable "project" { type = string }
variable "region" {
  type    = string
  default = "us-central1"
}
variable "name" {
  type    = string
  default = "cctl-control-plane"
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
  type    = number
  default = 400
}
variable "lock_audit_policy" {
  description = "Lock the bucket retention policy. Irreversible. false for a trial, true for production."
  type        = bool
  default     = false
}
variable "firestore_prefix" {
  type    = string
  default = "cctl"
}
variable "github_repository" {
  type    = string
  default = "cloudctlio/cloudctl"
}
variable "github_environment" {
  type    = string
  default = "production"
}

data "google_project" "this" {}

# ── shared state ─────────────────────────────────────────────────────────────
resource "google_firestore_database" "state" {
  name                              = "(default)"
  location_id                       = var.region
  type                              = "FIRESTORE_NATIVE"
  concurrency_mode                  = "PESSIMISTIC"
  point_in_time_recovery_enablement = "POINT_IN_TIME_RECOVERY_ENABLED"
  delete_protection_state           = "DELETE_PROTECTION_ENABLED"
  deletion_policy                   = "ABANDON"
}

resource "google_firestore_field" "lease_ttl" {
  database   = google_firestore_database.state.name
  collection = "${var.firestore_prefix}_lease"
  field      = "expire_at"
  ttl_config {}
  index_config {}
}

# ── immutable audit ──────────────────────────────────────────────────────────
resource "google_storage_bucket" "audit" {
  name                        = "${var.name}-audit-${data.google_project.this.number}"
  location                    = upper(var.region)
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false
  retention_policy {
    retention_period = var.audit_retain_days * 86400
    is_locked        = var.lock_audit_policy
  }
}

# ── workload identity ────────────────────────────────────────────────────────
resource "google_service_account" "service" {
  account_id   = "cctl-control-plane"
  display_name = "cctl control plane"
}

resource "google_service_account_iam_member" "wi" {
  service_account_id = google_service_account.service.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project}.svc.id.goog[${var.k8s_namespace}/${var.k8s_service_account}]"
}

resource "google_project_iam_member" "firestore" {
  project = var.project
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.service.email}"
}

resource "google_storage_bucket_iam_member" "audit" {
  bucket = google_storage_bucket.audit.name
  role   = "roles/storage.objectCreator" # create only; the retention lock blocks deletes
  member = "serviceAccount:${google_service_account.service.email}"
}

resource "google_storage_bucket_iam_member" "audit_read" {
  bucket = google_storage_bucket.audit.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.service.email}"
}

# The gate's GCP broker impersonates per-environment service accounts; grant
# roles/iam.serviceAccountTokenCreator on each of them to this account separately.

# ── CI: GitHub Actions through workload identity federation ──────────────────
resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = "github"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github"
  attribute_mapping = {
    "google.subject"        = "assertion.sub"
    "attribute.repository"  = "assertion.repository"
    "attribute.environment" = "assertion.environment"
  }
  attribute_condition = "assertion.repository == '${var.github_repository}' && assertion.environment == '${var.github_environment}'"
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account" "ci" {
  account_id   = "cctl-control-plane-ci"
  display_name = "cctl control plane CI"
}

resource "google_service_account_iam_member" "ci" {
  service_account_id = google_service_account.ci.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principal://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/subject/repo:${var.github_repository}:environment:${var.github_environment}"
}

output "service_account_email" { value = google_service_account.service.email }
output "audit_bucket" { value = google_storage_bucket.audit.name }
output "ci_service_account" {
  description = "Grant it Artifact Registry writer and GKE deploy access separately."
  value       = google_service_account.ci.email
}
output "workload_identity_provider" { value = google_iam_workload_identity_pool_provider.github.name }
