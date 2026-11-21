# cctl control plane on AKS: Cosmos DB state, immutable audit blobs, workload identity.
terraform {
  required_version = ">= 1.10.5, < 2.0.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.14"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

variable "subscription_id" { type = string }
variable "location" {
  type    = string
  default = "eastus"
}
variable "name" {
  description = "Prefix; letters and digits only (storage account names allow nothing else)."
  type        = string
  default     = "cctlcp"
  validation {
    condition     = can(regex("^[a-z0-9]{3,16}$", var.name))
    error_message = "3-16 lower-case letters or digits."
  }
}
variable "aks_oidc_issuer_url" {
  description = "AKS OIDC issuer URL (az aks show --query oidcIssuerProfile.issuerUrl)."
  type        = string
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
  description = "Lock the account-level immutability policy. Irreversible: the retention can then only grow. Leave false for a trial, true for production."
  type        = bool
  default     = false
}
variable "github_repository" {
  type    = string
  default = "cloudctlio/cloudctl"
}
variable "github_environment" {
  type    = string
  default = "production"
}

resource "azurerm_resource_group" "cp" {
  name     = "${var.name}-rg"
  location = var.location
}

# ── shared state ─────────────────────────────────────────────────────────────
resource "azurerm_cosmosdb_account" "state" {
  name                          = "${var.name}-state"
  location                      = azurerm_resource_group.cp.location
  resource_group_name           = azurerm_resource_group.cp.name
  offer_type                    = "Standard"
  kind                          = "GlobalDocumentDB"
  local_authentication_disabled = true # Entra ID only, no account keys
  public_network_access_enabled = true # narrow with private endpoints in your network design
  minimal_tls_version           = "Tls12"
  capabilities {
    name = "EnableServerless"
  }
  consistency_policy {
    consistency_level = "Strong" # conditional writes and single-use approvals need it
  }
  geo_location {
    location          = azurerm_resource_group.cp.location
    failover_priority = 0
  }
  backup {
    type = "Continuous"
    tier = "Continuous30Days"
  }
}

resource "azurerm_cosmosdb_sql_database" "state" {
  name                = "cctl"
  resource_group_name = azurerm_resource_group.cp.name
  account_name        = azurerm_cosmosdb_account.state.name
}

resource "azurerm_cosmosdb_sql_container" "state" {
  name                = "state"
  resource_group_name = azurerm_resource_group.cp.name
  account_name        = azurerm_cosmosdb_account.state.name
  database_name       = azurerm_cosmosdb_sql_database.state.name
  partition_key_paths = ["/ns"]
  default_ttl         = -1 # on, but only leases set a ttl
}

# ── immutable audit ──────────────────────────────────────────────────────────
resource "azurerm_storage_account" "audit" {
  name                            = "${var.name}audit"
  resource_group_name             = azurerm_resource_group.cp.name
  location                        = azurerm_resource_group.cp.location
  account_tier                    = "Standard"
  account_replication_type        = "GZRS"
  min_tls_version                 = "TLS1_2"
  shared_access_key_enabled       = false
  allow_nested_items_to_be_public = false
  https_traffic_only_enabled      = true
  blob_properties {
    versioning_enabled = true
  }
  immutability_policy {
    allow_protected_append_writes = false
    state                         = var.lock_audit_policy ? "Locked" : "Unlocked"
    period_since_creation_in_days = var.audit_retain_days
  }
}

resource "azurerm_storage_container" "audit" {
  name                  = "cctl-audit"
  storage_account_id    = azurerm_storage_account.audit.id
  container_access_type = "private"
}

# ── workload identity ────────────────────────────────────────────────────────
resource "azurerm_user_assigned_identity" "service" {
  name                = "${var.name}-service"
  resource_group_name = azurerm_resource_group.cp.name
  location            = azurerm_resource_group.cp.location
}

resource "azurerm_federated_identity_credential" "service" {
  name                = "aks-${var.k8s_namespace}-${var.k8s_service_account}"
  resource_group_name = azurerm_resource_group.cp.name
  parent_id           = azurerm_user_assigned_identity.service.id
  issuer              = var.aks_oidc_issuer_url
  subject             = "system:serviceaccount:${var.k8s_namespace}:${var.k8s_service_account}"
  audience            = ["api://AzureADTokenExchange"]
}

data "azurerm_cosmosdb_sql_role_definition" "contributor" {
  resource_group_name = azurerm_resource_group.cp.name
  account_name        = azurerm_cosmosdb_account.state.name
  role_definition_id  = "00000000-0000-0000-0000-000000000002" # Cosmos DB Built-in Data Contributor
}

resource "azurerm_cosmosdb_sql_role_assignment" "service" {
  resource_group_name = azurerm_resource_group.cp.name
  account_name        = azurerm_cosmosdb_account.state.name
  role_definition_id  = data.azurerm_cosmosdb_sql_role_definition.contributor.id
  principal_id        = azurerm_user_assigned_identity.service.principal_id
  scope               = "${azurerm_cosmosdb_account.state.id}/dbs/${azurerm_cosmosdb_sql_database.state.name}/colls/${azurerm_cosmosdb_sql_container.state.name}"
}

# Owner, scoped to this one container: setting a per-blob immutability policy on upload
# needs blobs/* data actions that Data Contributor lacks. Immutability still stops deletes.
resource "azurerm_role_assignment" "audit" {
  scope                = azurerm_storage_container.audit.id # the ARM id when storage_account_id is used
  role_definition_name = "Storage Blob Data Owner"
  principal_id         = azurerm_user_assigned_identity.service.principal_id
}

# The gate's Azure credential broker gets per-operation tokens for target
# subscriptions; grant this identity the roles your IaC needs on them separately.

# ── CI: GitHub Actions through OIDC ──────────────────────────────────────────
resource "azurerm_user_assigned_identity" "ci" {
  name                = "${var.name}-ci"
  resource_group_name = azurerm_resource_group.cp.name
  location            = azurerm_resource_group.cp.location
}

resource "azurerm_federated_identity_credential" "ci" {
  name                = "github-${var.github_environment}"
  resource_group_name = azurerm_resource_group.cp.name
  parent_id           = azurerm_user_assigned_identity.ci.id
  issuer              = "https://token.actions.githubusercontent.com"
  subject             = "repo:${var.github_repository}:environment:${var.github_environment}"
  audience            = ["api://AzureADTokenExchange"]
}

output "service_identity_client_id" { value = azurerm_user_assigned_identity.service.client_id }
output "cosmos_endpoint" { value = azurerm_cosmosdb_account.state.endpoint }
output "audit_account_url" { value = azurerm_storage_account.audit.primary_blob_endpoint }
output "ci_identity_client_id" {
  description = "AZURE_CLIENT_ID on the GitHub environment; grant it AcrPush and AKS access separately."
  value       = azurerm_user_assigned_identity.ci.client_id
}
