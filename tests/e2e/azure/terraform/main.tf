terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.85"
    }
  }
  required_version = ">= 1.5"
}

provider "azurerm" {
  features {}
  # Credentials come from env vars:
  #   ARM_CLIENT_ID       = var.client_id
  #   ARM_CLIENT_SECRET   = var.client_secret
  #   ARM_TENANT_ID       = var.tenant_id
  #   ARM_SUBSCRIPTION_ID = var.subscription_id
}

# ── Resource group ───────────────────────────────────────────────────────────

resource "azurerm_resource_group" "rg" {
  name     = var.resource_group_name
  location = var.location

  tags = {
    managed-by  = "terraform"     # picked up by cloudctl deployment detector
    project     = "cloudctl-debug-test"
    environment = "test"
  }
}

# ── Container App environment ────────────────────────────────────────────────

resource "azurerm_log_analytics_workspace" "law" {
  name                = "cloudctl-test-law"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 7

  tags = { managed-by = "terraform" }
}

resource "azurerm_container_app_environment" "env" {
  name                       = "cloudctl-test-env"
  location                   = azurerm_resource_group.rg.location
  resource_group_name        = azurerm_resource_group.rg.name
  log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id

  tags = { managed-by = "terraform" }
}

# ── 4 Container Apps — one per scenario ──────────────────────────────────────

locals {
  apps = {
    healthy      = { mode = "healthy",      cpu = 0.25, memory = "0.5Gi" }
    "error-5xx"  = { mode = "error-5xx",    cpu = 0.25, memory = "0.5Gi" }
    "error-4xx"  = { mode = "error-4xx",    cpu = 0.25, memory = "0.5Gi" }
    intermittent = { mode = "intermittent", cpu = 0.25, memory = "0.5Gi" }
  }
}

resource "azurerm_container_app" "apps" {
  for_each = local.apps

  name                         = "cloudctl-test-${each.key}"
  resource_group_name          = azurerm_resource_group.rg.name
  container_app_environment_id = azurerm_container_app_environment.env.id
  revision_mode                = "Single"

  tags = {
    managed-by = "terraform"
    app-mode   = each.value.mode
  }

  template {
    container {
      name   = "app"
      image  = "${var.container_registry}/cloudctl-test-app:latest"
      cpu    = each.value.cpu
      memory = each.value.memory

      env {
        name  = "APP_MODE"
        value = each.value.mode
      }
      env {
        name  = "APP_NAME"
        value = "cloudctl-test-${each.key}"
      }
    }

    min_replicas = 1
    max_replicas = 3
  }

  ingress {
    external_enabled = true
    target_port      = 8080
    transport        = "http"

    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }
}
