variable "resource_group_name" {
  description = "Azure resource group name"
  type        = string
  default     = "cloudctl-debug-test"
}

variable "location" {
  description = "Azure region"
  type        = string
  default     = "eastus"
}

variable "container_registry" {
  description = "Container registry hostname (e.g. myregistry.azurecr.io)"
  type        = string
  # Build and push with:
  #   docker build -t <registry>/cloudctl-test-app:latest ../../shared/
  #   docker push <registry>/cloudctl-test-app:latest
}

# Credentials — set via env vars instead of hardcoding:
#   export ARM_CLIENT_ID=...
#   export ARM_CLIENT_SECRET=...
#   export ARM_TENANT_ID=...
#   export ARM_SUBSCRIPTION_ID=...
