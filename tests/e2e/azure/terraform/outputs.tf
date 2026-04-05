output "app_urls" {
  description = "Public URLs for each test app"
  value = {
    for k, app in azurerm_container_app.apps :
    k => "https://${app.ingress[0].fqdn}"
  }
}
