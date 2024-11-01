resource "azurerm_resource_group" "example" {
  name     = var.resource_group
  location = var.location
}
data "azurerm_subscription" "current" {}

