resource "azurerm_role_definition" "application_owners" {
  name        = "Application-Owners"
  description = "Contributor role granted for application/operations team at resource group level"
  scope       = data.azurerm_subscription.current.id

  permissions {
    actions = [
      "*"
    ]
    not_actions = [
      "Microsoft.Authorization/*/write",
      "Microsoft.Network/publicIPAddresses/write",
      "Microsoft.Network/virtualNetworks/write",
      "Microsoft.KeyVault/locations/deletedVaults/purge/action"
    ]
  }

  assignable_scopes = [data.azurerm_subscription.current.id, ]
}
