resource "azurerm_role_definition" "application_owners" {
  name        = "Application-Owners"
  description = "Contributor role granted for application/operations team at resource group level"
  scope       = "${current_scope_resource_id}" # Update with your actual scope ID

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

  assignable_scopes = ["${current_scope_resource_id}"] # Update with your actual scope ID
}
