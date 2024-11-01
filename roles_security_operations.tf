resource "azurerm_role_definition" "security_operations" {
  name        = "Security-Operations"
  description = "Security Administrator role with a horizontal view across the entire Azure estate and the Azure Key Vault purge policy."
  scope       = data.azurerm_subscription.current.id # Update with your actual scope ID

  permissions {
    actions = [
      "*/read",
      "*/register/action",
      "Microsoft.KeyVault/locations/deletedVaults/purge/action",
      "Microsoft.PolicyInsights/*",
      "Microsoft.Authorization/policyAssignments/*",
      "Microsoft.Authorization/policyDefinitions/*",
      "Microsoft.Authorization/policyExemptions/*",
      "Microsoft.Authorization/policySetDefinitions/*",
      "Microsoft.Insights/alertRules/*",
      "Microsoft.Resources/deployments/*",
      "Microsoft.Security/*",
      "Microsoft.Support/*"
    ]
    not_actions = []
  }

  assignable_scopes = [data.azurerm_subscription.current.id, ] # Update with your actual scope ID
}
