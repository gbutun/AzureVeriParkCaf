resource "azurerm_role_definition" "network_subnet_contributor" {
  name        = "Network-Subnet-Contributor"
  description = "Enterprise-scale custom Role Definition. Grants full access to manage Virtual Network subnets, but no other network resources."
  scope       = "${current_scope_resource_id}" # Update with your actual scope ID

  permissions {
    actions = [
      "Microsoft.Authorization/*/read",
      "Microsoft.Insights/alertRules/*",
      "Microsoft.ResourceHealth/availabilityStatuses/read",
      "Microsoft.Resources/deployments/*",
      "Microsoft.Resources/subscriptions/resourceGroups/read",
      "Microsoft.Support/*",
      "Microsoft.Network/*/read",
      "Microsoft.Network/virtualNetworks/subnets/*"
    ]
    not_actions = []
  }

  assignable_scopes = ["${current_scope_resource_id}"] # Update with your actual scope ID
}
