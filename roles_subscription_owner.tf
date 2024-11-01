resource "azurerm_role_definition" "subscription_owner" {
  name        = "Subscription-Owner"
  description = "Delegated role for subscription owner generated from subscription Owner role"
  scope       = data.azurerm_subscription.current.id # Update with your actual scope ID

  permissions {
    actions = [
      "*"
    ]
    not_actions = [
      "Microsoft.Authorization/*/write",
      "Microsoft.Network/vpnGateways/*",
      "Microsoft.Network/expressRouteCircuits/*",
      "Microsoft.Network/routeTables/write",
      "Microsoft.Network/vpnSites/*"
    ]
  }

  assignable_scopes = [data.azurerm_subscription.current.id, ] # Update with your actual scope ID
}
