resource "azurerm_role_definition" "network_management" {
  name        = "Network-Management"
  description = "Platform-wide global connectivity management: virtual networks, UDRs, NSGs, NVAs, VPN, Azure ExpressRoute, and others"
  scope       = data.azurerm_subscription.current.id # Update with your actual scope ID

  permissions {
    actions = [
      "*/read",
      "Microsoft.Network/*",
      "Microsoft.Resources/deployments/*",
      "Microsoft.Support/*"
    ]
    not_actions = []
  }

  assignable_scopes = [data.azurerm_subscription.current.id, ] # Update with your actual scope ID
}
