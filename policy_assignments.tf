resource "azurerm_subscription_policy_assignment" "custom_policy_assignment1" {
  name                 = "Append-AppService-httpsonly-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy1.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}
resource "azurerm_subscription_policy_assignment" "custom_policy_assignment2" {
  name                 = "Append-AppService-latestTLS-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy2.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment3" {
  name                 = "Append-KV-SoftDelete-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy3.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment4" {
  name                 = "Append-Redis-disableNonSslPort-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy4.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}
resource "azurerm_subscription_policy_assignment" "custom_policy_assignment5" {
  name                 = "Append-Redis-sslEnforcement-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy5.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}
resource "azurerm_subscription_policy_assignment" "custom_policy_assignment6" {
  name                 = "Audit-AzureHybridBenefit-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy6.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}
resource "azurerm_subscription_policy_assignment" "custom_policy_assignment7" {
  name                 = "Audit-Disks-UnusedResourcesCostOptimization-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy7.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}
resource "azurerm_subscription_policy_assignment" "custom_policy_assignment8" {
  name                 = "Audit-MachineLearning-PrivateEndpointId-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy8.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}
resource "azurerm_subscription_policy_assignment" "custom_policy_assignment9" {
  name                 = "Audit-PrivateLinkDnsZones-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy9.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}
resource "azurerm_subscription_policy_assignment" "custom_policy_assignment10" {
  name                 = "Audit-Pip-UnusedResourcesCostOpt-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy10.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}
resource "azurerm_subscription_policy_assignment" "custom_policy_assignment11" {
  name                 = "Audit-ServerFarms-UnusedResourcesCostOptimization-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy11.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment12" {
  name                 = "DenyAction-ActivityLogs-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy12.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

# resource "azurerm_subscription_policy_assignment" "custom_policy_assignment13" {
#   name                 = "DenyAction-DeleteResources-assignment"
#  subscription_id      = data.azurerm_subscription.current.id
#   policy_definition_id = azurerm_policy_definition.custom_policy13.id

# }

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment14" {
  name                 = "DenyAction-DiagnosticLogs-assignment"
  subscription_id      = data.azurerm_subscription.current.id
  policy_definition_id = azurerm_policy_definition.custom_policy14.id
  enforce              = false
}


resource "azurerm_subscription_policy_assignment" "custom_policy_assignment15" {
  name                 = "Deny-AA-child-resources-assignment"
  subscription_id      = data.azurerm_subscription.current.id
  policy_definition_id = azurerm_policy_definition.custom_policy15.id
  enforce              = false
}


resource "azurerm_subscription_policy_assignment" "custom_policy_assignment16" {
  name                 = "Deny-APIM-TLS-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy16.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment17" {
  name                 = "Deny-AppGw-Without-Tls-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy17.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment18" {
  name                 = "Deny-AppGW-Without-WAF-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy18.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment19" {
  name                 = "Deny-AppServiceApiApp-http-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy19.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment20" {
  name                 = "Deny-AppServiceFunctionApp-http-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy20.id
  subscription_id      = data.azurerm_subscription.current.id
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment21" {
  name                 = "Deny-AppServiceWebApp-http-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy21.id
  subscription_id      = data.azurerm_subscription.current.id
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment22" {
  name                 = "Deny-AppService-without-BYOC-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy22.id
  subscription_id      = data.azurerm_subscription.current.id
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment23" {
  name                 = "Deny-AzFw-Without-Policy-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy23.id
  subscription_id      = data.azurerm_subscription.current.id
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment24" {
  name                 = "Deny-CognitiveServices-NetworkAcls-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy24.id
  subscription_id      = data.azurerm_subscription.current.id
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment25" {
  name                 = "Deny-CognitiveServices-Resource-Kinds-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy25.id
  subscription_id      = data.azurerm_subscription.current.id
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment26" {
  name                 = "Deny-CognitiveServices-RestrictOutboundNetworkAccess-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy26.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}
resource "azurerm_subscription_policy_assignment" "custom_policy_assignment27" {
  name                 = "Deny-Databricks-NoPublicIp-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy27.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment28" {
  name                 = "Deny-Databricks-Sku-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy28.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment29" {
  name                 = "Deny-Databricks-VirtualNetwork-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy29.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment30" {
  name                 = "Deny-EH-minTLS-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy30.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment31" {
  name                 = "Deny-EH-Premium-CMK-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy31.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}
resource "azurerm_subscription_policy_assignment" "custom_policy_assignment32" {
  name                 = "Deny-FileServices-InsecureAuth-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy32.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment33" {
  name                 = "Deny-FileServices-InsecureKerberos-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy33.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}
resource "azurerm_subscription_policy_assignment" "custom_policy_assignment34" {
  name                 = "Deny-FileServices-InsecureSmbChannel-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy34.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment35" {
  name                 = "Deny-FileServices-InsecureSmbVersions-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy35.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}
resource "azurerm_subscription_policy_assignment" "custom_policy_assignment36" {
  name                 = "Deny-LogicApps-Without-Https-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy36.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment37" {
  name                 = "Deny-LogicApp-Public-Network-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy37.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment38" {
  name                 = "Deny-MachineLearning-Aks-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy38.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment39" {
  name                 = "Deny-ML-ComputeCluster-RemoteLoginPortPubAcc-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy39.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment40" {
  name                 = "Deny-MachineLearning-ComputeCluster-Scale-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy40.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false

}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment41" {
  name                 = "Deny-MachineLearning-Compute-SubnetId-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy41.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false

}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment42" {
  name                 = "Deny-MachineLearning-Compute-VmSize-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy42.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false

}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment43" {
  name                 = "Deny-MachineLearning-HbiWorkspace-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy43.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment44" {
  name                 = "Deny-MachineLearning-PublicAccessWhenBehindVnet-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy44.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment45" {
  name                 = "Deny-MachineLearning-PublicNetworkAccess-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy45.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment46" {
  name                 = "Deny-MgmtPorts-From-Internet-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy46.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment47" {
  name                 = "Deny-MySql-http-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy47.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment48" {
  name                 = "Deny-PostgreSql-http-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy48.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}
resource "azurerm_subscription_policy_assignment" "custom_policy_assignment49" {
  name                 = "Deny-Private-DNS-Zones-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy49.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment50" {
  name                 = "Deny-PublicEndpoint-MariaDB-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy50.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment51" {
  name                 = "Deny-PublicIP-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy51.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment52" {
  name                 = "Deny-RDP-From-Internet-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy52.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment53" {
  name                 = "Deny-Redis-http-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy53.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment54" {
  name                 = "Deny-Service-Endpoints-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy54.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment55" {
  name                 = "Deny-SqlMi-minTLS-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy55.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment56" {
  name                 = "Deny-Sql-minTLS-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy56.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment57" {
  name                 = "Deny-StorageAccount-CustomDomain-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy57.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment58" {
  name                 = "Deny-Storage-ContainerDeleteRetentionPolicy-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy58.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment59" {
  name                 = "Deny-Storage-CopyScope-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy59.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment60" {
  name                 = "Deny-Storage-CorsRules-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy60.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment61" {
  name                 = "Deny-Storage-LocalUser-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy61.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment62" {
  name                 = "Deny-Storage-minTLS-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy62.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment63" {
  name                 = "Deny-Storage-NetworkAclsBypass-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy63.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment64" {
  name                 = "Deny-Storage-NetworkAclsVirtualNetworkRules-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy64.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment65" {
  name                 = "Deny-Storage-ResourceAccessRulesResourceId-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy65.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment66" {
  name                 = "Deny-Storage-ResourceAccessRulesTenantId-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy66.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment67" {
  name                 = "Deny-Storage-ServicesEncryption-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy67.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment68" {
  name                 = "Deny-Storage-SFTP-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy68.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment69" {
  name                 = "Deny-Subnet-Without-Nsg-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy69.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment70" {
  name                 = "Deny-Subnet-Without-Penp-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy70.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment71" {
  name                 = "Deny-Subnet-Without-Udr-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy71.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}
resource "azurerm_subscription_policy_assignment" "custom_policy_assignment72" {
  name                 = "Deny-UDR-With-Specific-NextHop-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy72.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}
resource "azurerm_subscription_policy_assignment" "custom_policy_assignment73" {
  name                 = "Deny-VNet-Peering-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy73.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}
resource "azurerm_subscription_policy_assignment" "custom_policy_assignment74" {
  name                 = "Deny-VNET-Peering-To-Non-Approved-VNETs-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy74.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}
resource "azurerm_subscription_policy_assignment" "custom_policy_assignment75" {
  name                 = "Deny-VNET-Peer-Cross-Sub-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy75.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment76" {
  name                 = "Deploy-ASC-SecurityContacts-assignment"
  subscription_id      = data.azurerm_subscription.current.id
  policy_definition_id = azurerm_policy_definition.custom_policy76.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "emailSecurityContact" = { "value" = "var.emailSecurityContact" }
  })
  identity {
    type = "SystemAssigned"
  }
}


resource "azurerm_subscription_policy_assignment" "custom_policy_assignment77" {
  name                 = "Deploy-Budget-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy77.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  identity {
    type = "SystemAssigned"
  }
}

# resource "azurerm_subscription_policy_assignment" "custom_policy_assignment78" {
#   name = "Deploy-Custom-Route-Table-assignment"
#   policy_definition_id = azurerm_policy_definition.custom_policy78.id
#   subscription_id      = data.azurerm_subscription.current.id
#   enforce = false
#   location = var.location
#   parameters = jsonencode({
#     "requiredRoutes" = "your-required-routes"
#     "routeTableName" = "your-route-table-name"
#     "vnetRegion" = var.location
#   })
#   identity {
#     type="SystemAssigned" 
#   }
# }

# resource "azurerm_subscription_policy_assignment" "custom_policy_assignment79" {
#   name = "Deploy-DDoSProtection-assignment"
#   policy_definition_id = azurerm_policy_definition.custom_policy79.id
#   subscription_id      = data.azurerm_subscription.current.id
#   enforce = false
#   location = var.location
#   identity {
#     type="SystemAssigned" 
#   }
# }

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment80" {
  name                 = "Deploy-Diagnostics-AA-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy80.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment81" {
  name                 = "Deploy-Diagnostics-ACI-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy81.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}


resource "azurerm_subscription_policy_assignment" "custom_policy_assignment82" {
  name                 = "Deploy-Diagnostics-ACR-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy82.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment83" {
  name                 = "Deploy-Diagnostics-AnalysisService-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy83.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment84" {
  name                 = "Deploy-Diagnostics-ApiForFHIR-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy84.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment85" {
  name                 = "Deploy-Diagnostics-APIMgmt-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy85.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment86" {
  name                 = "Deploy-Diagnostics-ApplicationGateway-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy86.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment87" {
  name                 = "Deploy-Diagnostics-AVDScalingPlans-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy87.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment88" {
  name                 = "Deploy-Diagnostics-Bastion-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy88.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment89" {
  name                 = "Deploy-Diagnostics-CDNEndpoints-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy89.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment90" {
  name                 = "Deploy-Diagnostics-CognitiveServices-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy90.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment91" {
  name                 = "Deploy-Diagnostics-CosmosDB-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy91.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment92" {
  name                 = "Deploy-Diagnostics-Databricks-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy92.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment93" {
  name                 = "Deploy-Diagnostics-DataExplorerCluster-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy93.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment94" {
  name                 = "Deploy-Diagnostics-DataFactory-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy94.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment95" {
  name                 = "Deploy-Diagnostics-DLAnalytics-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy95.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment96" {
  name                 = "Deploy-Diagnostics-EventGridSub-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy96.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment97" {
  name                 = "Deploy-Diagnostics-EventGridSystemTopic-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy97.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment98" {
  name                 = "Deploy-Diagnostics-EventGridTopic-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy98.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment99" {
  name                 = "Deploy-Diagnostics-ExpressRoute-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy99.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment100" {
  name                 = "Deploy-Diagnostics-Firewall-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy100.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment101" {
  name                 = "Deploy-Diagnostics-FrontDoor-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy101.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment102" {
  name                 = "Deploy-Diagnostics-Function-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy102.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment103" {
  name                 = "Deploy-Diagnostics-HDInsight-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy103.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment104" {
  name                 = "Deploy-Diagnostics-iotHub-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy104.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment105" {
  name                 = "Deploy-Diagnostics-LoadBalancer-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy105.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment106" {
  name                 = "Deploy-Diagnostics-LogAnalytics-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy106.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment107" {
  name                 = "Deploy-Diagnostics-LogicAppsISE-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy107.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment108" {
  name                 = "Deploy-Diagnostics-MariaDB-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy108.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment109" {
  name                 = "Deploy-Diagnostics-MediaService-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy109.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment110" {
  name                 = "Deploy-Diagnostics-MlWorkspace-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy110.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment111" {
  name                 = "Deploy-Diagnostics-MySQL-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy111.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment112" {
  name                 = "Deploy-Diagnostics-NetworkSecurityGroups-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy112.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment113" {
  name                 = "Deploy-Diagnostics-NIC-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy113.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment114" {
  name                 = "Deploy-Diagnostics-PostgreSQL-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy114.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment115" {
  name                 = "Deploy-Diagnostics-PowerBIEmbedded-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy115.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment116" {
  name                 = "Deploy-Diagnostics-RedisCache-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy116.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment117" {
  name                 = "Deploy-Diagnostics-Relay-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy117.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment118" {
  name                 = "Deploy-Diagnostics-SignalR-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy118.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment119" {
  name                 = "Deploy-Diagnostics-SQLElasticPools-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy119.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment120" {
  name                 = "Deploy-Diagnostics-SQLMI-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy120.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment121" {
  name                 = "Deploy-Diagnostics-TimeSeriesInsights-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy121.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment122" {
  name                 = "Deploy-Diagnostics-TrafficManager-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy122.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment123" {
  name                 = "Deploy-Diagnostics-VirtualNetwork-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy123.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment124" {
  name                 = "Deploy-Diagnostics-VM-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy124.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment125" {
  name                 = "Deploy-Diagnostics-VMSS-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy125.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment126" {
  name                 = "Deploy-Diagnostics-VNetGW-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy126.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment127" {
  name                 = "Deploy-Diagnostics-VWanS2SVPNGW-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy127.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment128" {
  name                 = "Deploy-Diagnostics-WebServerFarm-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy128.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment129" {
  name                 = "Deploy-Diagnostics-Website-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy129.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment130" {
  name                 = "Deploy-Diagnostics-WVDAppGroup-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy130.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment131" {
  name                 = "Deploy-Diagnostics-WVDHostPools-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy131.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment132" {
  name                 = "Deploy-Diagnostics-WVDWorkspace-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy132.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  })
  identity {
    type = "SystemAssigned"
  }
}

# resource "azurerm_subscription_policy_assignment" "custom_policy_assignment133" {
#   name                 = "Deploy-FirewallPolicy-assignment"
#   policy_definition_id = azurerm_policy_definition.custom_policy133.id
#   subscription_id      = data.azurerm_subscription.current.id
#   enforce              = false
#   location             = var.location
#   parameters = jsonencode({
#     "fwPolicyRegion"                   = { "value" = "fwPolicyRegion" },
#     "rgName"                 = { "value" = "rgName" }
#   })
#   identity {
#     type = "SystemAssigned"
#   }
# }

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment134" {
  name                 = "Deploy-LogicApp-TLS-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy134.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  identity {
    type = "SystemAssigned"
  }
}

# resource "azurerm_subscription_policy_assignment" "custom_policy_assignment135" {
#   name                 = "Deploy-MDFC-Arc-SQL-DCR-Association-assignment"
#   policy_definition_id = azurerm_policy_definition.custom_policy135.id
#   subscription_id      = data.azurerm_subscription.current.id
#   enforce              = false
#   location             = var.location
#   parameters = jsonencode({
#     "dcrId"                   = { "value" = "dcrId" },
#     "dcrName"                 = { "value" = "dcrName" },
#     "dcrResourceGroup"        = { "value" = "dcrResourceGroup" },
#     "workspaceRegion"         = { "value" = "workspaceRegion" }
#   })
#   identity {
#     type = "SystemAssigned"
#   }
# }

# resource "azurerm_subscription_policy_assignment" "custom_policy_assignment136" {
#   name                 = "Deploy-MDFC-Arc-Sql-DefenderSQL-DCR-assignment"
#   policy_definition_id = azurerm_policy_definition.custom_policy136.id
#   subscription_id      = data.azurerm_subscription.current.id
#   enforce              = false
#   location             = var.location
#   parameters = jsonencode({
#     "dcrId"                   = { "value" = "dcrId" },
#     "dcrName"                 = { "value" = "dcrName" },
#     "dcrResourceGroup"        = { "value" = "dcrResourceGroup" },
#     "workspaceRegion"         = { "value" = "workspaceRegion" }
#   })
#   identity {
#     type = "SystemAssigned"
#   }
# }

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment137" {
  name                 = "Deploy-MDFC-SQL-AMA-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy137.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  identity {
    type = "SystemAssigned"
  }
}

# resource "azurerm_subscription_policy_assignment" "custom_policy_assignment138" {
#   name                 = "Deploy-MDFC-SQL-DefenderSQL-assignment"
#   policy_definition_id = azurerm_policy_definition.custom_policy138.id
#   subscription_id      = data.azurerm_subscription.current.id
#   enforce              = false
#   location             = var.location
#   parameters = jsonencode({
#     "dcrId"                   = { "value" = "dcrId" },
#     "dcrName"                 = { "value" = "dcrName" },
#     "dcrResourceGroup"        = { "value" = "dcrResourceGroup" },
#     "workspaceRegion"         = { "value" = "workspaceRegion" }
#   })
#   identity {
#     type = "SystemAssigned"
#   }
# }

# resource "azurerm_subscription_policy_assignment" "custom_policy_assignment139" {
#   name                 = "Deploy-MDFC-SQL-DefenderSQL-DCR-assignment"
#   policy_definition_id = azurerm_policy_definition.custom_policy139.id
#   subscription_id      = data.azurerm_subscription.current.id
#   enforce              = false
#   location             = var.location
#   parameters = jsonencode({
#     "dcrId"                   = { "value" = "dcrId" },
#     "dcrName"                 = { "value" = "dcrName" },
#     "dcrResourceGroup"        = { "value" = "dcrResourceGroup" },
#     "userWorkspaceResourceId" = { "value" = "userWorkspaceResourceId" },
#     "workspaceRegion"         = { "value" = "workspaceRegion" }
#   })
#   identity {
#     type = "SystemAssigned"
#   }
# }

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment140" {
  name                 = "Deploy-MySQL-sslEnforcement-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy140.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment141" {
  name                 = "Deploy-Nsg-FlowLogs-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy141.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  parameters = jsonencode({
    "storageAccountResourceId" = { "value" = var.storageAccountResourceId_diag }
  })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment142" {
  name                 = "Deploy-Nsg-FlowLogs-to-LA-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy142.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  # parameters = jsonencode({
  #   "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  # })
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment143" {
  name                 = "Deploy-PostgreSQL-sslEnforcement-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy143.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  # parameters = jsonencode({
  #   "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
  # })
  identity {
    type = "SystemAssigned"
  }
}

# resource "azurerm_subscription_policy_assignment" "custom_policy_assignment144" {
#   name                 = "Deploy-Private-DNS-Generic-assignment"
#   policy_definition_id = azurerm_policy_definition.custom_policy144.id
#   subscription_id      = data.azurerm_subscription.current.id
#   enforce              = false
#   location             = var.location
#   parameters = jsonencode({
#     "groupId"          = { "value" = "groupId" },
#     "privateDnsZoneId" = { "value" = "privateDnsZoneId" },
#     "resourceType"     = { "value" = "resourceType" }
#   })
#   identity {
#     type = "SystemAssigned"
#   }
# }

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment145" {
  name                 = "Deploy-SqlMi-minTLS-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy145.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment146" {
  name                 = "Deploy-Sql-AuditingSettings-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy146.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment147" {
  name                 = "Deploy-SQL-minTLS-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy147.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment148" {
  name                 = "Deploy-Sql-SecurityAlertPolicies-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy148.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment149" {
  name                 = "Deploy-Sql-Tde-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy149.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  identity {
    type = "SystemAssigned"
  }
}

# resource "azurerm_subscription_policy_assignment" "custom_policy_assignment150" {
#   name                 = "Deploy-Sql-vulnerabilityAssessments-assignment"
#   policy_definition_id = azurerm_policy_definition.custom_policy150.id
#   subscription_id      = data.azurerm_subscription.current.id
#   enforce              = false
#   location             = var.location
#   parameters = jsonencode({
#     "vulnerabilityAssessmentsEmail"         = { "value" = "vulnerabilityAssessmentsEmail" },
#     "vulnerabilityAssessmentsStorageID"       = { "value" = "vulnerabilityAssessmentsStorageID" }
#   })
#   identity {
#     type = "SystemAssigned"
#   }
# }

# resource "azurerm_subscription_policy_assignment" "custom_policy_assignment151" {
#   name                 = "Deploy-Sql-vulnerabilityAssessments_20230706-assignment"
#   policy_definition_id = azurerm_policy_definition.custom_policy151.id
#   subscription_id      = data.azurerm_subscription.current.id
#   enforce              = false
#   location             = var.location
#   parameters = jsonencode({
#     "vulnerabilityAssessmentsEmail"     = { "value" = "vulnerabilityAssessmentsEmail" },
#     "vulnerabilityAssessmentsStorageID" = { "value" = "vulnerabilityAssessmentsStorageID" }
#   })
#   identity {
#     type = "SystemAssigned"
#   }
# }

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment152" {
  name                 = "Deploy-Storage-sslEnforcement-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy152.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  identity {
    type = "SystemAssigned"
  }
}

# resource "azurerm_subscription_policy_assignment" "custom_policy_assignment153" {
#   name                 = "Deploy-UserAssignedManagedIdentity-VMInsights-assignment"
#   policy_definition_id = azurerm_policy_definition.custom_policy153.id
#   subscription_id      = data.azurerm_subscription.current.id
#   enforce              = false
#   location             = var.location
#   parameters = jsonencode({
#     "bringYourOwnUserAssignedManagedIdentity" = { "value" = "bringYourOwnUserAssignedManagedIdentity" }
#   })
#   identity {
#     type = "SystemAssigned"
#   }
# }

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment154" {
  name                 = "Deploy-Vm-autoShutdown-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy154.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  identity {
    type = "SystemAssigned"
  }
}

# resource "azurerm_subscription_policy_assignment" "custom_policy_assignment155" {
#   name                 = "Deploy-VNET-HubSpoke-assignment"
#   policy_definition_id = azurerm_policy_definition.custom_policy155.id
#   subscription_id      = data.azurerm_subscription.current.id
#   enforce              = false
#   location             = var.location
#   parameters = jsonencode({
#     "hubResourceId"         = { "value" = "hubResourceId" },
#     "vNetCidrRange"       = { "value" = "vNetCidrRange" },
#     "vNetLocation"     = { "value" = "vNetLocation" },
#     "vNetName"     = { "value" = "vNetName" },
#     "vNetRgName" = { "value" = "vNetRgName" }
#   })
#   identity {
#     type = "SystemAssigned"
#   }
# }

# resource "azurerm_subscription_policy_assignment" "custom_policy_assignment156" {
#   name                 = "Deploy-Windows-DomainJoin-assignment"
#   policy_definition_id = azurerm_policy_definition.custom_policy156.id
#   subscription_id      = data.azurerm_subscription.current.id
#   enforce              = false
#   location             = var.location
#   parameters = jsonencode({
#     "domainFQDN"         = { "value" = "domainFQDN" },
#     "domainOUPath"       = { "value" = "domainOUPath" },
#     "domainPassword"     = { "value" = "domainPassword" },
#     "domainUsername"     = { "value" = "domainUsername" },
#     "keyVaultResourceId" = { "value" = "keyVaultResourceId" }
#   })
#   identity {
#     type = "SystemAssigned"
#   }
# }

resource "azurerm_subscription_policy_assignment" "custom_policy_assignment157" {
  name                 = "Modify-NSG-assignment"
  policy_definition_id = azurerm_policy_definition.custom_policy157.id
  subscription_id      = data.azurerm_subscription.current.id
  enforce              = false
  location             = var.location
  identity {
    type = "SystemAssigned"
  }
}

# resource "azurerm_subscription_policy_assignment" "custom_policy_assignment158" {
#   name = "Modify-UDR-assignment"
#   policy_definition_id = azurerm_policy_definition.custom_policy158.id
#   subscription_id      = data.azurerm_subscription.current.id
#   enforce              = false
#   location             = var.location
#   parameters = jsonencode({
#     "logAnalytics" = { "value" = var.logAnalytics_diagnostics }
#   })
#   identity {
#     type = "SystemAssigned"
#   }
# }
