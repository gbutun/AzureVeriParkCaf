resource "azurerm_policy_definition" "custom_policy1" {
  name         = "Append-AppService-httpsonly"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "AppService append enable https only setting to enforce https setting."
  description  = "Appends the AppService sites object to ensure that  HTTPS only is enabled for  server/service authentication and protects data in transit from network layer eavesdropping attacks. Please note Append does not enforce compliance use then deny."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "App Service", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_append_appservice_httpsonly_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_append_appservice_httpsonly_policy_paramater.json")
}

resource "azurerm_policy_definition" "custom_policy2" {
  name         = "Append-AppService-latestTLS"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "AppService append sites with minimum TLS version to enforce."
  description  = "Append the AppService sites object to ensure that min Tls version is set to required minimum TLS version. Please note Append does not enforce compliance use then deny."
  metadata     = jsonencode({ "version" : "1.1.0", "category" : "App Service", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_append_appservice_latesttls_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_append_appservice_latesttls_policy_paramater.json")
}

resource "azurerm_policy_definition" "custom_policy3" {
  name         = "Append-KV-SoftDelete"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "KeyVault SoftDelete should be enabled"
  description  = "This policy enables you to ensure when a Key Vault is created with out soft delete enabled it will be added."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Key Vault", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_append_kv_softdelete_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_append_kv_softdelete_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy4" {
  name         = "Append-Redis-disableNonSslPort"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Azure Cache for Redis Append and the enforcement that enableNonSslPort is disabled."
  description  = "Azure Cache for Redis Append and the enforcement that enableNonSslPort is disabled. Enables secure server to client by enforce  minimal Tls Version to secure the connection between your database server and your client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and your application. This configuration enforces that SSL is always enabled for accessing your database server."
  metadata     = jsonencode({ "version" : "1.0.1", "category" : "Cache", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_append_redis_disablenonsslport_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_append_redis_disablenonsslport_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy5" {
  name         = "Append-Redis-sslEnforcement"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Azure Cache for Redis Append a specific min TLS version requirement and enforce TLS."
  description  = "Append a specific min TLS version requirement and enforce SSL on Azure Cache for Redis. Enables secure server to client by enforce  minimal Tls Version to secure the connection between your database server and your client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and your application. This configuration enforces that SSL is always enabled for accessing your database server."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Cache", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_append_redis_sslenforcement_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_append_redis_sslenforcement_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy6" {
  name         = "Audit-AzureHybridBenefit"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Audit AHUB for eligible VMs"
  description  = "Optimize cost by enabling Azure Hybrid Benefit. Leverage this Policy definition as a cost control to reveal Virtual Machines not using AHUB."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Cost Optimization", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_audit_azurehybridbenefit_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_audit_azurehybridbenefit_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy7" {
  name         = "Audit-Disks-UnusedResourcesCostOptimization"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Unused Disks driving cost should be avoided"
  description  = "Optimize cost by detecting unused but chargeable resources. Leverage this Policy definition as a cost control to reveal orphaned Disks that are driving cost."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Cost Optimization", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_audit_disks_unusedresourcescostoptimization_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_audit_disks_unusedresourcescostoptimization_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy8" {
  name         = "Audit-MachineLearning-PrivateEndpointId"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Control private endpoint connections to Azure Machine Learning"
  description  = "Audit private endpoints that are created in other subscriptions and/or tenants for Azure Machine Learning."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Machine Learning", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud"] })
  policy_rule  = file("./lib/definitions/Policy_audit_machinelearning_privateendpointid_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_audit_machinelearning_privateendpointid_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy9" {
  name         = "Audit-PrivateLinkDnsZones"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Audit or Deny the creation of Private Link Private DNS Zones"
  description  = "This policy audits or denies, depending on assignment effect, the creation of a Private Link Private DNS Zones in the current scope, used in combination with policies that create centralized private DNS in connectivity subscription"
  metadata     = jsonencode({ "version" : "1.0.2", "category" : "Network", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_audit_privatelinkdnszones_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_audit_privatelinkdnszones_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy10" {
  name         = "Audit-PublicIpAddresses-UnusedResourcesCostOptimization"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Unused Public IP addresses driving cost should be avoided"
  description  = "Optimize cost by detecting unused but chargeable resources. Leverage this Policy definition as a cost control to reveal orphaned Public IP addresses that are driving cost."
  metadata     = jsonencode({ "version" : "1.1.0", "category" : "Cost Optimization", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_audit_publicipaddresses_unusedresourcescostoptimization_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_audit_publicipaddresses_unusedresourcescostoptimization_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy11" {
  name         = "Audit-ServerFarms-UnusedResourcesCostOptimization"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Unused App Service plans driving cost should be avoided"
  description  = "Optimize cost by detecting unused but chargeable resources. Leverage this Policy definition as a cost control to reveal orphaned App Service plans that are driving cost."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Cost Optimization", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_audit_serverfarms_unusedresourcescostoptimization_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_audit_serverfarms_unusedresourcescostoptimization_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy12" {
  name         = "DenyAction-ActivityLogs"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "DenyAction implementation on Activity Logs"
  description  = "This is a DenyAction implementation policy on Activity Logs."
  metadata     = jsonencode({ "deprecated" : false, "version" : "1.0.0", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_denyaction_activitylogs_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_denyaction_activitylogs_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy13" {
  name         = "DenyAction-DeleteResources"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Do not allow deletion of specified resource and resource type"
  description  = "This policy enables you to specify the resource and resource type that your organization can protect from accidentals deletion by blocking delete calls using the deny action effect."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "General", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_denyaction_deleteresources_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_denyaction_deleteresources_policy_paramater.json")
}

resource "azurerm_policy_definition" "custom_policy14" {
  name         = "DenyAction-DiagnosticLogs"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "DenyAction implementation on Diagnostic Logs."
  description  = "DenyAction implementation on Diagnostic Logs."
  metadata     = jsonencode({ "deprecated" : false, "version" : "1.0.0", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_denyaction_diagnosticlogs_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_denyaction_diagnosticlogs_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy15" {
  name         = "Deny-AA-child-resources"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "No child resources in Automation Account"
  description  = "This policy denies the creation of child resources on the Automation Account"
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Automation", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_aa_child_resources_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_aa_child_resources_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy16" {
  name         = "Deny-APIM-TLS"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "API Management services should use TLS version 1.2"
  description  = "Azure API Management service should use TLS version 1.2"
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "API Management", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_apim_tls_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_apim_tls_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy17" {
  name         = "Deny-AppGw-Without-Tls"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Application Gateway should be deployed with predefined Microsoft policy that is using TLS version 1.2"
  description  = "This policy enables you to restrict that Application Gateways is always deployed with predefined Microsoft policy that is using TLS version 1.2"
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Network", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_appgw_without_tls_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_appgw_without_tls_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy18" {
  name         = "Deny-AppGW-Without-WAF"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Application Gateway should be deployed with WAF enabled"
  description  = "This policy enables you to restrict that Application Gateways is always deployed with WAF enabled"
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Network", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_appgw_without_waf_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_appgw_without_waf_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy19" {
  name         = "Deny-AppServiceApiApp-http"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "API App should only be accessible over HTTPS"
  description  = "Use of HTTPS ensures server/service authentication and protects data in transit from network layer eavesdropping attacks."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "App Service", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_appserviceapiapp_http_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_appserviceapiapp_http_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy20" {
  name         = "Deny-AppServiceFunctionApp-http"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Function App should only be accessible over HTTPS"
  description  = "Use of HTTPS ensures server/service authentication and protects data in transit from network layer eavesdropping attacks."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "App Service", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_appservicefunctionapp_http_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_appservicefunctionapp_http_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy21" {
  name         = "Deny-AppServiceWebApp-http"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Web Application should only be accessible over HTTPS"
  description  = "Use of HTTPS ensures server/service authentication and protects data in transit from network layer eavesdropping attacks."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "App Service", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_appservicewebapp_http_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_appservicewebapp_http_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy22" {
  name         = "Deny-AppService-without-BYOC"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "App Service certificates must be stored in Key Vault"
  description  = "App Service (including Logic apps and Function apps) must use certificates stored in Key Vault"
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "App Service", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_appservice_without_byoc_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_appservice_without_byoc_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy23" {
  name         = "Deny-AzFw-Without-Policy"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Azure Firewall should have a default Firewall Policy"
  description  = "This policy denies the creation of Azure Firewall without a default Firewall Policy."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Network", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_azfw_without_policy_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_azfw_without_policy_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy24" {
  name         = "Deny-CognitiveServices-NetworkAcls"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Network ACLs should be restricted for Cognitive Services"
  description  = "Azure Cognitive Services should not allow adding individual IPs or virtual network rules to the service-level firewall. Enable this to restrict inbound network access and enforce the usage of private endpoints."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Cognitive Services", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_cognitiveservices_networkacls_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_cognitiveservices_networkacls_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy25" {
  name         = "Deny-CognitiveServices-Resource-Kinds"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Only explicit kinds for Cognitive Services should be allowed"
  description  = "Azure Cognitive Services should only create explicit allowed kinds."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Cognitive Services", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_cognitiveservices_resource_kinds_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_cognitiveservices_resource_kinds_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy26" {
  name         = "Deny-CognitiveServices-RestrictOutboundNetworkAccess"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Outbound network access should be restricted for Cognitive Services"
  description  = "Azure Cognitive Services allow restricting outbound network access. Enable this to limit outbound connectivity for the service."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Cognitive Services", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_cognitiveservices_restrictoutboundnetworkaccess_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_cognitiveservices_restrictoutboundnetworkaccess_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy27" {
  name         = "Deny-Databricks-NoPublicIp"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Deny public IPs for Databricks cluster"
  description  = "Denies the deployment of workspaces that do not use the noPublicIp feature to host Databricks clusters without public IPs."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Databricks", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud"] })
  policy_rule  = file("./lib/definitions/Policy_deny_databricks_nopublicip_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_databricks_nopublicip_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy28" {
  name         = "Deny-Databricks-Sku"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Deny non-premium Databricks sku"
  description  = "Enforces the use of Premium Databricks workspaces to make sure appropriate security features are available including Databricks Access Controls, Credential Passthrough and SCIM provisioning for Microsoft Entra ID."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Databricks", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud"] })
  policy_rule  = file("./lib/definitions/Policy_deny_databricks_sku_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_databricks_sku_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy29" {
  name         = "Deny-Databricks-VirtualNetwork"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Deny Databricks workspaces without Vnet injection"
  description  = "Enforces the use of vnet injection for Databricks workspaces."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Databricks", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud"] })
  policy_rule  = file("./lib/definitions/Policy_deny_databricks_virtualnetwork_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_databricks_virtualnetwork_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy30" {
  name         = "Deny-EH-minTLS"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Event Hub namespaces should use a valid TLS version"
  description  = "Event Hub namespaces should use a valid TLS version."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Event Hub", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_eh_mintls_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_eh_mintls_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy31" {
  name         = "Deny-EH-Premium-CMK"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Event Hub namespaces (Premium) should use a customer-managed key for encryption"
  description  = "Event Hub namespaces (Premium) should use a customer-managed key for encryption."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Event Hub", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_eh_premium_cmk_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_eh_premium_cmk_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy32" {
  name         = "Deny-FileServices-InsecureAuth"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "File Services with insecure authentication methods should be denied"
  description  = "This policy denies the use of insecure authentication methods (NTLMv2) when using File Services on a storage account."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Storage", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_fileservices_insecureauth_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_fileservices_insecureauth_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy33" {
  name         = "Deny-FileServices-InsecureKerberos"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "File Services with insecure Kerberos ticket encryption should be denied"
  description  = "This policy denies the use of insecure Kerberos ticket encryption (RC4-HMAC) when using File Services on a storage account."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Storage", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_fileservices_insecurekerberos_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_fileservices_insecurekerberos_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy34" {
  name         = "Deny-FileServices-InsecureSmbChannel"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "File Services with insecure SMB channel encryption should be denied"
  description  = "This policy denies the use of insecure channel encryption (AES-128-CCM) when using File Services on a storage account."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Storage", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_fileservices_insecuresmbchannel_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_fileservices_insecuresmbchannel_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy35" {
  name         = "Deny-FileServices-InsecureSmbVersions"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "File Services with insecure SMB versions should be denied"
  description  = "This policy denies the use of insecure versions of SMB (2.1 & 3.0) when using File Services on a storage account."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Storage", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_fileservices_insecuresmbversions_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_fileservices_insecuresmbversions_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy36" {
  name         = "Deny-LogicApps-Without-Https"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Logic app should only be accessible over HTTPS"
  description  = "Use of HTTPS ensures server/service authentication and protects data in transit from network layer eavesdropping attacks."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Logic Apps", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_logicapps_without_https_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_logicapps_without_https_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy37" {
  name         = "Deny-LogicApp-Public-Network"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Logic apps should disable public network access"
  description  = "Disabling public network access improves security by ensuring that the Logic App is not exposed on the public internet. Creating private endpoints can limit exposure of a Logic App. Learn more at: https://aka.ms/app-service-private-endpoint."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Logic Apps", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_logicapp_public_network_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_logicapp_public_network_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy38" {
  name         = "Deny-MachineLearning-Aks"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Deny AKS cluster creation in Azure Machine Learning"
  description  = "Deny AKS cluster creation in Azure Machine Learning and enforce connecting to existing clusters."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Machine Learning", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud"] })
  policy_rule  = file("./lib/definitions/Policy_deny_machinelearning_aks_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_machinelearning_aks_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy39" {
  name         = "Deny-MachineLearning-ComputeCluster-RemoteLoginPortPublicAccess"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Deny public access of Azure Machine Learning clusters via SSH"
  description  = "Deny public access of Azure Machine Learning clusters via SSH."
  metadata     = jsonencode({ "version" : "1.1.0", "category" : "Machine Learning", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud"] })
  policy_rule  = file("./lib/definitions/Policy_deny_machinelearning_computecluster_remoteloginportpublicaccess_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_machinelearning_computecluster_remoteloginportpublicaccess_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy40" {
  name         = "Deny-MachineLearning-ComputeCluster-Scale"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Enforce scale settings for Azure Machine Learning compute clusters"
  description  = "Enforce scale settings for Azure Machine Learning compute clusters."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Budget", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud"] })
  policy_rule  = file("./lib/definitions/Policy_deny_machinelearning_computecluster_scale_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_machinelearning_computecluster_scale_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy41" {
  name         = "Deny-MachineLearning-Compute-SubnetId"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Enforce subnet connectivity for Azure Machine Learning compute clusters and compute instances"
  description  = "Enforce subnet connectivity for Azure Machine Learning compute clusters and compute instances."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Machine Learning", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud"] })
  policy_rule  = file("./lib/definitions/Policy_deny_machinelearning_compute_subnetid_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_machinelearning_compute_subnetid_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy42" {
  name         = "Deny-MachineLearning-Compute-VmSize"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Limit allowed vm sizes for Azure Machine Learning compute clusters and compute instances"
  description  = "Limit allowed vm sizes for Azure Machine Learning compute clusters and compute instances."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Budget", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud"] })
  policy_rule  = file("./lib/definitions/Policy_deny_machinelearning_compute_vmsize_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_machinelearning_compute_vmsize_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy43" {
  name         = "Deny-MachineLearning-HbiWorkspace"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Enforces high business impact Azure Machine Learning Workspaces"
  description  = "Enforces high business impact Azure Machine Learning workspaces."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Machine Learning", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud"] })
  policy_rule  = file("./lib/definitions/Policy_deny_machinelearning_hbiworkspace_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_machinelearning_hbiworkspace_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy44" {
  name         = "Deny-MachineLearning-PublicAccessWhenBehindVnet"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Deny public access behind vnet to Azure Machine Learning workspace"
  description  = "Deny public access behind vnet to Azure Machine Learning workspaces."
  metadata     = jsonencode({ "version" : "1.0.1", "category" : "Machine Learning", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud"] })
  policy_rule  = file("./lib/definitions/Policy_deny_machinelearning_publicaccesswhenbehindvnet_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_machinelearning_publicaccesswhenbehindvnet_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy45" {
  name         = "Deny-MachineLearning-PublicNetworkAccess"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated] Azure Machine Learning should have disabled public network access"
  description  = "Denies public network access for Azure Machine Learning workspaces. Superseded by https://www.azadvertizer.net/azpolicyadvertizer/438c38d2-3772-465a-a9cc-7a6666a275ce.html"
  metadata     = jsonencode({ "version" : "1.0.0-deprecated", "category" : "Machine Learning", "source" : "https://github.com/Azure/Enterprise-Scale/", "deprecated" : true, "supersededBy" : "438c38d2-3772-465a-a9cc-7a6666a275ce", "alzCloudEnvironments" : ["AzureCloud"] })
  policy_rule  = file("./lib/definitions/Policy_deny_machinelearning_publicnetworkaccess_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_machinelearning_publicnetworkaccess_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy46" {
  name         = "Deny-MgmtPorts-From-Internet"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Management port access from the Internet should be blocked"
  description  = "This policy denies any network security rule that allows management port access from the Internet, by default blocking SSH/RDP ports."
  metadata     = jsonencode({ "version" : "2.1.1", "category" : "Network", "source" : "https://github.com/Azure/Enterprise-Scale/", "replacesPolicy" : "Deny-RDP-From-Internet", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_mgmtports_from_internet_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_mgmtports_from_internet_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy47" {
  name         = "Deny-MySql-http"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "MySQL database servers enforce SSL connections."
  description  = "Azure Database for MySQL supports connecting your Azure Database for MySQL server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between your database server and your client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and your application. This configuration enforces that SSL is always enabled for accessing your database server."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "SQL", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_mysql_http_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_mysql_http_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy48" {
  name         = "Deny-PostgreSql-http"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "PostgreSQL database servers enforce SSL connection."
  description  = "Azure Database for PostgreSQL supports connecting your Azure Database for PostgreSQL server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between your database server and your client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and your application. This configuration enforces that SSL is always enabled for accessing your database server."
  metadata     = jsonencode({ "version" : "1.0.1", "category" : "SQL", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_postgresql_http_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_postgresql_http_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy49" {
  name         = "Deny-Private-DNS-Zones"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Deny the creation of private DNS"
  description  = "This policy denies the creation of a private DNS in the current scope, used in combination with policies that create centralized private DNS in connectivity subscription"
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Network", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_private_dns_zones_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_private_dns_zones_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy50" {
  name         = "Deny-PublicEndpoint-MariaDB"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated] Public network access should be disabled for MariaDB"
  description  = "This policy denies the creation of Maria DB accounts with exposed public endpoints. Superseded by https://www.azadvertizer.net/azpolicyadvertizer/fdccbe47-f3e3-4213-ad5d-ea459b2fa077.html"
  metadata     = jsonencode({ "version" : "1.0.0-deprecated", "category" : "SQL", "source" : "https://github.com/Azure/Enterprise-Scale/", "deprecated" : true, "supersededBy" : "fdccbe47-f3e3-4213-ad5d-ea459b2fa077", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_publicendpoint_mariadb_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_publicendpoint_mariadb_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy51" {
  name         = "Deny-PublicIP"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated] Deny the creation of public IP"
  description  = "[Deprecated] This policy denies creation of Public IPs under the assigned scope. Superseded by https://www.azadvertizer.net/azpolicyadvertizer/6c112d4e-5bc7-47ae-a041-ea2d9dccd749.html using appropriate assignment parameters."
  metadata     = jsonencode({ "deprecated" : true, "supersededBy" : "6c112d4e-5bc7-47ae-a041-ea2d9dccd749", "version" : "1.0.0-deprecated", "category" : "Network", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_publicip_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_publicip_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy52" {
  name         = "Deny-RDP-From-Internet"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "[Deprecated] RDP access from the Internet should be blocked"
  description  = "This policy denies any network security rule that allows RDP access from Internet. This policy is superseded by https://www.azadvertizer.net/azpolicyadvertizer/Deny-MgmtPorts-From-Internet.html"
  metadata     = jsonencode({ "deprecated" : true, "supersededBy" : "Deny-MgmtPorts-From-Internet", "version" : "1.0.1-deprecated", "category" : "Network", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_rdp_from_internet_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_rdp_from_internet_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy53" {
  name         = "Deny-Redis-http"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Azure Cache for Redis only secure connections should be enabled"
  description  = "Audit enabling of only connections via SSL to Azure Cache for Redis. Validate both minimum TLS version and enableNonSslPort is disabled. Use of secure connections ensures authentication between the server and the service and protects data in transit from network layer attacks such as man-in-the-middle, eavesdropping, and session-hijacking"
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Cache", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_redis_http_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_redis_http_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy54" {
  name         = "Deny-Service-Endpoints"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Deny or Audit service endpoints on subnets"
  description  = "This Policy will deny/audit Service Endpoints on subnets. Service Endpoints allows the network traffic to bypass Network appliances, such as the Azure Firewall."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Network", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_service_endpoints_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_service_endpoints_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy55" {
  name         = "Deny-SqlMi-minTLS"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "SQL Managed Instance should have the minimal TLS version set to the highest version"
  description  = "Setting minimal TLS version to 1.2 improves security by ensuring your SQL Managed Instance can only be accessed from clients using TLS 1.2. Using versions of TLS less than 1.2 is not reccomended since they have well documented security vunerabilities."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "SQL", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_sqlmi_mintls_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_sqlmi_mintls_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy56" {
  name         = "Deny-Sql-minTLS"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Azure SQL Database should have the minimal TLS version set to the highest version"
  description  = "Setting minimal TLS version to 1.2 improves security by ensuring your Azure SQL Database can only be accessed from clients using TLS 1.2. Using versions of TLS less than 1.2 is not reccomended since they have well documented security vunerabilities."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "SQL", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_sql_mintls_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_sql_mintls_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy57" {
  name         = "Deny-StorageAccount-CustomDomain"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Storage Accounts with custom domains assigned should be denied"
  description  = "This policy denies the creation of Storage Accounts with custom domains assigned as communication cannot be encrypted, and always uses HTTP."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Storage", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_storageaccount_customdomain_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_storageaccount_customdomain_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy58" {
  name         = "Deny-Storage-ContainerDeleteRetentionPolicy"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Storage Accounts should use a container delete retention policy"
  description  = "Enforce container delete retention policies larger than seven days for storage account. Enable this for increased data loss protection."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Storage", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_storage_containerdeleteretentionpolicy_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_storage_containerdeleteretentionpolicy_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy59" {
  name         = "Deny-Storage-CopyScope"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Allowed Copy scope should be restricted for Storage Accounts"
  description  = "Azure Storage accounts should restrict the allowed copy scope. Enforce this for increased data exfiltration protection."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Storage", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_storage_copyscope_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_storage_copyscope_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy60" {
  name         = "Deny-Storage-CorsRules"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Storage Accounts should restrict CORS rules"
  description  = "Deny CORS rules for storage account for increased data exfiltration protection and endpoint protection."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Storage", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_storage_corsrules_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_storage_corsrules_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy61" {
  name         = "Deny-Storage-LocalUser"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Local users should be restricted for Storage Accounts"
  description  = "Azure Storage accounts should disable local users for features like SFTP. Enforce this for increased data exfiltration protection."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Storage", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_storage_localuser_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_storage_localuser_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy62" {
  name         = "Deny-Storage-minTLS"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "[Deprecated] Storage Account set to minimum TLS and Secure transfer should be enabled"
  description  = "Audit requirement of Secure transfer in your storage account. This policy is superseded by https://www.azadvertizer.net/azpolicyadvertizer/fe83a0eb-a853-422d-aac2-1bffd182c5d0.html and https://www.azadvertizer.net/azpolicyadvertizer/404c3081-a854-4457-ae30-26a93ef643f9.html"
  metadata     = jsonencode({ "deprecated" : true, "supersededBy" : "fe83a0eb-a853-422d-aac2-1bffd182c5d0,404c3081-a854-4457-ae30-26a93ef643f9", "version" : "1.0.0-deprecated", "category" : "Storage", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_storage_mintls_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_storage_mintls_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy63" {
  name         = "Deny-Storage-NetworkAclsBypass"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Network ACL bypass option should be restricted for Storage Accounts"
  description  = "Azure Storage accounts should restrict the bypass option for service-level network ACLs. Enforce this for increased data exfiltration protection."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Storage", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_storage_networkaclsbypass_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_storage_networkaclsbypass_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy64" {
  name         = "Deny-Storage-NetworkAclsVirtualNetworkRules"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Virtual network rules should be restricted for Storage Accounts"
  description  = "Azure Storage accounts should restrict the virtual network service-level network ACLs. Enforce this for increased data exfiltration protection."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Storage", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_storage_networkaclsvirtualnetworkrules_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_storage_networkaclsvirtualnetworkrules_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy65" {
  name         = "Deny-Storage-ResourceAccessRulesResourceId"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Resource Access Rules resource IDs should be restricted for Storage Accounts"
  description  = "Azure Storage accounts should restrict the resource access rule for service-level network ACLs to services from a specific Azure subscription. Enforce this for increased data exfiltration protection."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Storage", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_storage_resourceaccessrulesresourceid_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_storage_resourceaccessrulesresourceid_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy66" {
  name         = "Deny-Storage-ResourceAccessRulesTenantId"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Resource Access Rules Tenants should be restricted for Storage Accounts"
  description  = "Azure Storage accounts should restrict the resource access rule for service-level network ACLs to service from the same AAD tenant. Enforce this for increased data exfiltration protection."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Storage", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_storage_resourceaccessrulestenantid_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_storage_resourceaccessrulestenantid_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy67" {
  name         = "Deny-Storage-ServicesEncryption"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Encryption for storage services should be enforced for Storage Accounts"
  description  = "Azure Storage accounts should enforce encryption for all storage services. Enforce this for increased encryption scope."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Storage", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_storage_servicesencryption_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_storage_servicesencryption_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy68" {
  name         = "Deny-Storage-SFTP"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Storage Accounts with SFTP enabled should be denied"
  description  = "This policy denies the creation of Storage Accounts with SFTP enabled for Blob Storage."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Storage", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_storage_sftp_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_storage_sftp_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy69" {
  name         = "Deny-Subnet-Without-Nsg"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Subnets should have a Network Security Group"
  description  = "This policy denies the creation of a subnet without a Network Security Group. NSG help to protect traffic across subnet-level."
  metadata     = jsonencode({ "version" : "2.0.0", "category" : "Network", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_subnet_without_nsg_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_subnet_without_nsg_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy70" {
  name         = "Deny-Subnet-Without-Penp"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Subnets without Private Endpoint Network Policies enabled should be denied"
  description  = "This policy denies the creation of a subnet without Private Endpoint Netwotk Policies enabled. This policy is intended for 'workload' subnets, not 'central infrastructure' (aka, 'hub') subnets."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Network", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_subnet_without_penp_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_subnet_without_penp_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy71" {
  name         = "Deny-Subnet-Without-Udr"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Subnets should have a User Defined Route"
  description  = "This policy denies the creation of a subnet without a User Defined Route (UDR)."
  metadata     = jsonencode({ "version" : "2.0.0", "category" : "Network", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_subnet_without_udr_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_subnet_without_udr_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy72" {
  name         = "Deny-UDR-With-Specific-NextHop"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "User Defined Routes with 'Next Hop Type' set to 'Internet' or 'VirtualNetworkGateway' should be denied"
  description  = "This policy denies the creation of a User Defined Route with 'Next Hop Type' set to 'Internet' or 'VirtualNetworkGateway'."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Network", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_udr_with_specific_nexthop_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_udr_with_specific_nexthop_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy73" {
  name         = "Deny-VNet-Peering"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Deny vNet peering "
  description  = "This policy denies the creation of vNet Peerings under the assigned scope."
  metadata     = jsonencode({ "version" : "1.0.1", "category" : "Network", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_vnet_peering_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_vnet_peering_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy74" {
  name         = "Deny-VNET-Peering-To-Non-Approved-VNETs"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Deny vNet peering to non-approved vNets"
  description  = "This policy denies the creation of vNet Peerings to non-approved vNets under the assigned scope."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Network", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_vnet_peering_to_non_approved_vnets_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_vnet_peering_to_non_approved_vnets_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy75" {
  name         = "Deny-VNET-Peer-Cross-Sub"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Deny vNet peering cross subscription."
  description  = "This policy denies the creation of vNet Peerings outside of the same subscriptions under the assigned scope."
  metadata     = jsonencode({ "version" : "1.0.1", "category" : "Network", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deny_vnet_peer_cross_sub_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deny_vnet_peer_cross_sub_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy76" {
  name         = "Deploy-ASC-SecurityContacts"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Deploy Microsoft Defender for Cloud Security Contacts"
  description  = "Deploy Microsoft Defender for Cloud Security Contacts"
  metadata     = jsonencode({ "version" : "2.0.0", "category" : "Security Center", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_asc_securitycontacts_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_asc_securitycontacts_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy77" {
  name         = "Deploy-Budget"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Deploy a default budget on all subscriptions under the assigned scope"
  description  = "Deploy a default budget on all subscriptions under the assigned scope"
  metadata     = jsonencode({ "version" : "1.1.0", "category" : "Budget", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_budget_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_budget_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy78" {
  name         = "Deploy-Custom-Route-Table"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Deploy a route table with specific user defined routes"
  description  = "Deploys a route table with specific user defined routes when one does not exist. The route table deployed by the policy must be manually associated to subnet(s)"
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Network", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_custom_route_table_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_custom_route_table_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy79" {
  name         = "Deploy-DDoSProtection"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Deploy an Azure DDoS Network Protection"
  description  = "Deploys an Azure DDoS Network Protection"
  metadata     = jsonencode({ "version" : "1.0.1", "category" : "Network", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_ddosprotection_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_ddosprotection_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy80" {
  name         = "Deploy-Diagnostics-AA"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Automation to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Automation to stream to a Log Analytics workspace when any Automation which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_aa_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_aa_policy_paramater.json")
}

resource "azurerm_policy_definition" "custom_policy81" {
  name         = "Deploy-Diagnostics-ACI"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Container Instances to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Container Instances to stream to a Log Analytics workspace when any ACR which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_aci_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_aci_policy_paramater.json")
}

resource "azurerm_policy_definition" "custom_policy82" {
  name         = "Deploy-Diagnostics-ACR"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Container Registry to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Container Registry to stream to a Log Analytics workspace when any ACR which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_acr_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_acr_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy83" {
  name         = "Deploy-Diagnostics-AnalysisService"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Analysis Services to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Analysis Services to stream to a Log Analytics workspace when any Analysis Services which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_analysisservice_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_analysisservice_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy84" {
  name         = "Deploy-Diagnostics-ApiForFHIR"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Azure API for FHIR to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Azure API for FHIR to stream to a Log Analytics workspace when any Azure API for FHIR which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_apiforfhir_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_apiforfhir_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy85" {
  name         = "Deploy-Diagnostics-APIMgmt"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for API Management to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for API Management to stream to a Log Analytics workspace when any API Management which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.2.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_apimgmt_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_apimgmt_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy86" {
  name         = "Deploy-Diagnostics-ApplicationGateway"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Application Gateway to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Application Gateway to stream to a Log Analytics workspace when any Application Gateway which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_applicationgateway_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_applicationgateway_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy87" {
  name         = "Deploy-Diagnostics-AVDScalingPlans"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for AVD Scaling Plans to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for AVD Scaling Plans to stream to a Log Analytics workspace when any Scaling Plan which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_avdscalingplans_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_avdscalingplans_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy88" {
  name         = "Deploy-Diagnostics-Bastion"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Azure Bastion to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Azure Bastion to stream to a Log Analytics workspace when any Azure Bastion which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_bastion_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_bastion_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy89" {
  name         = "Deploy-Diagnostics-CDNEndpoints"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for CDN Endpoint to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for CDN Endpoint to stream to a Log Analytics workspace when any CDN Endpoint which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_cdnendpoints_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_cdnendpoints_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy90" {
  name         = "Deploy-Diagnostics-CognitiveServices"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Cognitive Services to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Cognitive Services to stream to a Log Analytics workspace when any Cognitive Services which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_cognitiveservices_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_cognitiveservices_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy91" {
  name         = "Deploy-Diagnostics-CosmosDB"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Cosmos DB to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Cosmos DB to stream to a Log Analytics workspace when any Cosmos DB which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.2.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_cosmosdb_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_cosmosdb_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy92" {
  name         = "Deploy-Diagnostics-Databricks"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Databricks to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Databricks to stream to a Log Analytics workspace when any Databricks which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.3.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_databricks_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_databricks_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy93" {
  name         = "Deploy-Diagnostics-DataExplorerCluster"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Azure Data Explorer Cluster to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Azure Data Explorer Cluster to stream to a Log Analytics workspace when any Azure Data Explorer Cluster which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_dataexplorercluster_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_dataexplorercluster_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy94" {
  name         = "Deploy-Diagnostics-DataFactory"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Data Factory to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Data Factory to stream to a Log Analytics workspace when any Data Factory which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.2.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_datafactory_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_datafactory_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy95" {
  name         = "Deploy-Diagnostics-DLAnalytics"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Data Lake Analytics to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Data Lake Analytics to stream to a Log Analytics workspace when any Data Lake Analytics which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_dlanalytics_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_dlanalytics_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy96" {
  name         = "Deploy-Diagnostics-EventGridSub"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Event Grid subscriptions to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Event Grid subscriptions to stream to a Log Analytics workspace when any Event Grid subscriptions which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_eventgridsub_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_eventgridsub_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy97" {
  name         = "Deploy-Diagnostics-EventGridSystemTopic"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Event Grid System Topic to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Event Grid System Topic to stream to a Log Analytics workspace when any Event Grid System Topic which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_eventgridsystemtopic_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_eventgridsystemtopic_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy98" {
  name         = "Deploy-Diagnostics-EventGridTopic"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Event Grid Topic to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Event Grid Topic to stream to a Log Analytics workspace when any Event Grid Topic which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.2.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_eventgridtopic_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_eventgridtopic_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy99" {
  name         = "Deploy-Diagnostics-ExpressRoute"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for ExpressRoute to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for ExpressRoute to stream to a Log Analytics workspace when any ExpressRoute which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_expressroute_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_expressroute_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy100" {
  name         = "Deploy-Diagnostics-Firewall"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Firewall to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Firewall to stream to a Log Analytics workspace when any Firewall which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.2.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_firewall_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_firewall_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy101" {
  name         = "Deploy-Diagnostics-FrontDoor"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Front Door to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Front Door to stream to a Log Analytics workspace when any Front Door which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_frontdoor_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_frontdoor_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy102" {
  name         = "Deploy-Diagnostics-Function"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Azure Function App to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Azure Function App to stream to a Log Analytics workspace when any function app which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_function_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_function_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy103" {
  name         = "Deploy-Diagnostics-HDInsight"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for HDInsight to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for HDInsight to stream to a Log Analytics workspace when any HDInsight which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_hdinsight_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_hdinsight_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy104" {
  name         = "Deploy-Diagnostics-iotHub"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for IoT Hub to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for IoT Hub to stream to a Log Analytics workspace when any IoT Hub which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_iothub_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_iothub_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy105" {
  name         = "Deploy-Diagnostics-LoadBalancer"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Load Balancer to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Load Balancer to stream to a Log Analytics workspace when any Load Balancer which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_loadbalancer_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_loadbalancer_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy106" {
  name         = "Deploy-Diagnostics-LogAnalytics"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Log Analytics to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Log Analytics workspaces to stream to a Log Analytics workspace when any Log Analytics workspace which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_loganalytics_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_loganalytics_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy107" {
  name         = "Deploy-Diagnostics-LogicAppsISE"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Logic Apps integration service environment to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Logic Apps integration service environment to stream to a Log Analytics workspace when any Logic Apps integration service environment which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_logicappsise_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_logicappsise_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy108" {
  name         = "Deploy-Diagnostics-MariaDB"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated] Diagnostic Settings for MariaDB to Log Analytics Workspace"
  description  = "Deploys the diagnostic settings for MariaDB to stream to a Log Analytics workspace when any MariaDB  which is missing this diagnostic settings is created or updated. The Policy will set the diagnostic with all metrics and category enabled. Deprecating due to service retirement, https://learn.microsoft.com/en-us/azure/mariadb/whats-happening-to-mariadb"
  metadata     = jsonencode({ "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "deprecated" : true, "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_mariadb_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_mariadb_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy109" {
  name         = "Deploy-Diagnostics-MediaService"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Azure Media Service to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Azure Media Service to stream to a Log Analytics workspace when any Azure Media Service which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_mediaservice_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_mediaservice_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy110" {
  name         = "Deploy-Diagnostics-MlWorkspace"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Machine Learning workspace to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Machine Learning workspace to stream to a Log Analytics workspace when any Machine Learning workspace which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.2.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_mlworkspace_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_mlworkspace_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy111" {
  name         = "Deploy-Diagnostics-MySQL"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Database for MySQL to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Database for MySQL to stream to a Log Analytics workspace when any Database for MySQL which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_mysql_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_mysql_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy112" {
  name         = "Deploy-Diagnostics-NetworkSecurityGroups"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Network Security Groups to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Network Security Groups to stream to a Log Analytics workspace when any Network Security Groups which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_networksecuritygroups_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_networksecuritygroups_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy113" {
  name         = "Deploy-Diagnostics-NIC"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Network Interfaces to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Network Interfaces to stream to a Log Analytics workspace when any Network Interfaces which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_nic_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_nic_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy114" {
  name         = "Deploy-Diagnostics-PostgreSQL"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Database for PostgreSQL to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Database for PostgreSQL to stream to a Log Analytics workspace when any Database for PostgreSQL which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "2.0.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_postgresql_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_postgresql_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy115" {
  name         = "Deploy-Diagnostics-PowerBIEmbedded"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Power BI Embedded to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Power BI Embedded to stream to a Log Analytics workspace when any Power BI Embedded which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_powerbiembedded_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_powerbiembedded_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy116" {
  name         = "Deploy-Diagnostics-RedisCache"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Redis Cache to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Redis Cache to stream to a Log Analytics workspace when any Redis Cache which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_rediscache_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_rediscache_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy117" {
  name         = "Deploy-Diagnostics-Relay"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Relay to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Relay to stream to a Log Analytics workspace when any Relay which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_relay_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_relay_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy118" {
  name         = "Deploy-Diagnostics-SignalR"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for SignalR to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for SignalR to stream to a Log Analytics workspace when any SignalR which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_signalr_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_signalr_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy119" {
  name         = "Deploy-Diagnostics-SQLElasticPools"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for SQL Elastic Pools to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for SQL Elastic Pools to stream to a Log Analytics workspace when any SQL Elastic Pools which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_sqlelasticpools_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_sqlelasticpools_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy120" {
  name         = "Deploy-Diagnostics-SQLMI"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for SQL Managed Instances to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for SQL Managed Instances to stream to a Log Analytics workspace when any SQL Managed Instances which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_sqlmi_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_sqlmi_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy121" {
  name         = "Deploy-Diagnostics-TimeSeriesInsights"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Time Series Insights to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Time Series Insights to stream to a Log Analytics workspace when any Time Series Insights which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_timeseriesinsights_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_timeseriesinsights_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy122" {
  name         = "Deploy-Diagnostics-TrafficManager"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Traffic Manager to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Traffic Manager to stream to a Log Analytics workspace when any Traffic Manager which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_trafficmanager_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_trafficmanager_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy123" {
  name         = "Deploy-Diagnostics-VirtualNetwork"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Virtual Network to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Virtual Network to stream to a Log Analytics workspace when any Virtual Network which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_virtualnetwork_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_virtualnetwork_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy124" {
  name         = "Deploy-Diagnostics-VM"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Virtual Machines to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Virtual Machines to stream to a Log Analytics workspace when any Virtual Machines which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_vm_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_vm_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy125" {
  name         = "Deploy-Diagnostics-VMSS"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for Virtual Machine Scale Sets to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Virtual Machine Scale Sets  to stream to a Log Analytics workspace when any Virtual Machine Scale Sets  which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_vmss_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_vmss_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy126" {
  name         = "Deploy-Diagnostics-VNetGW"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for VPN Gateway to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for VPN Gateway to stream to a Log Analytics workspace when any VPN Gateway which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.1-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_vnetgw_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_vnetgw_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy127" {
  name         = "Deploy-Diagnostics-VWanS2SVPNGW"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for VWAN S2S VPN Gateway to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for VWAN S2S VPN Gateway to stream to a Log Analytics workspace when any VWAN S2S VPN Gateway which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.0.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_vwans2svpngw_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_vwans2svpngw_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy128" {
  name         = "Deploy-Diagnostics-WebServerFarm"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for App Service Plan to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for App Service Plan to stream to a Log Analytics workspace when any App Service Plan which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_webserverfarm_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_webserverfarm_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy129" {
  name         = "Deploy-Diagnostics-Website"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for App Service to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for Web App to stream to a Log Analytics workspace when any Web App which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.2.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_website_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_website_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy130" {
  name         = "Deploy-Diagnostics-WVDAppGroup"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for AVD Application group to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for AVD Application group to stream to a Log Analytics workspace when any application group which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.1-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_wvdappgroup_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_wvdappgroup_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy131" {
  name         = "Deploy-Diagnostics-WVDHostPools"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for AVD Host Pools to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for AVD Host Pools to stream to a Log Analytics workspace when any Host Pools which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.3.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_wvdhostpools_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_wvdhostpools_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy132" {
  name         = "Deploy-Diagnostics-WVDWorkspace"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy Diagnostic Settings for AVD Workspace to Log Analytics workspace"
  description  = "Deploys the diagnostic settings for AVD Workspace to stream to a Log Analytics workspace when any Workspace which is missing this diagnostic settings is created or updated. This policy is superseded by built-in initiative https://www.azadvertizer.net/azpolicyinitiativesadvertizer/0884adba-2312-4468-abeb-5422caed1038.html."
  metadata     = jsonencode({ "deprecated" : true, "version" : "1.1.1-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_diagnostics_wvdworkspace_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_diagnostics_wvdworkspace_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy133" {
  name         = "Deploy-FirewallPolicy"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Deploy Azure Firewall Manager policy in the subscription"
  description  = "Deploys Azure Firewall Manager policy in subscription where the policy is assigned."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Network", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_firewallpolicy_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_firewallpolicy_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy134" {
  name         = "Deploy-LogicApp-TLS"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Configure Logic apps to use the latest TLS version"
  description  = "Periodically, newer versions are released for TLS either due to security flaws, include additional functionality, and enhance speed. Upgrade to the latest TLS version for Function apps to take advantage of security fixes, if any, and/or new functionalities of the latest version."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Logic Apps", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_logicapp_tls_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_logicapp_tls_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy135" {
  name         = "Deploy-MDFC-Arc-SQL-DCR-Association"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Configure Arc-enabled SQL Servers with DCR Association to Microsoft Defender for SQL user-defined DCR"
  description  = "Policy is deprecated as the built-in policy now supports bringing your own UAMI and DCR. Superseded by https://www.azadvertizer.net/azpolicyadvertizer/2227e1f1-23dd-4c3a-85a9-7024a401d8b2.html"
  metadata     = jsonencode({ "version" : "1.0.0-deprecated", "category" : "Security Center", "source" : "https://github.com/Azure/Enterprise-Scale/", "deprecated" : true, "supersededBy" : "2227e1f1-23dd-4c3a-85a9-7024a401d8b2", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_mdfc_arc_sql_dcr_association_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_mdfc_arc_sql_dcr_association_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy136" {
  name         = "Deploy-MDFC-Arc-Sql-DefenderSQL-DCR"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Configure Arc-enabled SQL Servers to auto install Microsoft Defender for SQL and DCR with a user-defined LAW"
  description  = "Policy is deprecated as the built-in policy now supports bringing your own UAMI and DCR. Superseded by https://www.azadvertizer.net/azpolicyadvertizer/63d03cbd-47fd-4ee1-8a1c-9ddf07303de0.html"
  metadata     = jsonencode({ "version" : "1.0.0-deprecated", "category" : "Security Center", "source" : "https://github.com/Azure/Enterprise-Scale/", "deprecated" : true, "supersededBy" : "63d03cbd-47fd-4ee1-8a1c-9ddf07303de0", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_mdfc_arc_sql_defendersql_dcr_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_mdfc_arc_sql_defendersql_dcr_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy137" {
  name         = "Deploy-MDFC-SQL-AMA"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Configure SQL Virtual Machines to automatically install Azure Monitor Agent"
  description  = "Policy is deprecated as the built-in policy now supports bringing your own UAMI and DCR. Superseded by https://www.azadvertizer.net/azpolicyadvertizer/f91991d1-5383-4c95-8ee5-5ac423dd8bb1.html"
  metadata     = jsonencode({ "version" : "1.0.0-deprecated", "category" : "Security Center", "source" : "https://github.com/Azure/Enterprise-Scale/", "deprecated" : true, "supersededBy" : "f91991d1-5383-4c95-8ee5-5ac423dd8bb1", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_mdfc_sql_ama_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_mdfc_sql_ama_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy138" {
  name         = "Deploy-MDFC-SQL-DefenderSQL"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Configure SQL Virtual Machines to automatically install Microsoft Defender for SQL"
  description  = "Policy is deprecated as the built-in policy now supports bringing your own UAMI and DCR. Superseded by https://www.azadvertizer.net/azpolicyadvertizer/ddca0ddc-4e9d-4bbb-92a1-f7c4dd7ef7ce.html"
  metadata     = jsonencode({ "version" : "1.0.0-deprecated", "category" : "Security Center", "source" : "https://github.com/Azure/Enterprise-Scale/", "deprecated" : true, "supersededBy" : "ddca0ddc-4e9d-4bbb-92a1-f7c4dd7ef7ce", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_mdfc_sql_defendersql_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_mdfc_sql_defendersql_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy139" {
  name         = "Deploy-MDFC-SQL-DefenderSQL-DCR"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Configure SQL Virtual Machines to auto install Microsoft Defender for SQL and DCR with a user-defined LAW"
  description  = "Policy is deprecated as the built-in policy now supports bringing your own UAMI and DCR. Superseded by https://www.azadvertizer.net/azpolicyadvertizer/04754ef9-9ae3-4477-bf17-86ef50026304.html"
  metadata     = jsonencode({ "version" : "1.0.1-deprecated", "category" : "Security Center", "source" : "https://github.com/Azure/Enterprise-Scale/", "deprecated" : true, "supersededBy" : "04754ef9-9ae3-4477-bf17-86ef50026304", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_mdfc_sql_defendersql_dcr_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_mdfc_sql_defendersql_dcr_policy_paramater.json")
}

resource "azurerm_policy_definition" "custom_policy140" {
  name         = "Deploy-MySQL-sslEnforcement"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Azure Database for MySQL server deploy a specific min TLS version and enforce SSL."
  description  = "Deploy a specific min TLS version requirement and enforce SSL on Azure Database for MySQL server. Enforce the Server to client applications using minimum version of Tls to secure the connection between your database server and your client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and your application. This configuration enforces that SSL is always enabled for accessing your database server."
  metadata     = jsonencode({ "version" : "1.1.0", "category" : "SQL", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_mysql_sslenforcement_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_mysql_sslenforcement_policy_paramater.json")
}

resource "azurerm_policy_definition" "custom_policy141" {
  name         = "Deploy-Nsg-FlowLogs"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated] Deploys NSG flow logs and traffic analytics"
  description  = "[Deprecated] Deprecated by built-in policy. Deploys NSG flow logs and traffic analytics to a storageaccountid with a specified retention period. Superseded by https://www.azadvertizer.net/azpolicyadvertizer/e920df7f-9a64-4066-9b58-52684c02a091.html"
  metadata     = jsonencode({ "deprecated" : true, "supersededBy" : "e920df7f-9a64-4066-9b58-52684c02a091", "version" : "1.0.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_nsg_flowlogs_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_nsg_flowlogs_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy142" {
  name         = "Deploy-Nsg-FlowLogs-to-LA"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated] Deploys NSG flow logs and traffic analytics to Log Analytics"
  description  = "[Deprecated] Deprecated by built-in policy. Deploys NSG flow logs and traffic analytics to Log Analytics with a specified retention period. Superseded by https://www.azadvertizer.net/azpolicyadvertizer/e920df7f-9a64-4066-9b58-52684c02a091.html"
  metadata     = jsonencode({ "deprecated" : true, "supersededBy" : "e920df7f-9a64-4066-9b58-52684c02a091", "version" : "1.1.0-deprecated", "category" : "Monitoring", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_nsg_flowlogs_to_la_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_nsg_flowlogs_to_la_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy143" {
  name         = "Deploy-PostgreSQL-sslEnforcement"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Azure Database for PostgreSQL server deploy a specific min TLS version requirement and enforce SSL "
  description  = "Deploy a specific min TLS version requirement and enforce SSL on Azure Database for PostgreSQL server. Enables secure server to client by enforce  minimal Tls Version to secure the connection between your database server and your client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and your application. This configuration enforces that SSL is always enabled for accessing your database server."
  metadata     = jsonencode({ "version" : "1.1.0", "category" : "SQL", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_postgresql_sslenforcement_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_postgresql_sslenforcement_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy144" {
  name         = "Deploy-Private-DNS-Generic"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Deploy-Private-DNS-Generic"
  description  = "Configure private DNS zone group to override the DNS resolution for PaaS services private endpoint. See https://aka.ms/pepdnszones for information on values to provide to parameters in this policy."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Networking", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_private_dns_generic_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_private_dns_generic_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy145" {
  name         = "Deploy-SqlMi-minTLS"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "SQL managed instances deploy a specific min TLS version requirement."
  description  = "Deploy a specific min TLS version requirement and enforce SSL on SQL managed instances. Enables secure server to client by enforce  minimal Tls Version to secure the connection between your database server and your client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and your application. This configuration enforces that SSL is always enabled for accessing your database server."
  metadata     = jsonencode({ "version" : "1.2.0", "category" : "SQL", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_sqlmi_mintls_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_sqlmi_mintls_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy146" {
  name         = "Deploy-Sql-AuditingSettings"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Deploy SQL database auditing settings"
  description  = "Deploy auditing settings to SQL Database when it not exist in the deployment"
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "SQL", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_sql_auditingsettings_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_sql_auditingsettings_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy147" {
  name         = "Deploy-SQL-minTLS"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "SQL servers deploys a specific min TLS version requirement."
  description  = "Deploys a specific min TLS version requirement and enforce SSL on SQL servers. Enables secure server to client by enforce  minimal Tls Version to secure the connection between your database server and your client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and your application. This configuration enforces that SSL is always enabled for accessing your database server."
  metadata     = jsonencode({ "version" : "1.1.0", "category" : "SQL", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_sql_mintls_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_sql_mintls_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy148" {
  name         = "Deploy-Sql-SecurityAlertPolicies"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Deploy SQL Database security Alert Policies configuration with email admin accounts"
  description  = "Deploy the security Alert Policies configuration with email admin accounts when it not exist in current configuration"
  metadata     = jsonencode({ "version" : "1.1.1", "category" : "SQL", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_sql_securityalertpolicies_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_sql_securityalertpolicies_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy149" {
  name         = "Deploy-Sql-Tde"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated] Deploy SQL Database Transparent Data Encryption"
  description  = "Deploy the Transparent Data Encryption when it is not enabled in the deployment. Please use this policy instead https://www.azadvertizer.net/azpolicyadvertizer/86a912f6-9a06-4e26-b447-11b16ba8659f.html"
  metadata     = jsonencode({ "deprecated" : true, "supersededBy" : "86a912f6-9a06-4e26-b447-11b16ba8659f", "version" : "1.1.1-deprecated", "category" : "SQL", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_sql_tde_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_sql_tde_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy150" {
  name         = "Deploy-Sql-vulnerabilityAssessments"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy SQL Database vulnerability Assessments"
  description  = "Deploy SQL Database vulnerability Assessments when it not exist in the deployment. Superseded by https://www.azadvertizer.net/azpolicyadvertizer/Deploy-Sql-vulnerabilityAssessments_20230706.html"
  metadata     = jsonencode({ "version" : "1.0.1-deprecated", "category" : "SQL", "source" : "https://github.com/Azure/Enterprise-Scale/", "deprecated" : true, "supersededBy" : "Deploy-Sql-vulnerabilityAssessments_20230706", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_sql_vulnerabilityassessments_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_sql_vulnerabilityassessments_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy151" {
  name         = "Deploy-Sql-vulnerabilityAssessments_20230706"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Deploy SQL Database Vulnerability Assessments"
  description  = "Deploy SQL Database Vulnerability Assessments when it does not exist in the deployment, and save results to the storage account specified in the parameters."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "SQL", "source" : "https://github.com/Azure/Enterprise-Scale/", "replacesPolicy" : "Deploy-Sql-vulnerabilityAssessments", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_sql_vulnerabilityassessments_20230706_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_sql_vulnerabilityassessments_20230706_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy152" {
  name         = "Deploy-Storage-sslEnforcement"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Azure Storage deploy a specific min TLS version requirement and enforce SSL/HTTPS "
  description  = "Deploy a specific min TLS version requirement and enforce SSL on Azure Storage. Enables secure server to client by enforce minimal Tls Version to secure the connection between your database server and your client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and your application. This configuration enforces that SSL is always enabled for accessing your Azure Storage."
  metadata     = jsonencode({ "version" : "1.2.0", "category" : "Storage", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_storage_sslenforcement_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_storage_sslenforcement_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy153" {
  name         = "Deploy-UserAssignedManagedIdentity-VMInsights"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Deprecated]: Deploy User Assigned Managed Identity for VM Insights"
  description  = "Policy is deprecated as it's no longer required. User-Assigned Management Identity is now centralized and deployed by Azure Landing Zones to the Management Subscription."
  metadata     = jsonencode({ "version" : "1.0.0-deprecated", "category" : "Managed Identity", "source" : "https://github.com/Azure/Enterprise-Scale/", "deprecated" : true, "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_userassignedmanagedidentity_vminsights_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_userassignedmanagedidentity_vminsights_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy154" {
  name         = "Deploy-Vm-autoShutdown"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Deploy Virtual Machine Auto Shutdown Schedule"
  description  = "Deploys an auto shutdown schedule to a virtual machine"
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Compute", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_vm_autoshutdown_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_vm_autoshutdown_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy155" {
  name         = "Deploy-VNET-HubSpoke"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Deploy Virtual Network with peering to the hub"
  description  = "This policy deploys virtual network and peer to the hub"
  metadata     = jsonencode({ "version" : "1.1.0", "category" : "Network", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_vnet_hubspoke_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_vnet_hubspoke_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy156" {
  name         = "Deploy-Windows-DomainJoin"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Deploy Windows Domain Join Extension with keyvault configuration"
  description  = "Deploy Windows Domain Join Extension with keyvault configuration when the extension does not exist on a given windows Virtual Machine"
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Guest Configuration", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_deploy_windows_domainjoin_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_deploy_windows_domainjoin_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy157" {
  name         = "Modify-NSG"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Enforce specific configuration of Network Security Groups (NSG)"
  description  = "This policy enforces the configuration of Network Security Groups (NSG)."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Network", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_modify_nsg_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_modify_nsg_policy_paramater.json")
}
resource "azurerm_policy_definition" "custom_policy158" {
  name         = "Modify-UDR"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Enforce specific configuration of User-Defined Routes (UDR)"
  description  = "This policy enforces the configuration of User-Defined Routes (UDR) within a subnet."
  metadata     = jsonencode({ "version" : "1.0.0", "category" : "Network", "source" : "https://github.com/Azure/Enterprise-Scale/", "alzCloudEnvironments" : ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"] })
  policy_rule  = file("./lib/definitions/Policy_modify_udr_policy_rule.json")
  parameters   = file("./lib/definitions/Policy_modify_udr_policy_paramater.json")
}
