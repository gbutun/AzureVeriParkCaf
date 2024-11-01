variable "resource_group" {
  type    = string
  default = "verigroup"
}

variable "location" {
  type    = string
  default = "westeurope"
}

variable "logAnalytics_diagnostics" {
  type    = string
  default = "b5f6e029-7cdb-4625-84d6-fc1a0f2bc17e"
}

variable "emailSecurityContact" {
  type    = string
  default = "abc@xyz.com"
}

variable "storageAccountResourceId_diag" {
  type    = string
  default = "/subscriptions/2959c09a-6da0-4463-b541-d266cd08a769/resourceGroups/alz-terraform-rg/providers/Microsoft.Storage/storageAccounts/alzterraformrgsa"
}



# variable "policy_name" {
#   type = string
# }
# variable "policy_displayname" {
#   type = string
# }
# variable "policy_description" {
#   type = string
# }
# variable "custom_policy_rule_path" {
#   description = "Path to the custom policy rule JSON"
#   type        = string
# }
# variable "custom_policy_rule_parameter_path" {
#   description = "Path to the custom policy rule parameter JSON"
#   type        = string
# }
# variable "policy_definition_id" {
#   type = string

# }
# variable "scope_id" {
#   type        = string
#   description = "Scope ID from the Policy Assignment. Depending on the Policy Assignment type, this could be the `management_group_id`, `subscription_id`, `resource_group_id` or `resource_id`."
# }
