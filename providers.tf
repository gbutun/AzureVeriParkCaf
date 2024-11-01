terraform {
  required_version = ">=0.13"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~>2.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~>3.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~>4.0"
    }

  }
  backend "azurerm" {
    subscription_id      = "2959c09a-6da0-4463-b541-d266cd08a769"
    tenant_id            = "d17c69a5-a6d3-4c15-9bf1-9d222a5c3e34"
    resource_group_name  = "alz-terraform-rg"
    storage_account_name = "alzterraformrgsa"
    container_name       = "tfstate"
    key                  = "veripol.tfstate"
  }


}

provider "azurerm" {
  features {}
  subscription_id = "2959c09a-6da0-4463-b541-d266cd08a769"
}


