variable "root_bucket_name" {
    default = "<name/of/root/bucket>"
}

variable "workspace_vpce_service" {
    default = "<workspace-vpce-id>"
}
variable "relay_vpce_service" {
    default = "<scc-vpce-id>"
}

variable "gateways" {
  default = {
    "nat_gateway": false,
    "single_nat": false,
    "igw": false
  }
}

variable "private_dns_enabled" { default = true }

variable "databricks_account_username" {
  default = "<user@email.com>"
}
variable "databricks_account_password" {sensitive = true}

variable "databricks_account_id" {
  default = "<your-databricks-account-id>"
}

variable "tags" {
  default = {
    "Creator": "<user@email.com>",
    "Owner": "<user@email.com>",
    "Service":"Databricks Cloud Infra", 
    "Purpose": "terraform-test",
    "AllowDowntime": "off"
  }
}

variable "cidr_block" {
  default = "10.4.0.0/16"
}

variable "aws_vars" {
  default = {
    "region": "<aws-selected-region>",
    "profile": "<aws-profile-to-use>"
  }
}

locals {
  prefix = "<prefix-for-asset-names>"
}

variable "local_ip" {default = "<your/ip/address>"} 