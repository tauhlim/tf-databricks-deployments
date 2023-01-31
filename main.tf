terraform {
  required_providers {
    databricks = {
      source = "databricks/databricks"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.15.0"
    }
  }
}

provider "aws" {
  region = var.aws_vars.region
  profile = var.aws_vars.profile
}

provider "databricks" {
  alias    = "mws"
  host     = "https://accounts.cloud.databricks.com"
  username = var.databricks_account_username
  password = var.databricks_account_password
}

/*
Create Cross-Account IAM Role
*/
data "databricks_aws_assume_role_policy" "this" {
  external_id = var.databricks_account_id
}

resource "aws_iam_role" "cross_account_role" {
  name               = "${local.prefix}-crossaccount"
  assume_role_policy = data.databricks_aws_assume_role_policy.this.json
  tags               = merge(var.tags, {Description = "Cross-Account IAM Role for Databricks"})
}

data "databricks_aws_crossaccount_policy" "this" {
}

resource "aws_iam_role_policy" "this" {
  name   = "${local.prefix}-policy"
  role   = aws_iam_role.cross_account_role.id
  policy = data.databricks_aws_crossaccount_policy.this.json
}

resource "time_sleep" "wait" {
  depends_on = [
    aws_iam_role.cross_account_role
  ]
  create_duration = "10s"
}

resource "databricks_mws_credentials" "this" {
  provider         = databricks.mws
  account_id       = var.databricks_account_id
  role_arn         = aws_iam_role.cross_account_role.arn
  credentials_name = "${local.prefix}-creds"
  depends_on       = [aws_iam_role_policy.this, aws_iam_role.cross_account_role, time_sleep.wait]
}

/*
Create S3 Bucket
*/

resource "aws_s3_bucket" "root_storage_bucket" {
  bucket = var.root_bucket_name
  acl    = "private"
  versioning {
    enabled = false
  }
  force_destroy = true
  tags = merge(var.tags, {
    Name = var.root_bucket_name,
    Description = "Workspace Root Bucket for Databricks"
  })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "root_storage_bucket" {
  bucket = aws_s3_bucket.root_storage_bucket.bucket

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "root_storage_bucket" {
  bucket                  = aws_s3_bucket.root_storage_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
  depends_on              = [aws_s3_bucket.root_storage_bucket]
}

data "databricks_aws_bucket_policy" "this" {
  bucket = aws_s3_bucket.root_storage_bucket.bucket
}

resource "aws_s3_bucket_policy" "root_bucket_policy" {
  bucket     = aws_s3_bucket.root_storage_bucket.id
  policy     = data.databricks_aws_bucket_policy.this.json
  depends_on = [aws_s3_bucket_public_access_block.root_storage_bucket]
}

resource "databricks_mws_storage_configurations" "this" {
  provider                   = databricks.mws
  account_id                 = var.databricks_account_id
  bucket_name                = var.root_bucket_name
  storage_configuration_name = "${local.prefix}-storage"
}

/*
Create VPC and Endpoints
*/

data "aws_availability_zones" "available" {}

locals {
  cidr_blocks = {
    vpc = var.cidr_block
    public_subnets = [cidrsubnet(var.cidr_block, 4, 0)]
    private_subnets = [cidrsubnet(var.cidr_block, 4, 1), cidrsubnet(var.cidr_block, 4, 2)]
}
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "3.2.0"

  name = local.prefix
  cidr = local.cidr_blocks.vpc
  azs  = data.aws_availability_zones.available.names
  tags = merge(var.tags, {Description = "VPC for Databricks Workspaces"})

  enable_dns_hostnames = true
  enable_nat_gateway   = var.gateways.nat_gateway
  single_nat_gateway   = var.gateways.single_nat
  create_igw           = var.gateways.igw

  public_subnets = local.cidr_blocks.public_subnets
  private_subnets = local.cidr_blocks.private_subnets

  manage_default_security_group = true
  default_security_group_name   = "${local.prefix}-sg"

  default_security_group_egress = [ 
  {
    description = "Allow all internal TCP and UDP"
    self        = true
  },
  {
    description = "HTTPS"
    cidr_blocks = "0.0.0.0/0"
    protocol = "tcp"
    from_port = 443
    to_port = 443
  },
  {
    description = "PrivateLink"
    cidr_blocks = "0.0.0.0/0"
    protocol = "tcp"
    from_port = 6666
    to_port = 6666
  },
  {
    description = "Metastore"
    cidr_blocks = "0.0.0.0/0"
    protocol = "tcp"
    from_port = 3306
    to_port = 3306
  }]

  default_security_group_ingress = [{
    description = "Allow all internal TCP and UDP"
    self        = true
  }]
}

module "vpc_endpoints" {
  source  = "terraform-aws-modules/vpc/aws//modules/vpc-endpoints"
  version = "3.2.0"
  depends_on = [module.vpc]
  vpc_id             = module.vpc.vpc_id
  security_group_ids = [module.vpc.default_security_group_id]

  endpoints = {
    s3 = {
      service      = "s3"
      service_type = "Gateway"
      route_table_ids = flatten([
        module.vpc.public_route_table_ids,
        module.vpc.private_route_table_ids])
      tags = merge(var.tags, {
        Name = "${local.prefix}-s3-vpc-endpoint",
        Description = "Endpoint for Data Plane to communicate with S3"
      })
    },
    sts = {
      service             = "sts"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
      security_group_ids = [module.vpc.default_security_group_id]
      tags = merge(var.tags, {
        Name = "${local.prefix}-sts-vpc-endpoint",
        Description = "Endpoint for Data Plane to communicate with STS"
      })
    },
    kinesis-streams = {
      service             = "kinesis-streams"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
      security_group_ids = [module.vpc.default_security_group_id]
      tags = merge(var.tags, {
        Name = "${local.prefix}-kinesis-vpc-endpoint",
        Description = "Endpoint for Data Plane to communicate with Kinesis"
      })
    },
  }

  tags = var.tags
}

/* Create Subnet for VPCE */

data "aws_vpc" "prod" {
  id = module.vpc.vpc_id
}

resource "aws_subnet" "dataplane_vpce" {
  vpc_id     = module.vpc.vpc_id
  cidr_block = cidrsubnet(var.cidr_block, 4, 3)

  tags = merge(var.tags, {
    Name = "${local.prefix}-${data.aws_vpc.prod.id}-pl-vpce",
    Description = "Subnet for Databricks PL Endpoints"
  })

  depends_on = [
    module.vpc
  ]
}

resource "aws_route_table" "this" {
  vpc_id = module.vpc.vpc_id

  tags = merge(var.tags, {
    Name = "${local.prefix}-${data.aws_vpc.prod.id}-pl-local-route-tbl"
    Description = "Route Table for Databricks PL Endpoints Subnet"
  })

  depends_on = [
    module.vpc
  ]
}

resource "aws_route_table_association" "dataplane_vpce_rtb" {
  subnet_id      = aws_subnet.dataplane_vpce.id
  route_table_id = aws_route_table.this.id
}

/* 
Create Security Group
*/

data "aws_subnet" "ws_vpc_subnets" {
  for_each = {
    private_subnet_1 = module.vpc.private_subnets[0], 
    private_subnet_2 = module.vpc.private_subnets[1] # , 
    # public_subnet = module.vpc.public_subnets[0]
    }
    id = each.value
  depends_on = [
    module.vpc, module.vpc_endpoints
  ]
}

locals {
  vpc_cidr_blocks = [
    for subnet in data.aws_subnet.ws_vpc_subnets :
    subnet.cidr_block
  ]

  vpce_cidr_block = [aws_subnet.dataplane_vpce.cidr_block]
}

resource "aws_security_group" "dataplane_vpce" {
  name        = "Data Plane VPC endpoint security group"
  description = "Security group shared with relay and workspace endpoints"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description = "Inbound rules"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = concat(local.vpce_cidr_block, local.vpc_cidr_blocks)
  }

  ingress {
    description = "Inbound rules"
    from_port   = 6666
    to_port     = 6666
    protocol    = "tcp"
    cidr_blocks = concat(local.vpce_cidr_block, local.vpc_cidr_blocks)
  }

  egress {
    description = "Outbound rules"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = concat(local.vpce_cidr_block, local.vpc_cidr_blocks)
  }

  egress {
    description = "Outbound rules"
    from_port   = 6666
    to_port     = 6666
    protocol    = "tcp"
    cidr_blocks = concat(local.vpce_cidr_block, local.vpc_cidr_blocks)
  }

  tags = merge(var.tags, {
    Name = "${local.prefix}-${data.aws_vpc.prod.id}-pl-vpce-sg-rules"
  })
}

resource "aws_security_group" "jph_security_group" {
  name        = "Jumphost Security Group"
  description = "Security Group for Jumphost resources. Generally used to test when public_access_enabled=FALSE"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description = "Inbound rules for SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.local_ip]

  }

  ingress {
    description = "Inbound rules for RDP"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [var.local_ip]

  }

  egress {
    description = "Outbound rule to VPCE Subnet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = concat(local.vpce_cidr_block)
  }

  egress {
    description = "Outbound rule to VPCE Subnet"
    from_port   = 6666
    to_port     = 6666
    protocol    = "tcp"
    cidr_blocks = concat(local.vpce_cidr_block)
  }

  tags = merge(var.tags, {
    Name = "${local.prefix}-${data.aws_vpc.prod.id}-pl-vpce-sg-rules"
  })
}


/* Link VPCE to Databricks VPC Endpoint Service */

resource "aws_vpc_endpoint" "backend_rest" {
  vpc_id             = module.vpc.vpc_id
  service_name       = var.workspace_vpce_service
  vpc_endpoint_type  = "Interface"
  security_group_ids = [aws_security_group.dataplane_vpce.id]
  subnet_ids         = [aws_subnet.dataplane_vpce.id]
  tags = merge(var.tags, {
        Name = "${local.prefix}-workspace-vpc-endpoint",
        Description = "Databricks PL Workspace Endpoint"
      })
  private_dns_enabled = var.private_dns_enabled
  depends_on = [aws_subnet.dataplane_vpce, module.vpc]
}

resource "aws_vpc_endpoint" "relay" {
  vpc_id             = module.vpc.vpc_id
  service_name       = var.relay_vpce_service
  vpc_endpoint_type  = "Interface"
  security_group_ids = [aws_security_group.dataplane_vpce.id]
  subnet_ids         = [aws_subnet.dataplane_vpce.id]
  tags = merge(var.tags, {
        Name = "${local.prefix}-scc-vpc-endpoint",
        Description = "Databricks PL SCC Endpoint"
      })
  private_dns_enabled = var.private_dns_enabled
  depends_on = [aws_subnet.dataplane_vpce]
}

resource "databricks_mws_vpc_endpoint" "backend_rest_vpce" {
  provider            = databricks.mws
  account_id          = var.databricks_account_id
  aws_vpc_endpoint_id = aws_vpc_endpoint.backend_rest.id

  vpc_endpoint_name   = "${local.prefix}-vpc-backend-${module.vpc.vpc_id}"
  region              = var.aws_vars.region
  depends_on          = [aws_vpc_endpoint.backend_rest]
}

resource "databricks_mws_vpc_endpoint" "relay" {
  provider            = databricks.mws
  account_id          = var.databricks_account_id
  aws_vpc_endpoint_id = aws_vpc_endpoint.relay.id
  vpc_endpoint_name   = "${local.prefix}-vpc-relay-${module.vpc.vpc_id}"
  region              = var.aws_vars.region
  depends_on          = [aws_vpc_endpoint.relay]
}


/* 
Add network configuration to Databricks
*/

resource "databricks_mws_networks" "this" {
  provider           = databricks.mws
  account_id         = var.databricks_account_id
  network_name       = "${local.prefix}-network"
  security_group_ids = [module.vpc.default_security_group_id]
  subnet_ids         = module.vpc.private_subnets
  vpc_id             = module.vpc.vpc_id
  vpc_endpoints {
    dataplane_relay = [databricks_mws_vpc_endpoint.relay.vpc_endpoint_id]
    rest_api        = [databricks_mws_vpc_endpoint.backend_rest_vpce.vpc_endpoint_id]
  }
}


/* 
Create Private Access Settings and create workspace with the PAS
*/

resource "databricks_mws_private_access_settings" "pas" {
  provider                     = databricks.mws
  account_id                   = var.databricks_account_id
  private_access_settings_name = "Private Access Settings for ${local.prefix}"
  region                       = var.aws_vars.region
  public_access_enabled        = true
}

resource "databricks_mws_workspaces" "this" {
  provider                   = databricks.mws
  account_id                 = var.databricks_account_id
  aws_region                 = var.aws_vars.region
  workspace_name             = local.prefix
  credentials_id             = databricks_mws_credentials.this.credentials_id
  storage_configuration_id   = databricks_mws_storage_configurations.this.storage_configuration_id
  network_id                 = databricks_mws_networks.this.network_id
  private_access_settings_id = databricks_mws_private_access_settings.pas.private_access_settings_id
  pricing_tier               = "ENTERPRISE"
  depends_on                 = [databricks_mws_networks.this]
}