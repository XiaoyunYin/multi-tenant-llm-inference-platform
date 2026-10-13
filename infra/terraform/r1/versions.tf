terraform {
  required_version = "= 1.16.2"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.64.0"
    }
  }
}

provider "aws" {
  region                      = var.aws_region
  profile                     = var.offline_validation ? null : var.aws_profile
  skip_credentials_validation = var.offline_validation
  skip_metadata_api_check     = var.offline_validation
  skip_requesting_account_id  = var.offline_validation
  default_tags { tags = local.tags }
}
