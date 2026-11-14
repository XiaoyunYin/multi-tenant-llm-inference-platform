terraform {
  required_version = "= 1.16.2"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.64.0"
    }
  }
  backend "s3" {}
}

provider "aws" {
  region                      = var.aws_region
  skip_credentials_validation = var.offline_validation
  skip_metadata_api_check     = var.offline_validation
  skip_requesting_account_id  = var.offline_validation
  default_tags {
    tags = { Project = "multi-tenant-llm-inference-platform", Milestone = "INF-019", Session = var.session_id }
  }
}
