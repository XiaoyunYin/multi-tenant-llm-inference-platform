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
  region                      = "us-east-1"
  skip_credentials_validation = var.offline_validation
  skip_metadata_api_check     = var.offline_validation
  skip_requesting_account_id  = var.offline_validation
}
variable "enable_bootstrap" {
  type    = bool
  default = false
}
variable "offline_validation" {
  type    = bool
  default = true
}
variable "name" {
  type    = string
  default = "m5-offline"
  validation {
    condition     = can(regex("^m5-[a-z0-9-]{1,24}$", var.name))
    error_message = "Use a bounded session name; the same session must own the group."
  }
}
variable "state_bucket" {
  type    = string
  default = ""
  validation {
    condition     = !var.enable_bootstrap || can(regex("^m5-[a-z0-9-]{3,50}$", var.state_bucket))
    error_message = "An explicit globally unique M5 state-bucket name is required."
  }
}
locals { count = var.enable_bootstrap && !var.offline_validation ? 1 : 0 }
resource "terraform_data" "gate" {
  count = var.enable_bootstrap ? 1 : 0
  lifecycle {
    precondition {
      condition     = !var.offline_validation
      error_message = "Bootstrap must be explicitly enabled outside offline validation."
    }
  }
}
resource "aws_resourcegroups_group" "capacity" {
  count = local.count
  name  = "${var.name}-capacity"
  configuration { type = "AWS::EC2::CapacityReservationPool" }
  configuration {
    type = "AWS::ResourceGroups::Generic"
    parameters {
      name   = "allowed-resource-types"
      values = ["AWS::EC2::CapacityReservation"]
    }
  }
  tags       = { Milestone = "INF-019", Session = var.name }
  depends_on = [terraform_data.gate]
}
resource "aws_s3_bucket" "state" {
  count         = local.count
  bucket        = var.state_bucket
  force_destroy = false
  depends_on    = [terraform_data.gate]
}
resource "aws_s3_bucket_versioning" "state" {
  count  = local.count
  bucket = aws_s3_bucket.state[0].id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  count  = local.count
  bucket = aws_s3_bucket.state[0].id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}
resource "aws_s3_bucket_public_access_block" "state" {
  count                   = local.count
  bucket                  = aws_s3_bucket.state[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_policy" "state" {
  count  = local.count
  bucket = aws_s3_bucket.state[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "TLSOnly", Effect = "Deny", Principal = "*", Action = "s3:*",
      Resource  = [aws_s3_bucket.state[0].arn, "${aws_s3_bucket.state[0].arn}/*"],
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}
output "capacity_group_arn" {
  value = local.count == 1 ? aws_resourcegroups_group.capacity[0].arn : null
}
output "session_backend" {
  value = local.count == 1 ? {
    bucket = var.state_bucket, key = "${var.name}/terraform.tfstate",
    region = "us-east-1", encrypt = true, use_lockfile = true
  } : null
}
