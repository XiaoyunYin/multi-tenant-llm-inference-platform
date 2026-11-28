terraform {
  required_version = "= 1.16.2"
  required_providers {
    aws = { source = "hashicorp/aws", version = "= 6.64.0" }
  }
}
provider "aws" { region = "us-east-1" }
variable "session" { type = string }
variable "session_seconds" {
  type    = number
  default = 18000
}
variable "source_commit" { type = string }
variable "operator_ami" { type = string }
variable "zones" { type = list(string) }
variable "gpu_release" { type = string }
variable "cpu_release" { type = string }
variable "capacity_group_arn" { type = string }
variable "quota_vcpus" { type = number }
variable "prior_spend_usd" { type = number }
variable "session_forecast_usd" { type = number }
variable "cpu_clock_rehearsal" {
  type    = bool
  default = false
}
variable "cpu_clock_account" {
  type    = string
  default = ""
}

# Reuse the unchanged Package A instance, no ingress, encrypted storage and
# independent OS maximum-lifetime timer. No tests run on this product operator.
module "operator" {
  source             = "../package_a"
  enable_task        = true
  ami                = var.operator_ami
  instance_type      = "m6i.2xlarge"
  session            = "dec077-${var.session}"
  source_commit      = var.source_commit
  host_timer_seconds = var.session_seconds
  root_gib           = 100
}
module "eks" {
  source              = "../eks"
  enable_session      = true
  offline_validation  = false
  session_id          = var.session
  zones               = var.zones
  cpu_clock_rehearsal = var.cpu_clock_rehearsal
  gpu_enabled         = !var.cpu_clock_rehearsal
  pins = {
    kubernetes_version = "1.35"
    gpu_release        = var.gpu_release
    cpu_release        = var.cpu_release
    capacity_group_arn = var.capacity_group_arn
    operator_role_arn  = module.operator.role_arn
    # The only allowed public API caller is this planned operator. The value
    # is unknown in a create plan; the expression fixes a single /32.
    operator_cidrs = ["${module.operator.public_ip}/32"]
  }
  admission = {
    quota_vcpus     = var.quota_vcpus, cumulative_usd = var.prior_spend_usd, bringup_max_usd = var.session_forecast_usd / 2,
    measurement_usd = var.session_forecast_usd / 2, remaining_usd = 10, checkpoint_record = "DEC-087: descriptive session forecast; no cost-only halt"
  }
}
resource "aws_iam_role_policy" "operator" {
  name = "${var.session}-descriptive"
  role = module.operator.role_name
  policy = var.cpu_clock_rehearsal || var.session_seconds > 18000 ? jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["eks:DescribeCluster"], Resource = "arn:aws:eks:us-east-1:${var.cpu_clock_account}:cluster/${var.session}" },
    { Effect = "Allow", Action = ["ecr:GetAuthorizationToken"], Resource = "*" },
    { Effect = "Allow", Action = ["ecr:BatchCheckLayerAvailability", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload", "ecr:PutImage", "ecr:DescribeImages", "ecr:BatchGetImage"], Resource = "arn:aws:ecr:us-east-1:${var.cpu_clock_account}:repository/${var.session}" }
    ] }) : jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["eks:DescribeCluster", "ecr:GetAuthorizationToken"], Resource = "*" },
    { Effect = "Allow", Action = ["ecr:BatchCheckLayerAvailability", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload", "ecr:PutImage", "ecr:DescribeImages", "ecr:BatchGetImage"], Resource = module.eks.repository_arn }
  ] })
}
output "operator_instance" { value = module.operator.instance_id }
output "repository_url" { value = module.eks.repository_url }
output "capacity_binding" { value = module.eks.capacity_binding }
