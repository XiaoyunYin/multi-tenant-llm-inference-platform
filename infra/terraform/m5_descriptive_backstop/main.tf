terraform {
  required_version = "= 1.16.2"
  required_providers { aws = { source = "hashicorp/aws", version = "= 6.64.0" } }
}
provider "aws" {
  region = "us-east-1"
  default_tags { tags = { Project = "multi-tenant-llm-inference-platform", Session = var.session } }
}
variable "session" { type = string }
variable "state_bucket" { type = string }
variable "zip_path" { type = string }
variable "zip_sha256_base64" { type = string }
variable "account" { type = string }
locals { name = "${var.session}-cleanup" }
resource "aws_iam_role" "cleanup" {
  name               = local.name
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "lambda.amazonaws.com" } }] })
}
resource "aws_iam_role_policy" "cleanup" {
  role = aws_iam_role.cleanup.id
  name = local.name
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["ec2:Describe*", "eks:List*", "eks:Describe*", "iam:List*", "logs:DescribeLogGroups", "autoscaling:DescribeAutoScalingGroups"], Resource = "*" },
    { Effect = "Allow", Action = ["autoscaling:DeleteAutoScalingGroup"], Resource = "arn:aws:autoscaling:us-east-1:${var.account}:autoScalingGroup:*:autoScalingGroupName/eks-${var.session}-*" },
    { Effect = "Allow", Action = ["ssm:GetParameter"], Resource = "arn:aws:ssm:us-east-1:${var.account}:parameter/${var.session}/deadline" },
    { Effect = "Allow", Action = ["eks:DeleteCluster", "eks:DeleteNodegroup"], Resource = ["arn:aws:eks:us-east-1:${var.account}:cluster/${var.session}", "arn:aws:eks:us-east-1:${var.account}:nodegroup/${var.session}/*"] },
    { Effect = "Allow", Action = ["ecr:DeleteRepository"], Resource = "arn:aws:ecr:us-east-1:${var.account}:repository/${var.session}" },
    # Terraform default tags cover both roots; R1 tags the reservation at creation.
    { Effect = "Allow", Action = ["ec2:TerminateInstances", "ec2:DisassociateRouteTable", "ec2:DeleteRouteTable", "ec2:DeleteSubnet", "ec2:DetachInternetGateway", "ec2:DeleteInternetGateway", "ec2:DeleteVpc", "ec2:ReleaseAddress", "ec2:DeleteLaunchTemplate"], Resource = "*", Condition = { StringEquals = { "aws:RequestedRegion" = "us-east-1", "aws:ResourceTag/Session" = [var.session, "dec077-${var.session}"] } } },
    { Effect = "Allow", Action = ["ec2:CancelCapacityReservation"], Resource = "*", Condition = { StringEquals = { "aws:RequestedRegion" = "us-east-1", "aws:ResourceTag/Session" = var.session } } },
    # EKS managed instances carry a cluster-name tag, not necessarily Session.
    { Effect = "Allow", Action = ["ec2:TerminateInstances"], Resource = "*", Condition = { StringEquals = { "aws:RequestedRegion" = "us-east-1", "aws:ResourceTag/eks:cluster-name" = var.session } } },
    { Effect = "Allow", Action = ["ec2:TerminateInstances"], Resource = "*", Condition = { StringEquals = { "aws:RequestedRegion" = "us-east-1", "aws:ResourceTag/aws:eks:cluster-name" = var.session } } },
    # EKS-created ENIs/SGs need not inherit Session. The bound handler derives
    # them solely from VPCs carrying the exact session or operator session tag.
    { Effect = "Allow", Action = ["ec2:DeleteNetworkInterface", "ec2:RevokeSecurityGroupIngress", "ec2:RevokeSecurityGroupEgress", "ec2:DeleteSecurityGroup"], Resource = "*", Condition = { StringEquals = { "aws:RequestedRegion" = "us-east-1" } } },
    { Effect = "Allow", Action = ["iam:ListAttachedRolePolicies", "iam:ListRolePolicies", "iam:DetachRolePolicy", "iam:DeleteRolePolicy", "iam:DeleteRole", "iam:RemoveRoleFromInstanceProfile", "iam:DeleteInstanceProfile"], Resource = ["arn:aws:iam::${var.account}:role/${var.session}-*", "arn:aws:iam::${var.account}:role/dec077-${var.session}-*", "arn:aws:iam::${var.account}:instance-profile/dec077-${var.session}-*"] },
    { Effect = "Allow", Action = ["s3:ListBucketVersions", "s3:DeleteObjectVersion", "s3:DeleteObject", "s3:DeleteBucket"], Resource = ["arn:aws:s3:::${var.state_bucket}", "arn:aws:s3:::${var.state_bucket}/*"] },
    { Effect = "Allow", Action = ["resource-groups:DeleteGroup"], Resource = "arn:aws:resource-groups:us-east-1:${var.account}:group/${var.session}-capacity" },
    { Effect = "Allow", Action = ["logs:DeleteLogGroup"], Resource = "arn:aws:logs:us-east-1:${var.account}:log-group:/aws/eks/${var.session}/*" },
    { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "arn:aws:logs:us-east-1:${var.account}:log-group:/aws/lambda/${local.name}:*" }
  ] })
}
resource "aws_cloudwatch_log_group" "cleanup" {
  name              = "/aws/lambda/${local.name}"
  retention_in_days = 1
}
resource "aws_lambda_function" "cleanup" {
  function_name    = local.name
  role             = aws_iam_role.cleanup.arn
  runtime          = "python3.12"
  handler          = "m5_descriptive_cleanup.handler"
  filename         = var.zip_path
  source_code_hash = var.zip_sha256_base64
  timeout          = 55
  environment { variables = { SESSION = var.session, PARAMETER = "/${var.session}/deadline", STATE_BUCKET = var.state_bucket } }
  depends_on = [aws_iam_role_policy.cleanup, aws_cloudwatch_log_group.cleanup]
}
resource "aws_cloudwatch_event_rule" "cleanup" {
  name                = local.name
  schedule_expression = "rate(1 minute)"
  state               = "ENABLED"
}
resource "aws_cloudwatch_event_target" "cleanup" {
  rule = aws_cloudwatch_event_rule.cleanup.name
  arn  = aws_lambda_function.cleanup.arn
  retry_policy {
    maximum_event_age_in_seconds = 300
    maximum_retry_attempts       = 2
  }
}
resource "aws_lambda_permission" "schedule" {
  statement_id   = "OriginalDeadlineCleanup"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.cleanup.function_name
  principal      = "events.amazonaws.com"
  source_arn     = aws_cloudwatch_event_rule.cleanup.arn
  source_account = var.account
}
