variable "enable_task" {
  type    = bool
  default = false
}
variable "ami" {
  type = string
  validation {
    condition     = can(regex("^ami-[0-9a-f]{17}$", var.ami))
    error_message = "A refreshed Ubuntu amd64 AMI is required."
  }
}
variable "instance_type" {
  type = string
  validation {
    condition     = contains(["g6.xlarge"], var.instance_type)
    error_message = "Only the separately reviewed single-L4 compatibility shape is permitted."
  }
}
variable "session" {
  type = string
  validation {
    condition     = can(regex("^dec077-[a-z0-9-]{1,24}$", var.session))
    error_message = "An owned DEC-077 session is required."
  }
}
variable "source_sha256" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.source_sha256))
    error_message = "The complete payload manifest SHA256 is required."
  }
}
variable "host_timer_seconds" {
  type = number
}
variable "root_gib" {
  type    = number
  default = 128
  validation {
    condition     = var.root_gib >= 128 && var.root_gib <= 128 && floor(var.root_gib) == var.root_gib
    error_message = "Root storage must fit the byte worksheet at exactly 128 GiB."
  }
}
locals {
  n    = var.enable_task ? 1 : 0
  tags = { Project = "multi-tenant-llm-inference-platform", Milestone = "L4-COMPAT", Session = var.session, Source = var.source_sha256, ManagedBy = "terraform" }
}
resource "aws_vpc" "task" {
  count                = local.n
  cidr_block           = "10.77.0.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = true
}
resource "aws_internet_gateway" "task" {
  count  = local.n
  vpc_id = aws_vpc.task[0].id
}
resource "aws_subnet" "task" {
  count                   = local.n
  vpc_id                  = aws_vpc.task[0].id
  cidr_block              = "10.77.0.0/25"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true
}
resource "aws_route_table" "task" {
  count  = local.n
  vpc_id = aws_vpc.task[0].id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.task[0].id
  }
}
resource "aws_route_table_association" "task" {
  count          = local.n
  subnet_id      = aws_subnet.task[0].id
  route_table_id = aws_route_table.task[0].id
}
resource "aws_security_group" "task" {
  count                  = local.n
  name_prefix            = "${var.session}-"
  vpc_id                 = aws_vpc.task[0].id
  revoke_rules_on_delete = true
  # No ingress. Administration is through the R1 SSM operator path.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_iam_role" "task" {
  count       = local.n
  name_prefix = "${var.session}-"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }
  ] })
}
resource "aws_iam_role_policy_attachment" "ssm" {
  count      = local.n
  role       = aws_iam_role.task[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
resource "aws_iam_instance_profile" "task" {
  count       = local.n
  name_prefix = "${var.session}-"
  role        = aws_iam_role.task[0].name
}
resource "aws_instance" "task" {
  depends_on                           = [aws_iam_role_policy_attachment.ssm]
  count                                = local.n
  ami                                  = var.ami
  instance_type                        = var.instance_type
  subnet_id                            = aws_subnet.task[0].id
  vpc_security_group_ids               = [aws_security_group.task[0].id]
  associate_public_ip_address          = true
  iam_instance_profile                 = aws_iam_instance_profile.task[0].name
  instance_initiated_shutdown_behavior = "terminate"
  user_data_replace_on_change          = true
  user_data                            = templatefile("${path.module}/user-data.sh", { host_timer_seconds = var.host_timer_seconds })
  metadata_options { http_tokens = "required" }
  root_block_device {
    delete_on_termination = true
    encrypted             = true
    volume_type           = "gp3"
    volume_size           = var.root_gib
    iops                  = 3000
    throughput            = 125
  }
  tags        = local.tags
  volume_tags = local.tags
  timeouts { create = "10m" }
}
output "instance_id" { value = try(aws_instance.task[0].id, null) }
