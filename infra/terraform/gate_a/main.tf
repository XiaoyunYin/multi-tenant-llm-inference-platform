variable "ami" {
  type = string
  validation {
    condition     = can(regex("^ami-[0-9a-f]{17}$", var.ami))
    error_message = "A refreshed Ubuntu amd64 AMI is required."
  }
}
variable "session" {
  type = string
  validation {
    condition     = can(regex("^r366-[a-z0-9-]{1,24}$", var.session))
    error_message = "A Gate A owned session identifier is required."
  }
}
variable "source_commit" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{40}$", var.source_commit))
    error_message = "One full committed source head is required."
  }
}
variable "bucket_name" {
  type = string
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.bucket_name))
    error_message = "A globally unique lowercase bucket name is required."
  }
}
variable "recovery_volume_gib" {
  type = number
  validation {
    condition     = var.recovery_volume_gib >= 1 && var.recovery_volume_gib <= 16384 && floor(var.recovery_volume_gib) == var.recovery_volume_gib
    error_message = "Recovery volume size must be an integer gp3 size in 1-16384 GiB."
  }
}
variable "root_gib" {
  type    = number
  default = 80
  validation {
    condition     = var.root_gib >= 64 && var.root_gib <= 200 && floor(var.root_gib) == var.root_gib
    error_message = "Encrypted gp3 host root must be an integer in 64-200 GiB."
  }
}
variable "transfer_port" {
  type    = number
  default = 38473
  validation {
    condition     = var.transfer_port >= 1024 && var.transfer_port <= 65535 && floor(var.transfer_port) == var.transfer_port
    error_message = "Use an unprivileged TCP transfer port."
  }
}
variable "host_timer_seconds" {
  type = number
}

locals {
  tags = {
    Project   = "multi-tenant-llm-inference-platform"
    Milestone = "R366-Gate-A"
    Session   = var.session
    Source    = var.source_commit
    ManagedBy = "terraform"
  }
  prefix = "gate-a/${var.session}/"
}

resource "aws_vpc" "gate_a" {
  cidr_block           = "10.86.0.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(local.tags, { Role = "gate-a-vpc" })
}
resource "aws_subnet" "gate_a" {
  vpc_id                  = aws_vpc.gate_a.id
  cidr_block              = "10.86.0.0/25"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = false
  tags                    = merge(local.tags, { Role = "private-subnet" })
}
resource "aws_internet_gateway" "gate_a" {
  vpc_id = aws_vpc.gate_a.id
  tags   = merge(local.tags, { Role = "egress-gateway" })
}
resource "aws_subnet" "egress" {
  vpc_id                  = aws_vpc.gate_a.id
  cidr_block              = "10.86.0.128/26"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true
  tags                    = merge(local.tags, { Role = "egress-subnet" })
}
resource "aws_route_table" "egress" {
  vpc_id = aws_vpc.gate_a.id
  tags   = merge(local.tags, { Role = "egress-route-table" })
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gate_a.id
  }
}
resource "aws_route_table_association" "egress" {
  subnet_id      = aws_subnet.egress.id
  route_table_id = aws_route_table.egress.id
}
resource "aws_eip" "gate_a_nat" {
  domain = "vpc"
  tags   = merge(local.tags, { Role = "egress-address" })
}
resource "aws_nat_gateway" "gate_a" {
  allocation_id = aws_eip.gate_a_nat.id
  subnet_id     = aws_subnet.egress.id
  depends_on    = [aws_internet_gateway.gate_a]
  tags          = merge(local.tags, { Role = "egress-nat" })
}
resource "aws_route_table" "gate_a" {
  vpc_id = aws_vpc.gate_a.id
  tags   = merge(local.tags, { Role = "private-route-table" })
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.gate_a.id
  }
}
resource "aws_route_table_association" "gate_a" {
  subnet_id      = aws_subnet.gate_a.id
  route_table_id = aws_route_table.gate_a.id
}
resource "aws_security_group" "hosts" {
  name_prefix            = "${var.session}-hosts-"
  vpc_id                 = aws_vpc.gate_a.id
  revoke_rules_on_delete = true
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_security_group" "receiver" {
  name_prefix            = "${var.session}-receiver-"
  vpc_id                 = aws_vpc.gate_a.id
  revoke_rules_on_delete = true
  ingress {
    description     = "Gate A sender only"
    from_port       = var.transfer_port
    to_port         = var.transfer_port
    protocol        = "tcp"
    security_groups = [aws_security_group.hosts.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_security_group" "endpoints" {
  name_prefix            = "${var.session}-endpoints-"
  vpc_id                 = aws_vpc.gate_a.id
  revoke_rules_on_delete = true
  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.hosts.id, aws_security_group.receiver.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_vpc_endpoint" "ssm" {
  for_each            = toset(["ssm", "ssmmessages", "ec2messages"])
  vpc_id              = aws_vpc.gate_a.id
  service_name        = "com.amazonaws.us-east-1.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.gate_a.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  tags                = merge(local.tags, { Role = "ssm-endpoint" })
}
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.gate_a.id
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.gate_a.id]
  tags              = merge(local.tags, { Role = "s3-endpoint" })
}

resource "aws_iam_role" "host" {
  for_each = toset(["sender", "receiver"])
  name     = "${var.session}-${each.key}"
  tags     = merge(local.tags, { Role = "${each.key}-host-role" })
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole"
    }]
  })
}
resource "aws_iam_role_policy_attachment" "ssm" {
  for_each   = aws_iam_role.host
  role       = each.value.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
resource "aws_iam_instance_profile" "host" {
  for_each = aws_iam_role.host
  name     = "${var.session}-${each.key}"
  role     = each.value.name
  tags     = merge(local.tags, { Role = "${each.key}-host-profile" })
}
resource "aws_iam_role_policy" "receiver_s3" {
  name = "gate-a-object-access"
  role = aws_iam_role.host["receiver"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:ListBucket"], Resource = aws_s3_bucket.receipts.arn, Condition = { StringLike = { "s3:prefix" = [local.prefix, "${local.prefix}*"] } } },
      { Effect = "Allow", Action = ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"], Resource = "${aws_s3_bucket.receipts.arn}/${local.prefix}*" }
    ]
  })
}
resource "aws_iam_role_policy" "sender_gate_a_input_read" {
  name = "gate-a-input-staging-read-only"
  role = aws_iam_role.host["sender"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "${aws_s3_bucket.receipts.arn}/${local.prefix}input/*"
    }]
  })
}
resource "aws_instance" "sender" {
  depends_on = [
    aws_iam_role_policy_attachment.ssm,
    aws_vpc_endpoint.ssm,
    aws_vpc_endpoint.s3,
    aws_route_table_association.gate_a,
  ]
  ami                                  = var.ami
  instance_type                        = "c6i.2xlarge"
  subnet_id                            = aws_subnet.gate_a.id
  vpc_security_group_ids               = [aws_security_group.hosts.id]
  associate_public_ip_address          = false
  iam_instance_profile                 = aws_iam_instance_profile.host["sender"].name
  instance_initiated_shutdown_behavior = "terminate"
  user_data_replace_on_change          = true
  user_data                            = templatefile("${path.module}/host-user-data.sh", { host_timer_seconds = var.host_timer_seconds, role = "sender", recovery_volume_id = "" })
  metadata_options { http_tokens = "required" }
  root_block_device {
    delete_on_termination = true
    encrypted             = true
    volume_type           = "gp3"
    volume_size           = var.root_gib
    iops                  = 3000
    throughput            = 125
  }
  tags        = merge(local.tags, { Role = "sender" })
  volume_tags = merge(local.tags, { Role = "sender-root" })
  timeouts { create = "10m" }
}
resource "aws_instance" "receiver" {
  depends_on = [
    aws_iam_role_policy_attachment.ssm,
    aws_vpc_endpoint.ssm,
    aws_vpc_endpoint.s3,
    aws_route_table_association.gate_a,
  ]
  ami                                  = var.ami
  instance_type                        = "c6i.2xlarge"
  subnet_id                            = aws_subnet.gate_a.id
  vpc_security_group_ids               = [aws_security_group.receiver.id]
  associate_public_ip_address          = false
  iam_instance_profile                 = aws_iam_instance_profile.host["receiver"].name
  instance_initiated_shutdown_behavior = "terminate"
  user_data_replace_on_change          = true
  user_data                            = templatefile("${path.module}/host-user-data.sh", { host_timer_seconds = var.host_timer_seconds, role = "receiver", recovery_volume_id = aws_ebs_volume.recovery.id })
  metadata_options { http_tokens = "required" }
  root_block_device {
    delete_on_termination = true
    encrypted             = true
    volume_type           = "gp3"
    volume_size           = var.root_gib
    iops                  = 3000
    throughput            = 125
  }
  tags        = merge(local.tags, { Role = "receiver" })
  volume_tags = merge(local.tags, { Role = "receiver-root" })
  timeouts { create = "10m" }
}
resource "aws_ebs_volume" "recovery" {
  availability_zone = "us-east-1a"
  encrypted         = true
  type              = "gp3"
  size              = var.recovery_volume_gib
  iops              = 3000
  throughput        = 125
  tags              = merge(local.tags, { Role = "recovery-volume" })
}
resource "aws_volume_attachment" "recovery" {
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.recovery.id
  instance_id = aws_instance.receiver.id
}
resource "aws_s3_bucket" "receipts" {
  bucket        = var.bucket_name
  force_destroy = true
  tags          = merge(local.tags, { Role = "receipts" })
}
resource "aws_s3_bucket_public_access_block" "receipts" {
  bucket                  = aws_s3_bucket.receipts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_ownership_controls" "receipts" {
  bucket = aws_s3_bucket.receipts.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "receipts" {
  bucket = aws_s3_bucket.receipts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
resource "aws_s3_bucket_policy" "receipts" {
  bucket = aws_s3_bucket.receipts.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport", Effect = "Deny", Principal = "*", Action = "s3:*",
      Resource  = [aws_s3_bucket.receipts.arn, "${aws_s3_bucket.receipts.arn}/*"],
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

output "sender_instance_id" { value = aws_instance.sender.id }
output "sender_private_ip" { value = aws_instance.sender.private_ip }
output "receiver_instance_id" { value = aws_instance.receiver.id }
output "receiver_private_ip" { value = aws_instance.receiver.private_ip }
output "recovery_volume_id" { value = aws_ebs_volume.recovery.id }
output "bucket_name" { value = aws_s3_bucket.receipts.bucket }
