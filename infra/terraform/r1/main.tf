locals {
  enabled = var.enable_paid && !var.offline_validation && var.gpu_ami != "" && var.cpu_ami != "" && var.m4_estimate_usd > 0 && var.m4_estimate_usd <= 86.54
  count   = local.enabled ? 1 : 0
  gpu_hosts = local.enabled ? {
    gpu-0 = { type = "g6.xlarge", ami = var.gpu_ami, root = 200 }
    gpu-1 = { type = "g6.xlarge", ami = var.gpu_ami, root = 200 }
  } : {}
  cpu_hosts = local.enabled ? {
    service   = { type = "c6i.2xlarge", ami = var.cpu_ami, root = 40 }
    generator = { type = "c6i.2xlarge", ami = var.cpu_ami, root = 40 }
  } : {}
  tags = {
    Project   = "multi-tenant-llm-inference-platform"
    Milestone = "INF-040"
    Session   = var.session_id
    ManagedBy = "terraform"
  }
}
check "paid_gate" {
  assert {
    condition     = !var.enable_paid || local.enabled
    error_message = "R1 paid plan needs exact AMIs, non-offline mode and estimate within Xiaoyun's DEC-058 $86.54 cap."
  }
}
resource "aws_vpc" "r1" {
  count                = local.count
  cidr_block           = "10.43.0.0/24"
  enable_dns_hostnames = true
  enable_dns_support   = true
}
resource "aws_internet_gateway" "r1" {
  count  = local.count
  vpc_id = aws_vpc.r1[0].id
}
resource "aws_subnet" "r1" {
  count                   = local.count
  vpc_id                  = aws_vpc.r1[0].id
  cidr_block              = "10.43.0.0/25"
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true
}
resource "aws_route_table" "r1" {
  count  = local.count
  vpc_id = aws_vpc.r1[0].id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.r1[0].id
  }
}
resource "aws_route_table_association" "r1" {
  count          = local.count
  subnet_id      = aws_subnet.r1[0].id
  route_table_id = aws_route_table.r1[0].id
}
resource "aws_security_group" "r1" {
  count                  = local.count
  name_prefix            = "r1-${var.session_id}-"
  vpc_id                 = aws_vpc.r1[0].id
  revoke_rules_on_delete = true
  ingress {
    description = "Only same-session hosts; never public ingress"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    self        = true
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_iam_role" "r1" {
  count       = local.count
  name_prefix = "r1-${var.session_id}-"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}
resource "aws_iam_role_policy_attachment" "ssm" {
  count      = local.count
  role       = aws_iam_role.r1[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
resource "aws_iam_instance_profile" "r1" {
  count       = local.count
  name_prefix = "r1-${var.session_id}-"
  role        = aws_iam_role.r1[0].name
}
resource "aws_instance" "gpu" {
  for_each                             = local.gpu_hosts
  ami                                  = each.value.ami
  instance_type                        = each.value.type
  subnet_id                            = aws_subnet.r1[0].id
  vpc_security_group_ids               = [aws_security_group.r1[0].id]
  associate_public_ip_address          = true
  iam_instance_profile                 = aws_iam_instance_profile.r1[0].name
  instance_initiated_shutdown_behavior = "terminate"
  user_data_replace_on_change          = true
  user_data                            = file("${path.module}/user-data.sh")
  capacity_reservation_specification {
    capacity_reservation_preference = "capacity-reservations-only"
  }
  tenancy = "default"
  metadata_options {
    http_tokens = "required"
  }
  root_block_device {
    delete_on_termination = true
    encrypted             = true
    volume_size           = each.value.root
    volume_type           = "gp3"
    iops                  = 3000
    throughput            = 125
  }
  tags        = merge(local.tags, { Role = each.key })
  volume_tags = merge(local.tags, { Role = each.key })
  timeouts { create = "10m" }
  depends_on = [aws_iam_role_policy_attachment.ssm, aws_route_table_association.r1]
}

resource "aws_instance" "cpu" {
  for_each                             = local.cpu_hosts
  ami                                  = each.value.ami
  instance_type                        = each.value.type
  subnet_id                            = aws_subnet.r1[0].id
  vpc_security_group_ids               = [aws_security_group.r1[0].id]
  associate_public_ip_address          = true
  iam_instance_profile                 = aws_iam_instance_profile.r1[0].name
  instance_initiated_shutdown_behavior = "terminate"
  user_data_replace_on_change          = true
  user_data                            = file("${path.module}/user-data.sh")
  metadata_options {
    http_tokens = "required"
  }
  root_block_device {
    delete_on_termination = true
    encrypted             = true
    volume_size           = each.value.root
    volume_type           = "gp3"
    iops                  = 3000
    throughput            = 125
  }
  tags        = merge(local.tags, { Role = each.key })
  volume_tags = merge(local.tags, { Role = each.key })
  timeouts { create = "10m" }
  depends_on = [
    aws_iam_role_policy_attachment.ssm,
    aws_route_table_association.r1,
    aws_instance.gpu,
  ]
}

output "hosts" {
  value = merge(
    { for role, host in aws_instance.gpu : role => { id = host.id, private_ip = host.private_ip } },
    { for role, host in aws_instance.cpu : role => { id = host.id, private_ip = host.private_ip } },
  )
}
