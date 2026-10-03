locals {
  paid_gate_open = (
    var.enable_paid_gpu &&
    !var.offline_validation &&
    trimspace(var.budget_authorization_id) != "" &&
    var.ami_id != "" &&
    var.approved_phase_cap_usd > 0 &&
    var.estimated_max_session_cost_usd > 0 &&
    var.estimated_max_session_cost_usd <= var.approved_phase_cap_usd
  )
  paid_resource_count = local.paid_gate_open ? 1 : 0

  common_tags = {
    Project   = "multi-tenant-llm-inference-platform"
    Milestone = "INF-011"
    ManagedBy = "terraform"
    Purpose   = "bounded-single-gpu-pilot"
  }
}

check "paid_resource_gate" {
  assert {
    condition = !var.enable_paid_gpu || local.paid_gate_open
    error_message = join(" ", [
      "Paid GPU creation is locked.",
      "Set offline_validation=false, record a budget_authorization_id and exact ami_id, and provide positive estimated/approved costs with estimate <= cap."
    ])
  }
}

resource "aws_vpc" "pilot" {
  count                = local.paid_resource_count
  cidr_block           = "10.42.0.0/24"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "inf011-pilot" }
}

resource "aws_internet_gateway" "pilot" {
  count  = local.paid_resource_count
  vpc_id = aws_vpc.pilot[0].id

  tags = { Name = "inf011-pilot" }
}

resource "aws_subnet" "pilot" {
  count                   = local.paid_resource_count
  vpc_id                  = aws_vpc.pilot[0].id
  cidr_block              = "10.42.0.0/25"
  availability_zone       = var.availability_zone != "" ? var.availability_zone : null
  map_public_ip_on_launch = true

  tags = { Name = "inf011-pilot" }
}

resource "aws_route_table" "pilot" {
  count  = local.paid_resource_count
  vpc_id = aws_vpc.pilot[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.pilot[0].id
  }

  tags = { Name = "inf011-pilot" }
}

resource "aws_route_table_association" "pilot" {
  count          = local.paid_resource_count
  subnet_id      = aws_subnet.pilot[0].id
  route_table_id = aws_route_table.pilot[0].id
}

resource "aws_security_group" "pilot" {
  count                  = local.paid_resource_count
  name_prefix            = "inf011-pilot-"
  description            = "No ingress; operator access is through SSM Session Manager"
  vpc_id                 = aws_vpc.pilot[0].id
  revoke_rules_on_delete = true

  egress {
    description = "Model, image, package, and SSM endpoints"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "inf011-pilot" }
}

resource "aws_iam_role" "pilot" {
  count       = local.paid_resource_count
  name_prefix = "inf011-pilot-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  count      = local.paid_resource_count
  role       = aws_iam_role.pilot[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "pilot" {
  count       = local.paid_resource_count
  name_prefix = "inf011-pilot-"
  role        = aws_iam_role.pilot[0].name
}

resource "aws_instance" "pilot" {
  count                       = local.paid_resource_count
  ami                         = var.ami_id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.pilot[0].id
  vpc_security_group_ids      = [aws_security_group.pilot[0].id]
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.pilot[0].name

  instance_initiated_shutdown_behavior = "terminate"
  user_data_replace_on_change          = true
  user_data = templatefile("${path.module}/user-data.sh.tftpl", {
    max_session_hours = var.max_session_hours
  })

  timeouts {
    create = "10m"
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    delete_on_termination = true
    encrypted             = true
    volume_size           = var.root_volume_gib
    volume_type           = "gp3"
  }

  volume_tags = merge(local.common_tags, { Name = "inf011-pilot-root" })

  tags = { Name = "inf011-pilot" }

  depends_on = [
    aws_iam_role_policy_attachment.ssm,
    aws_route_table_association.pilot,
  ]
}
