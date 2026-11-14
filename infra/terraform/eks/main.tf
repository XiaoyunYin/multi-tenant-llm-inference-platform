locals {
  addon_pins = jsondecode(file("${path.module}/addon-pins.json"))
  enabled    = var.enable_session && !var.offline_validation
  count      = local.enabled ? 1 : 0
  zones      = local.enabled ? { for i, z in var.zones : tostring(i) => z } : {}
  gpu_subnet = "0"
  roles      = local.enabled ? toset(["cluster", "node"]) : toset([])
  policies = local.enabled ? {
    cluster = { role = "cluster", policy = "AmazonEKSClusterPolicy" }
    worker  = { role = "node", policy = "AmazonEKSWorkerNodePolicy" }
    cni     = { role = "node", policy = "AmazonEKS_CNI_Policy" }
    ecr     = { role = "node", policy = "AmazonEC2ContainerRegistryPullOnly" }
    ssm     = { role = "node", policy = "AmazonSSMManagedInstanceCore" }
  } : {}
}

# Fail hard rather than silently planning an enabled session in offline mode.
resource "terraform_data" "gate" {
  count = var.enable_session ? 1 : 0
  lifecycle {
    precondition {
      condition     = !var.offline_validation
      error_message = "Explicit session mode required; mocked tests supply the AWS provider."
    }
  }
}
resource "aws_vpc" "m5" {
  count                = local.count
  cidr_block           = "10.45.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}
resource "aws_internet_gateway" "m5" {
  count  = local.count
  vpc_id = aws_vpc.m5[0].id
}
resource "aws_subnet" "m5" {
  for_each                = local.zones
  vpc_id                  = aws_vpc.m5[0].id
  availability_zone       = each.value
  cidr_block              = cidrsubnet("10.45.0.0/16", 8, tonumber(each.key))
  map_public_ip_on_launch = true
  tags                    = { "kubernetes.io/role/elb" = "1" }
}
resource "aws_route_table" "m5" {
  count  = local.count
  vpc_id = aws_vpc.m5[0].id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.m5[0].id
  }
}
resource "aws_route_table_association" "m5" {
  for_each       = local.zones
  subnet_id      = aws_subnet.m5[each.key].id
  route_table_id = aws_route_table.m5[0].id
}
resource "aws_iam_role" "m5" {
  for_each    = local.roles
  name_prefix = "${var.session_id}-${each.key}-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = {
      Service = each.key == "cluster" ? "eks.amazonaws.com" : "ec2.amazonaws.com"
    } }]
  })
}
resource "aws_iam_role_policy_attachment" "m5" {
  for_each   = local.policies
  role       = aws_iam_role.m5[each.value.role].name
  policy_arn = "arn:aws:iam::aws:policy/${each.value.policy}"
}
resource "aws_cloudwatch_log_group" "m5" {
  count             = local.count
  name              = "/aws/eks/${var.session_id}/cluster"
  retention_in_days = 1
}
resource "aws_eks_cluster" "m5" {
  count                         = local.count
  name                          = var.session_id
  role_arn                      = aws_iam_role.m5["cluster"].arn
  bootstrap_self_managed_addons = false
  version                       = var.pins.kubernetes_version
  enabled_cluster_log_types     = ["api", "audit", "authenticator"]
  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = false
  }
  vpc_config {
    subnet_ids              = [for s in aws_subnet.m5 : s.id]
    endpoint_private_access = true
    endpoint_public_access  = true
    public_access_cidrs     = var.pins.operator_cidrs
  }
  upgrade_policy { support_type = "STANDARD" }
  depends_on = [terraform_data.gate, aws_iam_role_policy_attachment.m5, aws_cloudwatch_log_group.m5]
}
resource "aws_eks_access_entry" "operator" {
  count         = local.count
  cluster_name  = aws_eks_cluster.m5[0].name
  principal_arn = var.pins.operator_role_arn
  type          = "STANDARD"
}
resource "aws_eks_access_policy_association" "operator" {
  count         = local.count
  cluster_name  = aws_eks_cluster.m5[0].name
  principal_arn = aws_eks_access_entry.operator[0].principal_arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  access_scope { type = "cluster" }
}

# EKS supplies the pinned release AMI and bootstrap data. No subnet or instance
# profile in the template (both are prohibited by EKS managed-node APIs).
resource "aws_launch_template" "gpu" {
  count         = local.enabled && var.gpu_enabled ? 1 : 0
  name_prefix   = "${var.session_id}-gpu-"
  instance_type = "g6.xlarge"
  capacity_reservation_specification {
    capacity_reservation_preference = "capacity-reservations-only"
    capacity_reservation_target {
      capacity_reservation_resource_group_arn = var.pins.capacity_group_arn
    }
  }
  placement { tenancy = "default" }
  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 200
      volume_type           = "gp3"
      encrypted             = true
      delete_on_termination = true
    }
  }
}
resource "aws_eks_node_group" "gpu" {
  count           = local.enabled && var.gpu_enabled ? 1 : 0
  cluster_name    = aws_eks_cluster.m5[0].name
  node_group_name = "${var.session_id}-gpu"
  node_role_arn   = aws_iam_role.m5["node"].arn
  # Keep the fixed instance reference visible in JSON configuration. A dynamic
  # index or local-only ID hides it. A different key must fail closed, not move
  # the GPU group; AZ alternatives change only var.zones order.
  subnet_ids      = local.gpu_subnet == "0" ? [aws_subnet.m5["0"].id] : []
  capacity_type   = "ON_DEMAND"
  ami_type        = "AL2023_x86_64_NVIDIA"
  version         = var.pins.kubernetes_version
  release_version = var.pins.gpu_release
  scaling_config {
    min_size     = 2
    desired_size = 2
    max_size     = 2
  }
  launch_template {
    id      = aws_launch_template.gpu[0].id
    version = tostring(aws_launch_template.gpu[0].latest_version)
  }
  node_repair_config { enabled = false }
  taint {
    key    = "nvidia.com/gpu"
    value  = "true"
    effect = "NO_SCHEDULE"
  }
  labels     = { "m5-role" = "gpu" }
  depends_on = [aws_route_table_association.m5, aws_eks_access_policy_association.operator, aws_eks_addon.network]
  # Deliberately no create_before_destroy, update strategy, autoscaler or pool.
  # Destroy packet: gpu_enabled=false, only delete the GPU group and template.
  # Then verify every old/conflicting GPU instance is EC2 terminated. Recreate
  # packet: gpu_enabled=true, using exactly the state that destroy leaves behind.
}
resource "aws_eks_node_group" "cpu" {
  count           = local.count
  cluster_name    = aws_eks_cluster.m5[0].name
  node_group_name = "${var.session_id}-cpu"
  node_role_arn   = aws_iam_role.m5["node"].arn
  subnet_ids      = [for s in aws_subnet.m5 : s.id]
  capacity_type   = "ON_DEMAND"
  instance_types  = ["c6i.2xlarge"]
  ami_type        = "AL2023_x86_64_STANDARD"
  version         = var.pins.kubernetes_version
  release_version = var.pins.cpu_release
  disk_size       = 40
  scaling_config {
    min_size     = 2
    desired_size = 2
    max_size     = 2
  }
  node_repair_config { enabled = false }
  labels     = { "m5-role" = "cpu" }
  depends_on = [aws_route_table_association.m5, aws_eks_access_policy_association.operator, aws_eks_addon.network]
}
resource "aws_ecr_repository" "m5" {
  count                = local.count
  name                 = var.session_id
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false
  encryption_configuration { encryption_type = "AES256" }
  image_scanning_configuration { scan_on_push = true }
}
output "repository_url" { value = try(aws_ecr_repository.m5[0].repository_url, null) }
output "repository_arn" { value = try(aws_ecr_repository.m5[0].arn, null) }
output "capacity_binding" {
  value = local.enabled && var.gpu_enabled ? {
    group_arn = var.pins.capacity_group_arn, type = "g6.xlarge", zone = aws_subnet.m5[local.gpu_subnet].availability_zone,
    platform  = "Linux/UNIX", tenancy = "default", count = 2
  } : null
}

# Exact versions are refreshed once and committed with request/time/response hashes.
resource "aws_eks_addon" "network" {
  for_each                    = local.enabled ? { for name in ["vpc-cni", "kube-proxy"] : name => local.addon_pins.addons[name] } : {}
  cluster_name                = aws_eks_cluster.m5[0].name
  addon_name                  = each.key
  addon_version               = each.value
  resolve_conflicts_on_create = "NONE"
  resolve_conflicts_on_update = "NONE"
  lifecycle {
    precondition {
      condition     = var.pins.kubernetes_version == local.addon_pins.kubernetes_version
      error_message = "eks:addon_kubernetes_pin"
    }
  }
}
resource "aws_eks_addon" "coredns" {
  count                       = local.count
  cluster_name                = aws_eks_cluster.m5[0].name
  addon_name                  = "coredns"
  addon_version               = local.addon_pins.addons.coredns
  configuration_values        = jsonencode(local.addon_pins.coredns_configuration)
  resolve_conflicts_on_create = "NONE"
  resolve_conflicts_on_update = "NONE"
  depends_on                  = [aws_eks_node_group.cpu]
}
