mock_provider "aws" {}
run "default_zero_resources" {
  command = plan
  assert {
    condition = alltrue([
      length(terraform_data.gate) == 0, length(aws_vpc.m5) == 0,
      length(aws_internet_gateway.m5) == 0, length(aws_subnet.m5) == 0,
      length(aws_route_table.m5) == 0, length(aws_route_table_association.m5) == 0,
      length(aws_iam_role.m5) == 0, length(aws_iam_role_policy_attachment.m5) == 0,
      length(aws_cloudwatch_log_group.m5) == 0, length(aws_eks_cluster.m5) == 0,
      length(aws_eks_access_entry.operator) == 0, length(aws_eks_access_policy_association.operator) == 0,
      length(aws_launch_template.gpu) == 0, length(aws_eks_node_group.gpu) == 0,
      length(aws_eks_node_group.cpu) == 0, length(aws_ecr_repository.m5) == 0
    ])
    error_message = "Default creates zero resources, including persistent services."
  }
}
run "reviewed_group_binding_and_fixed_nodes" {
  command = plan
  variables {
    enable_session     = true
    offline_validation = false
    session_id         = "m5-fixture"
    pins = {
      kubernetes_version = "1.35"
      gpu_release        = "1.35.2-20261001"
      cpu_release        = "1.35.2-20261001"
      capacity_group_arn = "arn:aws:resource-groups:us-east-1:000000000000:group/m5-fixture-capacity"
      operator_role_arn  = "arn:aws:iam::000000000000:role/fixture"
      operator_cidrs     = ["192.0.2.10/32"]
    }
    admission = {
      quota_vcpus     = 8, cumulative_usd = 100, bringup_max_usd = 10,
      measurement_usd = 10, remaining_usd = 40, checkpoint_record = ""
    }
  }
  assert {
    condition     = output.capacity_binding.zone == aws_subnet.m5["0"].availability_zone
    error_message = "The capacity output zone must equal the GPU subnet's planned AZ."
  }
  assert {
    condition     = aws_launch_template.gpu[0].capacity_reservation_specification[0].capacity_reservation_target[0].capacity_reservation_id == null && aws_launch_template.gpu[0].capacity_reservation_specification[0].capacity_reservation_target[0].capacity_reservation_resource_group_arn == var.pins.capacity_group_arn && aws_launch_template.gpu[0].capacity_reservation_specification[0].capacity_reservation_preference == "capacity-reservations-only" && !strcontains(jsonencode(aws_launch_template.gpu[0].capacity_reservation_specification), "cr-")
    error_message = "Saved-plan values must bind only the preexisting group ARN, with no reservation-ID literal or fallback."
  }
  assert {
    condition     = length(aws_eks_node_group.gpu[0].warm_pool_config) == 0 && length(aws_eks_node_group.gpu[0].update_config) == 0
    error_message = "No warm pool or GPU node-update configuration is allowed; updates are refused by the offline controller model."
  }
  assert {
    condition     = length(aws_eks_node_group.gpu) == 1 && aws_eks_node_group.gpu[0].scaling_config[0].min_size == 2 && aws_eks_node_group.gpu[0].scaling_config[0].desired_size == 2 && aws_eks_node_group.gpu[0].scaling_config[0].max_size == 2 && aws_eks_node_group.gpu[0].capacity_type == "ON_DEMAND" && aws_launch_template.gpu[0].instance_type == "g6.xlarge" && !aws_eks_node_group.gpu[0].node_repair_config[0].enabled && length(aws_eks_node_group.gpu[0].subnet_ids) == 1 && var.gpu_change_path == "destroy-recreate"
    error_message = "Two fixed On-Demand GPUs, one AZ, no automatic node repair or update path."
  }
  assert {
    condition     = aws_eks_node_group.cpu[0].scaling_config[0].max_size == 2 && aws_eks_node_group.cpu[0].instance_types[0] == "c6i.2xlarge" && length(aws_subnet.m5) == 2 && aws_launch_template.gpu[0].block_device_mappings[0].ebs[0].volume_size == 200 && aws_eks_node_group.cpu[0].disk_size == 40 && aws_eks_cluster.m5[0].vpc_config[0].public_access_cidrs == toset(["192.0.2.10/32"])
    error_message = "CPU/storage/network footprint must stay bounded and operator access restricted."
  }
}
run "reviewed_alternative_zone" {
  command = plan
  variables {
    enable_session     = true
    offline_validation = false
    session_id         = "m5-fixture"
    zones              = ["us-east-1b", "us-east-1a"]
    pins = {
      kubernetes_version = "1.35"
      gpu_release        = "1.35.2-20261001"
      cpu_release        = "1.35.2-20261001"
      capacity_group_arn = "arn:aws:resource-groups:us-east-1:000000000000:group/m5-fixture-capacity"
      operator_role_arn  = "arn:aws:iam::000000000000:role/fixture"
      operator_cidrs     = ["192.0.2.10/32"]
    }
    admission = {
      quota_vcpus     = 8, cumulative_usd = 100, bringup_max_usd = 10,
      measurement_usd = 10, remaining_usd = 40, checkpoint_record = ""
    }
  }
  assert {
    condition     = output.capacity_binding.zone == "us-east-1b" && output.capacity_binding.zone == aws_subnet.m5["0"].availability_zone
    error_message = "AZ alternatives must bind the output and GPU nodes to the first planned subnet."
  }
}
run "gpu_disabled_retains_session" {
  command = plan
  variables {
    gpu_enabled        = false
    enable_session     = true
    offline_validation = false
    session_id         = "m5-fixture"
    pins = {
      kubernetes_version = "1.35"
      gpu_release        = "1.35.2-20261001"
      cpu_release        = "1.35.2-20261001"
      capacity_group_arn = "arn:aws:resource-groups:us-east-1:000000000000:group/m5-fixture-capacity"
      operator_role_arn  = "arn:aws:iam::000000000000:role/fixture"
      operator_cidrs     = ["192.0.2.10/32"]
    }
    admission = {
      quota_vcpus     = 8, cumulative_usd = 100, bringup_max_usd = 10,
      measurement_usd = 10, remaining_usd = 40, checkpoint_record = ""
    }
  }
  assert {
    condition = alltrue([
      length(aws_launch_template.gpu) == 0, length(aws_eks_node_group.gpu) == 0,
      output.capacity_binding == null,
      length(terraform_data.gate) == 1, length(aws_vpc.m5) == 1,
      length(aws_internet_gateway.m5) == 1, length(aws_subnet.m5) == 2,
      length(aws_route_table.m5) == 1, length(aws_route_table_association.m5) == 2,
      length(aws_iam_role.m5) == 2, length(aws_iam_role_policy_attachment.m5) == 5,
      length(aws_cloudwatch_log_group.m5) == 1, length(aws_eks_cluster.m5) == 1,
      length(aws_eks_access_entry.operator) == 1, length(aws_eks_access_policy_association.operator) == 1,
      length(aws_eks_node_group.cpu) == 1, length(aws_ecr_repository.m5) == 1
    ])
    error_message = "gpu_enabled=false removes only GPU group/template and binding, retaining every other session resource."
  }
}
run "reject_region" {
  command = plan
  variables { aws_region = "us-west-2" }
  expect_failures = [var.aws_region]
}
run "reject_single_zone" {
  command = plan
  variables { zones = ["us-east-1a", "us-east-1a"] }
  expect_failures = [var.zones]
}
run "reject_missing_pins_and_estimates" {
  command = plan
  variables { enable_session = true }
  expect_failures = [var.pins, var.admission, terraform_data.gate]
}
run "reject_gpu_update" {
  command = plan
  variables { gpu_change_path = "MINIMAL" }
  expect_failures = [var.gpu_change_path]
}
