mock_provider "aws" {}
run "safe_default" {
  command = plan
  assert {
    condition     = length(aws_instance.gpu) == 0 && length(aws_instance.cpu) == 0 && length(aws_vpc.r1) == 0
    error_message = "Safe default must create nothing."
  }
}
run "exact_four_hosts" {
  command = plan
  variables {
    enable_paid        = true
    offline_validation = false
    gpu_ami            = "ami-00000000000000001"
    cpu_ami            = "ami-00000000000000002"
    m4_estimate_usd    = 86.54
  }
  assert {
    condition     = length(aws_instance.gpu) == 2 && length(aws_instance.cpu) == 2 && aws_instance.cpu["generator"].instance_type == "c6i.2xlarge" && aws_instance.gpu["gpu-0"].root_block_device[0].volume_size == 200 && aws_instance.cpu["service"].root_block_device[0].volume_size == 40 && aws_instance.gpu["gpu-0"].capacity_reservation_specification[0].capacity_reservation_preference == "capacity-reservations-only" && aws_instance.gpu["gpu-0"].tenancy == "default"
    error_message = "The admitted plan must retain the four distinct registered roles/storage."
  }
}
run "reject_over_cap" {
  command = plan
  variables {
    enable_paid        = true
    offline_validation = false
    gpu_ami            = "ami-00000000000000001"
    cpu_ami            = "ami-00000000000000002"
    m4_estimate_usd    = 86.55
  }
  expect_failures = [check.paid_gate]
}
