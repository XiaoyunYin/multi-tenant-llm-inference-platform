mock_provider "aws" {}

run "offline_plan_creates_nothing" {
  command = plan

  assert {
    condition     = output.paid_gate_open == false
    error_message = "The default plan must keep the paid gate closed."
  }

  assert {
    condition     = output.pilot_region == "us-east-1"
    error_message = "The default plan region must match the approved primary region."
  }

  assert {
    condition     = length(aws_instance.pilot) == 0
    error_message = "The default plan must contain no EC2 instance."
  }

  assert {
    condition     = length(aws_vpc.pilot) == 0
    error_message = "The default plan must contain no network resources."
  }
}

run "explicit_region_is_recorded" {
  command = plan

  variables {
    aws_region = "us-west-1"
  }

  assert {
    condition     = output.pilot_region == "us-west-1"
    error_message = "The selected aws_region must appear in the plan metadata output."
  }
}

run "enable_without_authorization_fails" {
  command = plan

  variables {
    enable_paid_gpu = true
  }

  expect_failures = [check.paid_resource_gate]
}

run "fully_authorized_mock_apply_is_one_bounded_host" {
  command = apply

  variables {
    enable_paid_gpu                = true
    offline_validation             = false
    budget_authorization_id        = "DEC-TEST"
    approved_phase_cap_usd         = 5
    estimated_max_session_cost_usd = 4.19
    ami_id                         = "ami-0123456789abcdef0"
  }

  assert {
    condition     = output.paid_gate_open == true
    error_message = "Complete authorization inputs must open the Terraform gate."
  }

  assert {
    condition     = length(aws_instance.pilot) == 1 && aws_instance.pilot[0].instance_type == "g6.xlarge"
    error_message = "The reviewed gate must create exactly one g6.xlarge host."
  }

  assert {
    condition     = aws_instance.pilot[0].timeouts.create == "10m"
    error_message = "Capacity-rejected instance creation must be bounded to ten minutes."
  }

  assert {
    condition     = aws_instance.pilot[0].instance_initiated_shutdown_behavior == "terminate"
    error_message = "The instance must terminate when the boot deadline shuts it down."
  }

  assert {
    condition     = length(aws_security_group.pilot[0].ingress) == 0
    error_message = "The pilot security group must expose no ingress."
  }

  assert {
    condition     = strcontains(aws_instance.pilot[0].user_data, "inf011-terminate.timer")
    error_message = "User data must install the automatic termination timer."
  }

  assert {
    condition     = strcontains(aws_instance.pilot[0].user_data, "cat >/etc/systemd/system/inf011-terminate.timer <<UNIT") && strcontains(aws_instance.pilot[0].user_data, "OnCalendar=@") && strcontains(aws_instance.pilot[0].user_data, "deadline_epoch")
    error_message = "User data must expand and schedule the persisted absolute deadline through an unquoted timer heredoc."
  }

  assert {
    condition     = strcontains(aws_instance.pilot[0].user_data, "systemd-analyze verify /etc/systemd/system/inf011-terminate.timer") && strcontains(aws_instance.pilot[0].user_data, "systemctl is-active --quiet inf011-terminate.timer") && strcontains(aws_instance.pilot[0].user_data, "NextElapseUSecRealtime")
    error_message = "User data must fail closed when the termination timer is invalid or has no next elapse."
  }

  assert {
    condition     = strcontains(aws_instance.pilot[0].user_data, "sha256:082ca6f035279109041ffd3fe0695cb568b29bc580b35c4f297a66a08b216c1b")
    error_message = "User data must use the pinned linux/amd64 runtime image."
  }

  assert {
    condition     = strcontains(aws_instance.pilot[0].user_data, "--kv-events-config '{\"enable_kv_cache_events\":true,\"publisher\":\"zmq\",\"endpoint\":\"tcp://*:5557\",\"topic\":\"kv-events\"}'") && !strcontains(aws_instance.pilot[0].user_data, "5557:5557")
    error_message = "Stage C requires the binding ZMQ publisher inside the container, without a published event port."
  }

  assert {
    condition     = can(regex("\\*|::|^(ipc|inproc)://", jsondecode(regex("--kv-events-config '([^']+)'", aws_instance.pilot[0].user_data)[0]).endpoint)) && jsondecode(file("../../../docs/INF011_STAGE_C_SESSION_INPUTS.json")).kv_events.capture_endpoint == "tcp://127.0.0.1:5557" && jsondecode(file("../../../docs/INF011_STAGE_C_SESSION_INPUTS.json")).kv_events.capture_operation == "connect" && strcontains(file("../../../python/src/inference_platform/kv_event_capture.py"), "subscriber.connect(endpoint)") && !strcontains(file("../../../python/src/inference_platform/kv_event_capture.py"), "subscriber.bind(")
    error_message = "The planned publisher endpoint must select v0.29.0 bind semantics; the same-container capture must connect to loopback."
  }

  assert {
    condition     = strcontains(aws_instance.pilot[0].user_data, "sha256:60d3b00ac80b4ae77f94dae2f943685605585ad9e92fdccda3154d009ae317cc") && strcontains(aws_instance.pilot[0].user_data, "127.0.0.1:9400:9400") && strcontains(aws_instance.pilot[0].user_data, "inf011-dcgm-exporter.service")
    error_message = "User data must run the pinned loopback-only DCGM Exporter service."
  }
}

run "fractional_session_duration_rejected" {
  command = plan

  variables {
    max_session_hours = 3.5
  }

  expect_failures = [var.max_session_hours]
}
