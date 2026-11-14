mock_provider "aws" {}
variables {
  enable_session     = true
  offline_validation = false
  session_id         = "m5-fixture"
  pins = {
    kubernetes_version = "1.35", gpu_release = "1.35.2-20261001", cpu_release = "1.35.2-20261001",
    capacity_group_arn = "arn:aws:resource-groups:us-east-1:000000000000:group/m5-fixture-capacity",
    operator_role_arn  = "arn:aws:iam::000000000000:role/fixture", operator_cidrs = ["192.0.2.10/32"]
  }
  admission = {
    quota_vcpus     = 8, cumulative_usd = 100, bringup_max_usd = 10,
    measurement_usd = 10, remaining_usd = 40, checkpoint_record = ""
  }
}
run "reject_missing_quota" {
  command = plan
  variables {
    admission = {
      quota_vcpus     = 4, cumulative_usd = 100, bringup_max_usd = 10,
      measurement_usd = 10, remaining_usd = 40, checkpoint_record = ""
    }
  }
  expect_failures = [var.admission]
}
run "reject_total_over_300" {
  command = plan
  variables {
    admission = {
      quota_vcpus     = 8, cumulative_usd = 100, bringup_max_usd = 10,
      measurement_usd = 10, remaining_usd = 180.01, checkpoint_record = ""
    }
  }
  expect_failures = [var.admission]
}
run "reject_bringup_checkpoint_equality_without_decision" {
  command = plan
  variables {
    admission = {
      quota_vcpus     = 8, cumulative_usd = 140, bringup_max_usd = 10,
      measurement_usd = 10, remaining_usd = 40, checkpoint_record = ""
    }
  }
  expect_failures = [var.admission]
}
run "reject_measurement_checkpoint_equality_without_decision" {
  command = plan
  variables {
    admission = {
      quota_vcpus     = 8, cumulative_usd = 130, bringup_max_usd = 10,
      measurement_usd = 10, remaining_usd = 40, checkpoint_record = ""
    }
  }
  expect_failures = [var.admission]
}
run "reject_unbounded_egress_estimate" {
  command = plan
  variables {
    admission = {
      quota_vcpus     = 8, cumulative_usd = 100, bringup_max_usd = 0,
      measurement_usd = 10, remaining_usd = 40, checkpoint_record = ""
    }
  }
  expect_failures = [var.admission]
}
run "reject_reservation_id_instead_of_group" {
  command = plan
  variables {
    pins = {
      kubernetes_version = "1.35", gpu_release = "1.35.2-20261001", cpu_release = "1.35.2-20261001",
      capacity_group_arn = "cr-does-not-exist-at-plan-time",
      operator_role_arn  = "arn:aws:iam::000000000000:role/fixture", operator_cidrs = ["192.0.2.10/32"]
    }
  }
  expect_failures = [var.pins]
}
run "reject_public_admin" {
  command = plan
  variables {
    pins = {
      kubernetes_version = "1.35", gpu_release = "1.35.2-20261001", cpu_release = "1.35.2-20261001",
      capacity_group_arn = "arn:aws:resource-groups:us-east-1:000000000000:group/m5-fixture-capacity",
      operator_role_arn  = "arn:aws:iam::000000000000:role/fixture", operator_cidrs = ["0.0.0.0/0"]
    }
  }
  expect_failures = [var.pins]
}
run "reject_unpinned_release" {
  command = plan
  variables {
    pins = {
      kubernetes_version = "1.35", gpu_release = "latest", cpu_release = "1.35.2-20261001",
      capacity_group_arn = "arn:aws:resource-groups:us-east-1:000000000000:group/m5-fixture-capacity",
      operator_role_arn  = "arn:aws:iam::000000000000:role/fixture", operator_cidrs = ["192.0.2.10/32"]
    }
  }
  expect_failures = [var.pins]
}
run "reject_release_from_different_kubernetes_version" {
  command = plan
  variables {
    pins = {
      kubernetes_version = "1.35", gpu_release = "1.34.2-20261001", cpu_release = "1.35.2-20261001",
      capacity_group_arn = "arn:aws:resource-groups:us-east-1:000000000000:group/m5-fixture-capacity",
      operator_role_arn  = "arn:aws:iam::000000000000:role/fixture", operator_cidrs = ["192.0.2.10/32"]
    }
  }
  expect_failures = [var.pins]
}
