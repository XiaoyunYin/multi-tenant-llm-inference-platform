mock_provider "aws" {}
run "default_empty" {
  command = plan
  assert {
    condition     = length(aws_resourcegroups_group.capacity) == 0 && length(aws_s3_bucket.state) == 0 && length(terraform_data.gate) == 0
    error_message = "Bootstrap default must create no group, backend or gate."
  }
}
run "explicit_bootstrap" {
  command = plan
  variables {
    enable_bootstrap   = true
    offline_validation = false
    name               = "m5-fixture"
    state_bucket       = "m5-fixture-state-only"
  }
  assert {
    condition     = length(aws_resourcegroups_group.capacity) == 1 && length(aws_resourcegroups_group.capacity[0].configuration) == 2 && !aws_s3_bucket.state[0].force_destroy && aws_s3_bucket_versioning.state[0].versioning_configuration[0].status == "Enabled" && aws_s3_bucket_server_side_encryption_configuration.state[0].rule != null && aws_s3_bucket_public_access_block.state[0].restrict_public_buckets && output.session_backend.use_lockfile
    error_message = "Group and encrypted/versioned/private locked state must have explicit ownership."
  }
}
run "reject_missing_bucket" {
  command = plan
  variables { enable_bootstrap = true }
  expect_failures = [var.state_bucket, terraform_data.gate]
}
