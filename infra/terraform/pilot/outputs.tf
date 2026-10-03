output "paid_gate_open" {
  description = "Whether all Terraform-side paid-resource gates are satisfied."
  value       = local.paid_gate_open
}

output "pilot_region" {
  description = "Region selected for this exact Terraform plan and corresponding wrapper checks."
  value       = var.aws_region
}

output "pilot_instance_id" {
  description = "Instance ID used with SSM; null for the safe offline plan."
  value       = local.paid_gate_open ? aws_instance.pilot[0].id : null
}

output "resolved_dlami_id" {
  description = "Exact region-specific DLAMI supplied to the reviewed paid plan."
  value       = local.paid_gate_open ? var.ami_id : null
}

output "automatic_termination_hours" {
  description = "Boot-relative termination bound installed by cloud-init."
  value       = var.max_session_hours
}

output "runtime_image" {
  description = "Pinned linux/amd64 vLLM image used by the pilot service."
  value       = "docker.io/vllm/vllm-openai@sha256:082ca6f035279109041ffd3fe0695cb568b29bc580b35c4f297a66a08b216c1b"
}

output "gpu_metrics_image" {
  description = "Pinned multi-platform DCGM Exporter image used by the pilot service."
  value       = "nvcr.io/nvidia/k8s/dcgm-exporter@sha256:60d3b00ac80b4ae77f94dae2f943685605585ad9e92fdccda3154d009ae317cc"
}
