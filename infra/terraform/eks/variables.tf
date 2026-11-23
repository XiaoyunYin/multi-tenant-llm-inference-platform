variable "enable_session" {
  type    = bool
  default = false
}
variable "gpu_enabled" {
  description = "GPU-only destroy/recreate toggle; leaves all other session resources enabled."
  type        = bool
  default     = true
}
variable "cpu_clock_rehearsal" {
  type    = bool
  default = false
}
variable "offline_validation" {
  type    = bool
  default = true
}
variable "aws_region" {
  type    = string
  default = "us-east-1"
  validation {
    condition     = var.aws_region == "us-east-1"
    error_message = "M5 is pinned to us-east-1."
  }
}
variable "session_id" {
  type    = string
  default = "m5-offline"
  validation {
    condition     = can(regex("^m5-[a-z0-9-]{1,24}$", var.session_id))
    error_message = "Use a bounded M5 session name."
  }
}
variable "zones" {
  type    = list(string)
  default = ["us-east-1a", "us-east-1b"]
  validation {
    condition     = length(var.zones) == 2 && length(distinct(var.zones)) == 2 && alltrue([for z in var.zones : can(regex("^us-east-1[a-f]$", z))])
    error_message = "Exactly two distinct primary-region AZs are required; GPU uses the first reviewed AZ."
  }
}
variable "pins" {
  type = object({
    kubernetes_version = string
    gpu_release        = string
    cpu_release        = string
    capacity_group_arn = string
    operator_role_arn  = string
    operator_cidrs     = list(string)
  })
  default = {
    kubernetes_version = "", gpu_release = "", cpu_release = "",
    capacity_group_arn = "", operator_role_arn = "", operator_cidrs = []
  }
  validation {
    condition = !var.enable_session || (
      can(regex("^1\\.[0-9]+$", var.pins.kubernetes_version)) &&
      (var.cpu_clock_rehearsal || can(regex("^1\\.[0-9]+\\.[0-9]+-[0-9]{8}$", var.pins.gpu_release))) &&
      can(regex("^1\\.[0-9]+\\.[0-9]+-[0-9]{8}$", var.pins.cpu_release)) &&
      (var.cpu_clock_rehearsal || startswith(var.pins.gpu_release, "${var.pins.kubernetes_version}.")) &&
      startswith(var.pins.cpu_release, "${var.pins.kubernetes_version}.") &&
      can(regex("^arn:aws:resource-groups:us-east-1:[0-9]{12}:group/${var.session_id}-capacity$", var.pins.capacity_group_arn)) &&
      can(regex("^arn:aws:iam::[0-9]{12}:role/.+$", var.pins.operator_role_arn)) &&
      length(var.pins.operator_cidrs) > 0 &&
      alltrue([for c in var.pins.operator_cidrs : can(cidrnetmask(c)) && try(tonumber(split("/", c)[1]) >= 24, false)])
    )
    error_message = "Enabled session needs exact matching EKS/AMI releases, reviewed session group ARN, operator role and restricted IPv4 CIDRs (/24 or narrower)."
  }
}
variable "admission" {
  type = object({
    quota_vcpus       = number
    cumulative_usd    = number
    bringup_max_usd   = number
    measurement_usd   = number
    remaining_usd     = number
    checkpoint_record = string
  })
  default = { quota_vcpus = 0, cumulative_usd = 0, bringup_max_usd = 0, measurement_usd = 0, remaining_usd = 0, checkpoint_record = "" }
  validation {
    condition = !var.enable_session || (
      var.admission.quota_vcpus >= (var.cpu_clock_rehearsal ? 32 : 8) &&
      var.admission.cumulative_usd >= 0 && var.admission.bringup_max_usd > 0 &&
      var.admission.measurement_usd > 0 && var.admission.remaining_usd > 0 &&
      var.admission.cumulative_usd + var.admission.bringup_max_usd + var.admission.measurement_usd + var.admission.remaining_usd <= 300 &&
      (var.admission.cumulative_usd + var.admission.bringup_max_usd < 150 &&
        var.admission.cumulative_usd + var.admission.bringup_max_usd + var.admission.measurement_usd < 150 ||
      can(regex("^DEC-[0-9]{3}:.+$", var.admission.checkpoint_record)))
    )
    error_message = "Need session vCPU quota, complete positive session/remainder estimates within $300, and a recorded decision if either cumulative session maximum reaches $150. This input is not approval."
  }
}
variable "gpu_change_path" {
  type    = string
  default = "destroy-recreate"
  validation {
    condition     = var.gpu_change_path == "destroy-recreate"
    error_message = "GPU updates/MINIMAL are refused; destroy, verify every instance terminated, then recreate."
  }
}
