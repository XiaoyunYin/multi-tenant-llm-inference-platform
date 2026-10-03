variable "aws_region" {
  description = "Primary region input for Terraform, PlanPaid preflight and AMI/quota checks; teardown uses hash-bound plan metadata."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$", var.aws_region))
    error_message = "aws_region must be a valid AWS region name."
  }
}

variable "availability_zone" {
  description = "Optional availability zone in aws_region, selected after a capacity check."
  type        = string
  default     = ""

  validation {
    condition     = var.availability_zone == "" || startswith(var.availability_zone, var.aws_region)
    error_message = "The availability zone must be empty or belong to aws_region."
  }
}

variable "instance_type" {
  description = "Reviewed single-GPU pilot shape."
  type        = string
  default     = "g6.xlarge"

  validation {
    condition     = var.instance_type == "g6.xlarge"
    error_message = "Only g6.xlarge is authorized by this readiness record."
  }
}

variable "ami_id" {
  description = "Exact region-specific DLAMI ID resolved and recorded immediately before the paid plan."
  type        = string
  default     = ""

  validation {
    condition     = var.ami_id == "" || can(regex("^ami-[0-9a-f]+$", var.ami_id))
    error_message = "ami_id must be empty for offline validation or an exact lowercase AMI ID."
  }
}

variable "enable_paid_gpu" {
  description = "Requests creation of paid resources; false is the safe default."
  type        = bool
  default     = false
}

variable "offline_validation" {
  description = "Skips AWS identity calls only for the zero-resource offline plan. Must be false for paid work."
  type        = bool
  default     = true
}

variable "budget_authorization_id" {
  description = "Repository decision/review identifier recording the user's approved cap."
  type        = string
  default     = ""
}

variable "approved_phase_cap_usd" {
  description = "Explicitly user-approved maximum spend for this paid phase."
  type        = number
  default     = 0

  validation {
    condition     = var.approved_phase_cap_usd >= 0
    error_message = "The approved phase cap cannot be negative."
  }
}

variable "estimated_max_session_cost_usd" {
  description = "Pre-launch maximum cost estimate, including expected network/storage overhead."
  type        = number
  default     = 0

  validation {
    condition     = var.estimated_max_session_cost_usd >= 0
    error_message = "The estimated maximum session cost cannot be negative."
  }
}

variable "max_session_hours" {
  description = "Automatic instance-termination deadline from first boot."
  type        = number
  default     = 4

  validation {
    condition     = var.max_session_hours > 0 && var.max_session_hours <= 4 && floor(var.max_session_hours) == var.max_session_hours
    error_message = "The INF-011 session must be a whole number of hours between one and four."
  }
}

variable "root_volume_gib" {
  description = "Encrypted gp3 root volume for the container and public model cache."
  type        = number
  default     = 100

  validation {
    condition     = var.root_volume_gib >= 80 && var.root_volume_gib <= 120
    error_message = "The reviewed pilot root volume must stay between 80 and 120 GiB."
  }
}
