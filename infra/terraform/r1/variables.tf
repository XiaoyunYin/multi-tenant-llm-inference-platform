variable "aws_region" {
  type    = string
  default = "us-east-1"
  validation {
    condition     = var.aws_region == "us-east-1"
    error_message = "R1 is registered in us-east-1."
  }
}
variable "aws_profile" {
  type    = string
  default = "admin-learning"
}
variable "offline_validation" {
  type    = bool
  default = true
}
variable "enable_paid" {
  type    = bool
  default = false
}
variable "session_id" {
  type    = string
  default = "readiness"
  validation {
    condition     = can(regex("^[a-z0-9-]{1,24}$", var.session_id))
    error_message = "A short lower-case session identifier is required."
  }
}
variable "availability_zone" {
  type    = string
  default = "us-east-1b"
}
variable "gpu_ami" {
  type    = string
  default = ""
}
variable "cpu_ami" {
  type    = string
  default = ""
}
variable "m4_estimate_usd" {
  type    = number
  default = 0
}
