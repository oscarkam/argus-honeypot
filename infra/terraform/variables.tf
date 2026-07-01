variable "aws_region" {
  description = "AWS region for all honeypot infrastructure"
  type        = string
  default     = "ap-southeast-1"
}

variable "instance_type" {
  description = "EC2 instance type for T-Pot host (needs 8GB+ RAM)"
  type        = string
  default     = "t3.large"
}

variable "key_pair_name" {
  description = "Name of the SSH Key Pair already imported to AWS"
  type        = string
  default     = "cp2-honeypot-key"
}

variable "admin_source_ip" {
  description = "Your home/dev IP in CIDR notation (e.g. 1.2.3.4/32) for management plane access"
  type        = string
  # Will be set via terraform.tfvars (which is gitignored) — do not hardcode here
}

variable "root_disk_size_gb" {
  description = "EC2 root volume size in GB (T-Pot HIVE requires 128GB minimum)"
  type        = number
  default     = 128
}