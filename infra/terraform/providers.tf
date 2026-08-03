provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "cp2-honeypot"
      Owner       = "argus-capstone"
      Environment = "capstone"
      ManagedBy   = "terraform"
    }
  }
}