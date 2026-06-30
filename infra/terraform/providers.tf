provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "cp2-honeypot"
      Owner       = "oscar-22064430"
      Environment = "capstone"
      ManagedBy   = "terraform"
    }
  }
}