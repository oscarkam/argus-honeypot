# ============================================================
# IAM: EC2 instance role for AWS Systems Manager Session Manager
# ============================================================
# Enables HTTPS-based shell access to the EC2 instance without SSH.
# Useful when the operator's network blocks port 22 (see PITFALLS.md #4
# — Sunway campus DPI blocks outbound SSH).
#
# After apply, connect from any network via:
#   aws ssm start-session --target <instance-id> --region ap-southeast-1
#
# Requires the SSM Agent already running on the instance. Ubuntu 24.04
# AWS AMIs ship with it enabled by default (verified in EV-DEPLOY earlier).
# ============================================================

resource "aws_iam_role" "honeypot_ssm" {
  name = "cp2-honeypot-ssm-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    Name = "cp2-honeypot-ssm-role"
  }
}

resource "aws_iam_role_policy_attachment" "honeypot_ssm_core" {
  role       = aws_iam_role.honeypot_ssm.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "honeypot" {
  name = "cp2-honeypot-instance-profile"
  role = aws_iam_role.honeypot_ssm.name

  tags = {
    Name = "cp2-honeypot-instance-profile"
  }
}