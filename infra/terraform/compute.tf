# ============================================================
# Data source: Latest Ubuntu 24.04 LTS AMI (Canonical official)
# Using a data source instead of a hardcoded AMI ID means our
# deployment automatically picks up the latest patched image
# every time we run terraform apply — better security posture
# ============================================================
data "aws_ami" "ubuntu_24_04" {
  most_recent = true
  owners      = ["099720109477"] # Canonical's official AWS account ID

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ============================================================
# EC2 Instance — the T-Pot honeypot host
# Instance type from variables.tf (default: t3.large — 2 vCPU, 8GB RAM)
# meets T-Pot CE 24.04 minimum requirements (8GB RAM for ELK stack)
# ============================================================
resource "aws_instance" "honeypot" {
  ami                    = data.aws_ami.ubuntu_24_04.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.honeypot_public.id
  vpc_security_group_ids = [aws_security_group.honeypot.id]
  key_name               = var.key_pair_name

  # T-Pot needs disk headroom for indexed logs + captured artifacts
  # 32GB gp3 = ~$2.56/month while running; sufficient for a 5-day capture window
  root_block_device {
    volume_size = var.root_disk_size_gb
    volume_type = "gp3"
    encrypted   = true

    tags = {
      Name = "cp2-honeypot-root-volume"
    }
  }

  # Enforce instance metadata service v2 (IMDSv2) — protects against
  # SSRF-style token theft that plagued IMDSv1
  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  tags = {
    Name = "cp2-honeypot-instance"
  }
}