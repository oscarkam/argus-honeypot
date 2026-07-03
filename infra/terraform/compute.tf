# ============================================================
# Data source: Latest Ubuntu 24.04 LTS AMI (Canonical official)
# ============================================================
data "aws_ami" "ubuntu_24_04" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

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
# ============================================================
resource "aws_instance" "honeypot" {
  ami                    = data.aws_ami.ubuntu_24_04.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.honeypot_public.id
  vpc_security_group_ids = [aws_security_group.honeypot.id]
  key_name               = var.key_pair_name
  iam_instance_profile   = aws_iam_instance_profile.honeypot.name

  root_block_device {
    volume_size = var.root_disk_size_gb
    volume_type = "gp3"
    encrypted   = true

    tags = {
      Name = "cp2-honeypot-root-volume"
    }
  }

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  tags = {
    Name = "cp2-honeypot-instance"
  }
}