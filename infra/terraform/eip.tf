# ============================================================
# Elastic IP: persistent public IPv4 across stop/start cycles
# ============================================================
# Without this, an EC2 stop/start (as required to remediate today's
# system status check failure) would rotate the public IP, invalidating
# DNS references, admin bookmarks, and inventory files.
#
# Cost: $0/hour while attached to a running instance.
#       $0.005/hour if detached — avoid detaching.
# ============================================================

resource "aws_eip" "honeypot" {
  domain     = "vpc"
  instance   = aws_instance.honeypot.id
  depends_on = [aws_internet_gateway.honeypot]

  tags = {
    Name = "cp2-honeypot-eip"
  }
}