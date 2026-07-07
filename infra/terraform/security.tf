# ============================================================
# Security Group — network firewall for the T-Pot host
# Implements the layered access model from CP1 Section 3.1:
#   - Management ports: restricted to admin IP only (Management Plane)
#   - Honeypot decoy ports: open to public internet (Deception Plane)
#   - Egress: currently broad; will be tightened in Phase 1b iteration
#     (implements "black-hole" egress policy from CP1 Section 3.5.1)
# ============================================================
resource "aws_security_group" "honeypot" {
  name        = "cp2-honeypot-sg"
  description = "T-Pot honeypot SG: management restricted, decoys public, egress broad initially"
  vpc_id      = aws_vpc.honeypot.id

  # ---------- MANAGEMENT PLANE (admin IP only) ----------
  ingress {
    description = "T-Pot SSH management port"
    from_port   = 64295
    to_port     = 64295
    protocol    = "tcp"
    cidr_blocks = [var.admin_source_ip]
  }

  ingress {
    description = "T-Pot Kibana admin dashboard (HTTPS)"
    from_port   = 64297
    to_port     = 64297
    protocol    = "tcp"
    cidr_blocks = [var.admin_source_ip]
  }

  ingress {
    description = "T-Pot Cockpit (system management)"
    from_port   = 64294
    to_port     = 64294
    protocol    = "tcp"
    cidr_blocks = [var.admin_source_ip]
  }

  # ---------- DECEPTION PLANE (public — adversary-facing) ----------
  ingress {
    description = "SSH honeypot (Cowrie)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Telnet honeypot (Cowrie)"
    from_port   = 23
    to_port     = 23
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP honeypot"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS honeypot"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SMB honeypot (Dionaea)"
    from_port   = 445
    to_port     = 445
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "MySQL honeypot"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # ---------- EGRESS ----------
  # TODO Phase 1b: tighten to DNS(53), HTTPS(443), NTP(123) only
  # to fully implement the "black-hole" policy from CP1 Section 3.5.1
  egress {
    description = "All outbound (initial permissive config for T-Pot install; to be restricted after install completes)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "cp2-honeypot-sg"
  }
}