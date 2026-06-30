# ============================================================
# VPC — isolated network for the honeypot deployment
# Implements the "Virtualization Plane" from CP1 Figure 1
# ============================================================
resource "aws_vpc" "honeypot" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "cp2-honeypot-vpc"
  }
}

# ============================================================
# Internet Gateway — allows the honeypot to be reachable from
# the public internet (essential — adversaries cannot find us
# if we're not internet-facing)
# ============================================================
resource "aws_internet_gateway" "honeypot" {
  vpc_id = aws_vpc.honeypot.id

  tags = {
    Name = "cp2-honeypot-igw"
  }
}

# ============================================================
# Public Subnet — where the T-Pot EC2 instance will live
# Single AZ for cost/simplicity (research project, not HA prod)
# ============================================================
resource "aws_subnet" "honeypot_public" {
  vpc_id                  = aws_vpc.honeypot.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "cp2-honeypot-public-subnet"
  }
}

# ============================================================
# Route Table — routes 0.0.0.0/0 traffic from the subnet
# through the Internet Gateway (egress to/from public internet)
# ============================================================
resource "aws_route_table" "honeypot_public" {
  vpc_id = aws_vpc.honeypot.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.honeypot.id
  }

  tags = {
    Name = "cp2-honeypot-public-rt"
  }
}

# ============================================================
# Route Table Association — attach the route table to the subnet
# Without this, the subnet has no routing rules
# ============================================================
resource "aws_route_table_association" "honeypot_public" {
  subnet_id      = aws_subnet.honeypot_public.id
  route_table_id = aws_route_table.honeypot_public.id
}