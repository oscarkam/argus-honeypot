output "honeypot_public_ip" {
  description = "Public IPv4 of the honeypot EC2 instance"
  value       = aws_instance.honeypot.public_ip
}

output "honeypot_instance_id" {
  description = "EC2 instance ID for AWS Console reference"
  value       = aws_instance.honeypot.id
}

output "ssh_command_admin" {
  description = "SSH command to reach T-Pot management shell (port 64295, not 22)"
  value       = "ssh -i ~/.ssh/cp2_honeypot_ed25519 -p 64295 ubuntu@${aws_instance.honeypot.public_ip}"
}

output "kibana_dashboard_url" {
  description = "T-Pot Kibana admin dashboard URL (accessible after T-Pot install completes)"
  value       = "https://${aws_instance.honeypot.public_ip}:64297"
}