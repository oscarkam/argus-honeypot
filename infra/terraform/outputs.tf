output "honeypot_public_ip" {
  description = "Persistent public IPv4 of the honeypot (Elastic IP)"
  value       = aws_eip.honeypot.public_ip
}

output "honeypot_instance_id" {
  description = "EC2 instance ID for AWS Console reference"
  value       = aws_instance.honeypot.id
}

output "ssh_command_admin" {
  description = "SSH to T-Pot management shell (post-install port 64295)"
  value       = "ssh -i ~/.ssh/cp2_honeypot_ed25519 -p 64295 ubuntu@${aws_eip.honeypot.public_ip}"
}

output "kibana_dashboard_url" {
  description = "T-Pot Kibana admin dashboard URL"
  value       = "https://${aws_eip.honeypot.public_ip}:64297"
}

output "ssm_session_command" {
  description = "AWS SSM Session Manager command for HTTPS-based shell access (bypasses campus SSH block)"
  value       = "aws ssm start-session --target ${aws_instance.honeypot.id} --region ap-southeast-1"
}