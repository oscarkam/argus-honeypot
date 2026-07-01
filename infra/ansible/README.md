# CP2 Ansible Playbooks

## Prerequisites

- Ansible controller: WSL2 Ubuntu with Ansible 2.16+
- SSH key: `~/.ssh/cp2_honeypot_ed25519` (private key for EC2 access)
- Network: SSH to EC2 requires **home WiFi or mobile hotspot** — campus WiFi blocks outbound SSH (see docs/PITFALLS.md #4)
- Secrets file: `vars/tpot_secrets.yml` populated (copy from `vars/tpot_secrets.example.yml`)

## Playbooks

### `site.yml` — Connectivity test
Verifies Ansible can reach the honeypot host and gather facts. Fast, no changes made.

## FOR ansible-playbook site.yml
### `install-tpot.yml` — Full T-Pot deployment
Extends filesystem, installs T-Pot HIVE. Takes ~20-40 minutes. Instance reboots at end.

## FOR ansible-playbook install-tpot.yml
## Post-install

After `install-tpot.yml` completes and the instance reboots:
1. Edit `inventory.yml`, change `ansible_port` from 22 to 64295.
2. Verify: `ansible honeypot -m ping`
3. Access Kibana: `https://<public_ip>:64297` (accept self-signed cert warning)

## Troubleshooting

- **UNREACHABLE / banner exchange timeout**: you're on campus WiFi (SSH blocked). Switch to home or hotspot.
- **Permission denied (publickey)**: check `~/.ssh/cp2_honeypot_ed25519` exists and has mode 600.
- **T-Pot install fails**: SSH into the EC2 manually and check `/opt/tpotce/install.log`.