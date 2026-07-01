# CP2 Ops Helper Scripts

Session-startup scripts that reconcile dynamic IPs (yours and Windows-host) with the checked-in configuration files, so you never have to hand-edit them again.

## `refresh-admin-ip.sh`

**Purpose**: Detect your machine's current public IP, update `infra/terraform/terraform.tfvars`, and apply a targeted security-group refresh so T-Pot admin access matches your current network. 

**When to run**:
- Start of each work session (in case your home IP changed overnight) 
- Right before a presentation, from the venue's WiFi
- After you notice `ssh -p 64295 ubuntu@<tpot_ip>` timing out

**What it changes**: Only `aws_security_group.honeypot` (via `terraform apply -target`). Takes ~10 seconds AWS-side.

## `refresh-ollama-host.sh`

**Purpose**: Detect the Windows host IP as seen from WSL2, update `analyzer/config.yml`, and verify Ollama is reachable on the new address.

**When to run**:
- Start of a WSL2 session after a Windows reboot or `wsl --shutdown`
- After `python analyzer.py --test-ollama` fails with "Connection refused"

**What it changes**: The `ollama.base_url` line in `analyzer/config.yml`. No infrastructure impact.

**Requires**: Ollama on Windows configured with `OLLAMA_HOST=0.0.0.0` (persistent user env var). See project MSD for setup.

## Both scripts

- Are idempotent — if nothing needs changing, they exit cleanly saying so.
- Are safe to run repeatedly.
- Do not require sudo.
- Print what they're about to change before doing it.