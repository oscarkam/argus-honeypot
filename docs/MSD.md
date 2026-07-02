# Master State Document (MSD)

> Single source of truth for project state. Updated after every meaningful phase exit.

## Project Identity

- **Project**: Automated Low-Interaction Honeypot with Threat Intelligence Visualization
- **Author**: Oscar Kam Gen Jynn (22064430)
- **Supervisor**: Associate Professor Dr. Morteza SaberiKamarposhti
- **Repo**: github.com/oscarkam/cp2-honeypot-iac (private)
- **Submission target**: 30 July 2026 (1 day buffer before 31 July deadline)
- **Viva**: 10–14 August 2026

## Cloud Infrastructure (AWS)

- **Account ID**: 12393612**** (full ID held separately, not committed to repo)
- **Account email**: aosikakam@gmail.com (capstone-dedicated)
- **Region**: ap-southeast-1 (Singapore)
- **Plan**: Paid (pay-as-you-go, no free credits — see Pitfall #1 context in proposal pivot)
- **Budget alarms**: $5 warning (25%), $17 hard cap (85%); alerts to oscarkam01@gmail.com + aosikakam@gmail.com
- **IAM user (Terraform)**: `terraform-cp2`
  - Policies: `AmazonEC2FullAccess`, `AmazonVPCFullAccess` (scoped — NOT AdministratorAccess)
  - Access keys: rotated once on 19 Jun (see PITFALLS.md #1)
- **Root account MFA**: pending Saturday setup

## Local Development Environment

- **Host OS**: Windows 11 Pro
- **Dev shell**: WSL2 Ubuntu 24.04 LTS (`/home/oscar`)
- **Editor**: VS Code with WSL Remote extension
- **Installed and verified (19 Jun)**:
  - Ansible 2.16.3
  - Git 2.43.0
  - Python 3.12.3
  - gh CLI 2.45.0 (authenticated to github.com/oscarkam)
  - AWS CLI 2.35.8 (configured with terraform-cp2 IAM user, ap-southeast-1 default)
  - Terraform 1.15.6 (via HashiCorp official apt repo)

## Current Phase

**Phase 0 RESCUE — Weekend Crash Foundation** (Day 1 of 2 complete)

### Day 1 (19 Jun 2026) outcomes
- AWS account created on dedicated Gmail; paid plan accepted after free-plan ineligibility detected
- Cost guardrails live: AWS Budgets at $5 / $17 with dual-channel email alerts
- WSL2 Ubuntu 24.04 LTS installed alongside existing Kali (Kali retained for unrelated coursework)
- Full local toolchain: Ansible, Git, Python, gh, AWS CLI v2, Terraform v1.15.6
- GitHub repo `cp2-honeypot-iac` scaffolded with docs/infra/elk/analyzer/reports structure
- First commits pushed with privacy-safe noreply email
- IAM user `terraform-cp2` created with scoped EC2+VPC permissions
- Security incident response executed: accidental access key exposure detected, key rotated within 5 minutes

### Day 2 (Saturday) — open items
- [ ] Ollama install + llama3.2:3b model download (~30 min)
- [ ] First weekly logbook entry in Word doc (~15 min) — covering Day 1 decisions + pitfall response
- [ ] Root account MFA setup (~5 min)
- [ ] Send supervisor email follow-up if reply received

### Day 2 (20 Jun 2026) outcomes
- Ollama 0.30.10 installed on Windows; llama3.2:3b model pulled (2.0 GB) and smoke-tested for coherent output
- AWS root account secured with TOTP MFA via Google Authenticator
- First weekly logbook entry written and saved (Word + markdown mirror in `docs/LOGBOOK.md`)
- SSH key pair `cp2_honeypot_ed25519` generated; public key imported to AWS as Key Pair `cp2-honeypot-key` in ap-southeast-1

**Phase 0 RESCUE: COMPLETE.** All foundation, tooling, security, and documentation prerequisites in place for Phase 1 (Break Week Mega-Sprint) starting Monday 22 June.

## Phase Log

| Date | Phase | Status | Notes |
|---|---|---|---|
| 19 Jun 2026 | Phase 0 RESCUE Day 1 | Completed | Foundation + cloud account + repo + full local toolchain |

- **Live infrastructure (as of 1 Jul 2026)**:
  - VPC: `vpc-0b231bdebdfde3f8f`
  - Subnet: `subnet-0cb7aac0f1a5c68e3` (10.0.1.0/24, ap-southeast-1a)
  - Security Group: `sg-06147f343a89ca0ee`
  - EC2 Instance: `i-02c73e226b225ce3e` (t3.large, Ubuntu 24.04.4 LTS)
  - Public IP: `47.129.9.195`
  - Internal IP: `10.0.1.237`
  - Kibana URL (post-install): `https://47.129.9.195:64297`

  **Phase 1: Build Sprint** (in progress)

### Day 1 (1 Jul 2026) outcomes
- Complete Terraform config authored (network.tf, security.tf, compute.tf, outputs.tf)
- First `terraform apply` succeeded — 7 AWS resources provisioned in 40 seconds
- SSH connectivity to EC2 verified via mobile hotspot (campus network SSH block documented as Pitfall #4)
- Instance vitals confirmed: 7.6 GiB RAM, 30 GB disk, egress working

**Phase 2: Analyser + Dashboard + Live Capture** (in progress)

### Day 1 (1 Jul 2026) outcomes (both Phase 1 and Phase 2)

**Phase 1 completed today**:
- Terraform authored, applied, and re-applied for 128GB disk resize (7 AWS resources live)
- SSH connectivity verified via mobile hotspot; campus DPI SSH block documented (Pitfall #4)
- Ansible controller config, inventory, connectivity playbook — all authored and syntax-validated
- T-Pot install playbook (`install-tpot.yml`) fully authored covering filesystem resize, system prep, T-Pot clone, non-interactive install, post-install guidance
- Secrets scaffolding via example-and-real pattern with `.gitignore` protection

**Phase 2 started today**:
- Python analyser scaffold (`analyzer/`) with venv + requirements
- WSL2→Windows Ollama bridge diagnosed and fixed (Pitfall #6)
- End-to-end Python→Ollama chain proven working (`llama3.2:3b` responded coherently to CP-relevant prompt)
- Two idempotent ops scripts authored: `refresh-admin-ip.sh` (targeted SG update) and `refresh-ollama-host.sh` (analyzer config sync)

### Outstanding for tonight (home network required)
- [x] `ansible honeypot -m ping` — verify connectivity
- [x] `ansible-playbook install-tpot.yml` — deploy T-Pot (~20-40 min)
- [ ] Post-reboot: update `inventory.yml` port 22 → 64295
- [ ] Verify Kibana at `https://47.129.9.195:64297`
- [ ] Screenshot Kibana as viva artifact