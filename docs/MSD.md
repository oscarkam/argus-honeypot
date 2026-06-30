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