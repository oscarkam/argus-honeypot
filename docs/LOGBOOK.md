====================================================================

Capstone Project 2 — Weekly Logbook

Student: Oscar Kam Gen Jynn (22064430)
Project: Automated Low-Interaction Honeypot with Threat Intelligence Visualization
Supervisor: Associate Professor Dr. Morteza SaberiKamarposhti
School of Computing and Artificial Intelligence, Sunway University
Repository: github.com/oscarkam/cp2-honeypot-iac (private)

====================================================================

Week 1 (15–21 June 2026): CP2 Execution Phase Kickoff

Summary

This week marked the formal start of CP2 execution. Active capstone development began on 19 June following finalisation of a compressed 6-week strategic plan running to the 30 July 2026 submission target. Foundation infrastructure was established (cloud account, version control, local development toolchain), and several architectural decisions made in CP1 were refined based on practical implementation constraints. The week's work is fully documented in the project repository.

Key Decisions, Justifications, and Evidence

Decision 1: Pivot cloud deployment target from VMware Workstation to AWS EC2

Justification: The CP1 proposal explicitly flagged in Section 3.3 that Terraform support for VMware Workstation was "exploratory and limited by provider constraints." A pre-execution review confirmed that no stable, maintained Terraform provider exists for VMware Workstation Pro 17. AWS EC2 was selected as the replacement target because (a) it directly aligns with Kabiri (2024) [reference 13 in CP1], whose AWS-based honeypot deployment is the most directly comparable work in the project's literature review; (b) Terraform's official AWS provider is mature, well-documented, and widely supported; and (c) cloud deployment eliminates the institutional ethical risk of operating adversary-facing infrastructure on personal or campus networks.

Evidence: Architecture refinement documented in repository README.md and docs/MSD.md. Supervisor notified by email on 19 June 2026 outlining the change and its alignment with cited literature. The four-plane isolation model from CP1 (Host / Virtualization / Management / Deception) is preserved and re-mapped to AWS primitives (VPC, security groups, EC2, isolated subnets).

Decision 2: Accept AWS paid plan rather than recover previous free-plan account

Justification: A previously held AWS account on a personal email had auto-closed after the 6-month free plan period; the recovery flow was further blocked by SMS-based MFA failures from AWS to the user's Malaysian carrier. A fresh paid-plan account on a dedicated capstone email was the lowest-risk and fastest path to a working environment. The estimated total project spend (approximately USD 10 for a 5-day live capture window plus minor incidentals) is well within the pre-agreed cost tolerance and is offset by the elimination of the auto-closure risk that would have recurred under any free plan.

Evidence: New AWS account established on aosikakam@gmail.com (capstone-dedicated). AWS Budgets configured with two thresholds — USD 5 (warning at 25%) and USD 17 (hard cap at 85%) — with email alerts to both primary and capstone email addresses. Configuration details recorded in docs/MSD.md under "Cloud Infrastructure."

Decision 3: Adopt Ubuntu 24.04 LTS (via WSL2) as the controller environment, retaining existing Kali installation separately

Justification: A Kali Linux WSL2 distribution was already present on the development machine from prior coursework. However, separating capstone tooling from penetration-testing tooling was judged important for operational hygiene during a deadline-driven 6-week project, where an inadvertent state change from unrelated work could cascade into capstone breakage. Ubuntu LTS's stable release model is materially preferable to Kali's rolling-release model for a fixed-deadline project where reproducibility matters more than feature recency. Both distributions are Debian-family and execute Ansible identically; no functional capability is lost by the choice.

Evidence: Ubuntu 24.04 LTS installed via wsl --install -d Ubuntu-24.04. Controller toolchain installed and version-verified: Ansible 2.16.3, Git 2.43.0, Python 3.12.3, GitHub CLI 2.45.0, AWS CLI 2.35.8, Terraform 1.15.6, Ollama 0.30.10 (with llama3.2:3b model). Full inventory recorded in docs/MSD.md under "Local Development Environment."

Decision 4: Configure IAM machine credentials with scoped permissions (AmazonEC2FullAccess + AmazonVPCFullAccess) rather than AdministratorAccess

Justification: The principle of least privilege dictates that machine credentials should hold only the permissions strictly necessary for their function. While many introductory tutorials use AdministratorAccess for simplicity, doing so dramatically increases the blast radius of any credential leakage. Restricting to AmazonEC2FullAccess + AmazonVPCFullAccess bounds any potential exploitation to compute and networking resources while preserving all permissions Terraform requires for the planned honeypot deployment. This decision also aligns with the security-by-design principle articulated in the CP1 Methodology chapter.

Evidence: IAM user terraform-cp2 created with the two named managed policies explicitly attached. Root account separately secured with TOTP-based multi-factor authentication via Google Authenticator. Both configurations documented in docs/MSD.md.

Critical Reflection: Security Incident and Response

During IAM credential configuration on 19 June, the full Secret Access Key for the terraform-cp2 user was inadvertently exposed in an external collaboration context as part of command output, before the secret nature of the field was recognised. The incident was detected within minutes. The compromised key was set to Inactive and Deleted from the AWS IAM console within approximately 5 minutes of exposure, and a replacement access key was generated and configured into the AWS CLI. No unauthorised API activity occurred during the window between exposure and rotation.

The incident is instructive in two ways. First, it demonstrates that the earlier design decision to scope IAM permissions (Decision 4 above) materially reduced the project's exposure to harm — had AdministratorAccess been used, the same accidental disclosure could have permitted account-wide compromise rather than being bounded to EC2/VPC operations. Second, it surfaces a previously unconsidered operational risk: that structured terminal output may embed secrets in fields whose names do not draw attention to their sensitivity. Going forward, all terminal output containing potential credentials, tokens, or keys is redacted before being shared in any external context. The incident and its response are formally logged in the project's docs/PITFALLS.md.

Hours Invested This Week

Approximately 6 hours (19 June afternoon and evening, with supplementary work on 20–21 June for Phase 0 RESCUE Day 2 completion).

Plan for Week 2 (22–28 June 2026)

Week 2 coincides with the semester break and is designated as the project's "Break Week Mega-Sprint" — the highest-density work week of the implementation phase, targeting approximately 30 focused hours. Planned milestones:

- Day 1–2: Terraform provisioning of hardened AWS EC2 instance in ap-southeast-1, with appropriate security group and network ACL configuration to enforce the four-plane isolation model.
- Day 3–4: Ansible playbook deployment of T-Pot CE 24.04 to the provisioned EC2 instance, including custom hardening and Logstash filter additions.
- Day 5: Ethical-gate validation (egress filtering verification, isolation testing) and commencement of live capture window.
- Day 6–7: Parallel work — initial data arriving in Elasticsearch while scaffolding begins for the Ollama-based analyser layer and the curated Kibana dashboard.

====================================================================