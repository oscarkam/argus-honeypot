# Pitfalls Log

## Pitfall 1: AWS Access Key Accidentally Exposed in External Chat
**Date**: 19 June 2026
**Phase**: 0 RESCUE — IAM user creation
**What happened**: The full `aws configure` output, including the IAM user `terraform-cp2`'s Secret Access Key, was pasted into an external chat session before realising the secret was visible in the output.

**Impact**: Low — credentials were scoped to AmazonEC2FullAccess + AmazonVPCFullAccess only (not AdministratorAccess), and account budget alarms at $5/$17 would have triggered quickly on any malicious spend.

**Response**: Compromised access key was set to Inactive and Deleted within ~5 minutes of exposure. A new access key was generated and AWS CLI reconfigured. No unauthorized API activity observed before rotation.

**Lesson learned**: Treat any "secret" / "key" / "token" field as sensitive even within structured command output. Always redact secrets to `XXXXX` before sharing terminal logs, regardless of how routine the command appears. The principle of least privilege (scoped IAM policy) materially reduced the blast radius of this exposure — confirming the design decision made earlier in Phase 0 to use scoped permissions instead of AdministratorAccess.

## Pitfall 2: Terraform Lock File Incorrectly Gitignored
**Date**: 30 June 2026
**Phase**: 0 RESCUE — Terraform skeleton
**What happened**: Initial `.gitignore` template excluded `.terraform.lock.hcl`. After running `terraform init`, the tool itself surfaced the issue with a printed reminder to commit the lock file. The exclusion would have caused non-reproducible builds for any future re-execution of the IaC.

**Impact**: Low — caught immediately on first `terraform init`, before any production deployment.

**Response**: Removed `.terraform.lock.hcl` from `.gitignore` and committed the lock file to version control with explanatory commit message.

**Lesson learned**: Always read the output of IaC tool initialisation commands — they often surface configuration smells the user wouldn't catch otherwise. Distinguish carefully between Terraform files that MUST be ignored (state files contain secrets, `.terraform/` is local cache) versus files that MUST be committed (lock files, `.tf` source, example `.tfvars`).

## Pitfall 3: `.gitattributes` Placed in Wrong Directory
**Date**: 30 June 2026
**Phase**: 0 RESCUE / 1 transition — line-ending consistency setup
**What happened**: The `.gitattributes` file intended to enforce LF line endings across the entire repository was inadvertently created inside `docs/` rather than at the repository root. Git only applies `.gitattributes` rules to files at or below its location, so the misplaced file would have only governed markdown files in `docs/`, leaving Terraform, Ansible, and Python source files unaffected.

**Impact**: Low — caught during `git status` review at the start of the next session before any cross-platform line-ending issue manifested.

**Response**: Moved the file from `docs/.gitattributes` to `.gitattributes` (repo root); committed and pushed with explanatory message. Also corrected the missing trailing newline (POSIX convention).

**Lesson learned**: Repository-wide configuration files (`.gitattributes`, `.gitignore`, `.editorconfig`, root-level `README.md`) must live at the repository root to have project-wide effect. When creating such files in VS Code, verify the parent folder is the repo root (not whichever subfolder happens to be open in the sidebar).

## Pitfall 4: Campus Network SSH Interception
**Date**: 1 July 2026
**Phase**: 1 Build Sprint — first EC2 SSH access
**What happened**: After successful `terraform apply` creating the T-Pot EC2 instance, all SSH attempts from campus WiFi hung indefinitely with no error output. Layered diagnostic (`nc` for TCP-level, `ssh -v` for handshake-level, AWS Console for instance health) revealed TCP reachability was intact and the EC2 instance passed 3/3 status checks — but the SSH handshake hung immediately after the client sent its version banner, with no server reply.

**Root cause**: The campus network's deep-packet-inspection firewall permits TCP connections to port 22 but silently intercepts and drops the SSH version-exchange handshake at the application layer, effectively blocking outbound SSH to public IPs. This is a common security policy on Malaysian university networks.

**Impact**: Session-blocking on campus premises only; no impact when working from mobile hotspot or residential ISP.

**Response**: Switched laptop to mobile hotspot connection; SSH connected instantly, confirming the diagnosis. Continued Ansible orchestration workflow over the hotspot connection.

**Long-term mitigation under evaluation**: AWS Systems Manager Session Manager (SSM) would provide IAM-authenticated shell access via HTTPS (port 443) through the AWS regional endpoint, eliminating the port 22 dependency. This would allow admin access from any network permitting outbound HTTPS, including campus WiFi. Requires adding an IAM role, instance profile, and SSM agent configuration to the Terraform config. Estimated setup: 15 minutes; deferred to a Phase 2 enhancement to avoid disrupting the current build sprint.

**Lesson learned**: When a TCP-level test succeeds but application-level handshake hangs, the culprit is typically an application-layer proxy or DPI firewall. Layered diagnostic (`nc` → `ssh -v` → cloud provider console) reveals the exact layer of failure and points to targeted mitigation. Always test connectivity from multiple network paths before assuming an infrastructure problem.

## Pitfall 5: Terraform Applied Before Committing to Version Control
**Date**: 1 July 2026
**Phase**: 1 Build Sprint — cloud infrastructure provisioning
**What happened**: Terraform code for the security group, EC2 instance, outputs, and a subsequent disk-size change was written, validated, and applied to live AWS infrastructure without first being committed to the git repository. Discovery came incidentally during a routine `git status` before an unrelated commit, revealing four files (`compute.tf`, `security.tf`, `outputs.tf`, plus a modified `variables.tf`) as untracked or unstaged despite having produced the running cloud environment.

**Impact**: Medium — the running infrastructure had no reproducible source-of-truth on any remote (GitHub). A laptop failure or disk corruption between apply and commit would have orphaned the running resources, requiring manual reverse-engineering from the AWS Console to reconstruct the Terraform config. No actual loss occurred because the gap was detected within the same working session.

**Response**: Immediately staged and committed all uncommitted Terraform files in a single logically-grouped commit with a message explicitly noting the "applied but previously uncommitted" state, pushed to origin. Verified `git status` clean afterwards.

**Lesson learned**: The correct order for IaC changes is always **commit → apply**, never **apply → commit later**. Even in a sprint under time pressure, `git add && git commit -m 'wip' && git push` before every `terraform apply` costs 20 seconds and guarantees the repo remains the single source of truth. Consider adding a pre-apply git-check habit: before typing `terraform apply`, run `git status` and refuse to proceed if the working tree isn't clean.

## Pitfall 6: WSL2 `localhost` ≠ Windows `localhost` for Ollama Bridge
**Date**: 1 July 2026
**Phase**: 2 Build — LLM analyser scaffolding
**What happened**: The initial `analyzer.py --test-ollama` smoke test failed with `Connection refused` when trying to reach `http://localhost:11434`. Ollama was running and healthy on Windows — verified with `curl http://localhost:11434/api/tags` from PowerShell — yet WSL2 could not reach it via the same URL.

**Root cause**: WSL2 runs in its own virtual network with its own loopback interface. `localhost` from inside WSL2 resolves to WSL2's own loopback, NOT the Windows host's loopback where Ollama was listening. Additionally, Ollama's default binding is `127.0.0.1:11434` (Windows loopback only), which even a correctly-addressed request from WSL2 could not reach.

**Response**: Two coordinated fixes.
1. On Windows: set persistent user env var `OLLAMA_HOST=0.0.0.0` and restart Ollama, causing it to listen on all interfaces (verified via `netstat -an | findstr :11434` showing `0.0.0.0:11434 LISTENING`).
2. In WSL2: retrieved Windows host IP via `ip route show default | awk '{print $3}'` → `172.30.192.1`. Updated `analyzer/config.yml` `ollama.base_url` to `http://172.30.192.1:11434`.

**Long-term mitigation**: Windows host IP as seen from WSL2 can change on Windows reboots or `wsl --shutdown`. Idempotent helper script `scripts/refresh-ollama-host.sh` was authored to auto-detect current Windows IP, verify Ollama reachability, and update `analyzer/config.yml` in place.

**Lesson learned**: When Python code inside WSL2 needs to reach a service on the Windows host, both a binding change (service listens on `0.0.0.0`) and an address change (use the WSL2 default gateway IP, not `localhost`) are required. Common pattern for Docker Desktop, database GUIs, LM Studio, etc.