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