#!/bin/bash
# ============================================================
# refresh-admin-ip.sh
# ------------------------------------------------------------
# Detects the current public IP of the machine running this script,
# updates infra/terraform/terraform.tfvars, and applies a targeted
# security-group refresh so admin access (T-Pot management ports)
# matches the current network location.
#
# Run this at the start of each work session, or right before a
# presentation from a new venue's network.
#
# Usage:
#   ./scripts/refresh-admin-ip.sh
#
# Requirements:
#   - AWS CLI configured (aws configure)
#   - Terraform installed
#   - curl available
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TF_DIR="${REPO_ROOT}/infra/terraform"
TFVARS="${TF_DIR}/terraform.tfvars"

echo "==> Detecting current public IP..."
CURRENT_IP="$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || curl -s --max-time 5 https://ifconfig.me 2>/dev/null)"

if [[ -z "${CURRENT_IP}" ]]; then
  echo "ERROR: Could not determine current public IP. Check internet connectivity." >&2
  exit 1
fi

echo "    Current public IP: ${CURRENT_IP}"

if [[ ! -f "${TFVARS}" ]]; then
  echo "ERROR: ${TFVARS} not found. Copy from terraform.tfvars.example and populate first." >&2
  exit 1
fi

EXISTING_IP="$(grep -E '^admin_source_ip' "${TFVARS}" | awk -F'"' '{print $2}' | cut -d'/' -f1 || true)"
echo "    IP currently in tfvars: ${EXISTING_IP:-<none>}"

if [[ "${CURRENT_IP}" == "${EXISTING_IP}" ]]; then
  echo "==> IP unchanged. Nothing to do."
  exit 0
fi

echo "==> Updating ${TFVARS}..."
sed -i.bak "s|^admin_source_ip = .*|admin_source_ip = \"${CURRENT_IP}/32\"|" "${TFVARS}"
rm -f "${TFVARS}.bak"

echo "    New tfvars content:"
cat "${TFVARS}"

echo "==> Applying targeted security group update via Terraform..."
cd "${TF_DIR}"
terraform apply -target=aws_security_group.honeypot -auto-approve

echo ""
echo "✓ Admin access now allowed from ${CURRENT_IP}"