#!/bin/bash
# ============================================================
# refresh-ollama-host.sh
# ------------------------------------------------------------
# Detects the Windows host IP as seen from WSL2, updates
# analyzer/config.yml, and verifies Ollama is reachable.
#
# Run at the start of a WSL2 session if the previous Ollama
# base_url no longer works (Windows host IP typically changes
# after a Windows reboot or WSL restart).
#
# Usage:
#   ./scripts/refresh-ollama-host.sh
#
# Requirements:
#   - Running inside WSL2 on a Windows host
#   - Ollama on Windows with OLLAMA_HOST=0.0.0.0
#   - curl available
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONFIG="${REPO_ROOT}/analyzer/config.yml"
OLLAMA_PORT="11434"

echo "==> Detecting Windows host IP from WSL2..."
WINDOWS_IP="$(ip route show default 2>/dev/null | awk '{print $3}')"

if [[ -z "${WINDOWS_IP}" ]]; then
  echo "ERROR: Could not determine Windows host IP." >&2
  echo "       Are you running inside WSL2?" >&2
  exit 1
fi

echo "    Windows host IP: ${WINDOWS_IP}"

echo "==> Testing Ollama reachability at http://${WINDOWS_IP}:${OLLAMA_PORT}..."
if ! curl -s --max-time 5 "http://${WINDOWS_IP}:${OLLAMA_PORT}/api/tags" > /dev/null; then
  echo "ERROR: Ollama not reachable at http://${WINDOWS_IP}:${OLLAMA_PORT}" >&2
  echo "" >&2
  echo "Fix checklist:" >&2
  echo "  1. Is Ollama running on Windows? (check system tray)" >&2
  echo "  2. Is OLLAMA_HOST=0.0.0.0 set as a Windows user env var?" >&2
  echo "     Verify from PowerShell:" >&2
  echo "       [System.Environment]::GetEnvironmentVariable('OLLAMA_HOST', 'User')" >&2
  echo "  3. Has Ollama been quit-and-relaunched since the env var was set?" >&2
  exit 1
fi

echo "    ✓ Ollama reachable and responding"

if [[ ! -f "${CONFIG}" ]]; then
  echo "ERROR: ${CONFIG} not found. Copy from config.example.yml first." >&2
  exit 1
fi

EXISTING_URL="$(grep -E '^\s*base_url:' "${CONFIG}" | head -1 | awk -F'"' '{print $2}')"
NEW_URL="http://${WINDOWS_IP}:${OLLAMA_PORT}"

if [[ "${EXISTING_URL}" == "${NEW_URL}" ]]; then
  echo "==> config.yml already up to date. Nothing to change."
  exit 0
fi

echo "==> Updating ${CONFIG}..."
echo "    Old base_url: ${EXISTING_URL:-<not set>}"
echo "    New base_url: ${NEW_URL}"

sed -i.bak "s|^\(\s*base_url:\).*|\1 \"${NEW_URL}\"|" "${CONFIG}"
rm -f "${CONFIG}.bak"

echo ""
echo "✓ analyzer/config.yml updated. Verify with:"
echo "    cd analyzer && source .venv/bin/activate && python analyzer.py --test-ollama"