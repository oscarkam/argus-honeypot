#!/bin/bash
# ============================================================
# ARGUS Preflight — session startup checks
# ------------------------------------------------------------
# 1. Refresh admin source IP (auto-detect network change)
# 2. Probe T-Pot health via SSH (skips gracefully if blocked)
# 3. Report git working-tree state
#
# Usage: ./scripts/preflight.sh
# ============================================================

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TPOT_HOST="47.129.9.195"
SSH_KEY="$HOME/.ssh/cp2_honeypot_ed25519"

echo "╔════════════════════════════════════════════════════╗"
echo "║  ARGUS Preflight — Session Startup                 ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""

# ---- Step 1: Admin IP refresh ----
echo "→ 1/3  Refreshing admin source IP..."
if "$REPO_ROOT/scripts/refresh-admin-ip.sh" 2>&1 | sed 's/^/     /'; then
  echo "     ✓ Admin IP current"
else
  echo "     ⚠ Refresh failed (see above)"
fi
echo ""

# ---- Step 2: T-Pot health via SSH ----
echo "→ 2/3  Probing T-Pot health at ${TPOT_HOST}:64295..."
SSH_OUT=$(timeout 10 ssh -o ConnectTimeout=5 -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
    -i "$SSH_KEY" -p 64295 "ubuntu@$TPOT_HOST" \
    "sudo systemctl is-active tpot 2>/dev/null; sudo docker ps -q | wc -l" 2>&1)
SSH_RC=$?
if [ $SSH_RC -eq 0 ]; then
  ACTIVE=$(echo "$SSH_OUT" | head -1)
  CONTAINERS=$(echo "$SSH_OUT" | tail -1)
  echo "     ✓ T-Pot service: $ACTIVE  |  Containers: $CONTAINERS"
else
  echo "     ⚠ Unreachable — possible causes:"
  echo "        • On campus WiFi (DPI blocks SSH → switch to hotspot/home)"
  echo "        • Instance stopped or account issue (check AWS Console)"
  echo "        • IP changed on your end — re-run refresh-admin-ip.sh"
fi
echo ""

# ---- Step 3: Git working tree ----
echo "→ 3/3  Git working tree..."
cd "$REPO_ROOT"
if [ -z "$(git status --porcelain)" ]; then
  echo "     ✓ Clean"
else
  echo "     ⚠ Uncommitted changes:"
  git status --porcelain | head -10 | sed 's/^/        /'
fi
echo "     Latest: $(git log --oneline -1)"
echo ""

echo "╔════════════════════════════════════════════════════╗"
echo "║  Preflight complete. Have a productive session.    ║"
echo "╚════════════════════════════════════════════════════╝"