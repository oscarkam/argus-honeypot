#!/bin/bash
# ARGUS Web — start the Streamlit Control Center
# Runs in foreground. Ctrl+C to stop.
#
# Usage:
#   ./scripts/argus-web-start.sh
#
# Prerequisites:
#   - SSH tunnel running (./scripts/session-start.sh first)
#   - Ollama running on Windows host
#   - analyzer venv exists at analyzer/.venv

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PATH="${REPO_ROOT}/analyzer/.venv"
ARGUS_WEB="${REPO_ROOT}/argus_web"

# Check venv exists
if [ ! -d "$VENV_PATH" ]; then
    echo "✗ Analyzer venv not found at $VENV_PATH"
    echo "  Fix: cd analyzer && python3 -m venv .venv && pip install -r requirements.txt"
    exit 1
fi

# Kill any prior Streamlit on port 8501
if lsof -ti :8501 >/dev/null 2>&1; then
    echo "⚠ Port 8501 already in use — killing existing Streamlit process..."
    lsof -ti :8501 | xargs -r kill
    sleep 1
fi

# Warn if SSH tunnel not up
if ! lsof -ti :9200 >/dev/null 2>&1; then
    echo "⚠ SSH tunnel not detected on port 9200"
    echo "  Live ES features (System Health, Report Studio, Home metrics) will fail."
    echo "  Run ./scripts/session-start.sh first (or in another terminal)."
    echo ""
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi
fi

echo "→ Activating analyzer venv..."
# shellcheck disable=SC1091
source "$VENV_PATH/bin/activate"

echo "→ Starting ARGUS Control Center..."
echo "   URL: http://localhost:8501"
echo "   Press Ctrl+C to stop"
echo ""

cd "$ARGUS_WEB"
exec streamlit run app.py --server.headless true