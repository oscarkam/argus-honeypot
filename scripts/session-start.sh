#!/bin/bash
# ARGUS session-start — one command to prep for a work session.
# Refreshes admin IP, ensures ES tunnel is up (background), verifies health, reports git state.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TUNNEL_LOG="/tmp/argus-tunnel.log"

echo "╔════════════════════════════════════════════════════╗"
echo "║               ARGUS Session Start                  ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""

# 1. Refresh admin IP
echo "→ 1/4  Refreshing admin source IP..."
"$REPO_ROOT/scripts/refresh-admin-ip.sh" 2>&1 | sed 's/^/     /'
echo ""

# 2. Ensure tunnel is running (background)
echo "→ 2/4  Ensuring ES tunnel is running..."
if lsof -ti :9200 >/dev/null 2>&1; then
    echo "     ✓ Tunnel already up (port 9200 bound)"
else
    echo "     Starting autossh tunnel in background..."
    nohup "$REPO_ROOT/scripts/tunnel-start.sh" > "$TUNNEL_LOG" 2>&1 &
    TUNNEL_PID=$!
    sleep 3
    if lsof -ti :9200 >/dev/null 2>&1; then
        echo "     ✓ Tunnel started (PID $TUNNEL_PID, log: $TUNNEL_LOG)"
    else
        echo "     ⚠ Tunnel failed — check $TUNNEL_LOG"
    fi
fi
echo ""

# 3. Probe ES health via tunnel
echo "→ 3/4  Probing Elasticsearch via tunnel..."
ES=$(curl -s --max-time 5 http://localhost:9200/_cluster/health 2>/dev/null)
if [ -n "$ES" ]; then
    CLUSTER=$(echo "$ES" | grep -oE '"cluster_name":"[^"]+"' | cut -d: -f2 | tr -d '"')
    STATUS=$(echo "$ES" | grep -oE '"status":"[^"]+"' | cut -d: -f2 | tr -d '"')
    echo "     ✓ ES reachable — cluster=$CLUSTER status=$STATUS"
else
    echo "     ⚠ ES unreachable via tunnel — check $TUNNEL_LOG"
fi
echo ""

# 4. Git state
echo "→ 4/4  Git working tree..."
cd "$REPO_ROOT"
if [ -z "$(git status --porcelain)" ]; then
    echo "     ✓ Clean"
else
    echo "     ⚠ Uncommitted:"
    git status --porcelain | head -10 | sed 's/^/        /'
fi
echo "     Latest: $(git log --oneline -1)"
echo ""

echo "╔═══════════════════════════════════════════════════════╗"
echo "║  Ready. Run: cd analyzer && source .venv/bin/activate ║"
echo "╚═══════════════════════════════════════════════════════╝"