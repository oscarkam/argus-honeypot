#!/bin/bash
# ARGUS ES tunnel — autossh keeps this alive across drops.
# Usage: ./scripts/tunnel-start.sh [instance_ip]
# Runs in foreground; Ctrl+C to stop; leave in a dedicated terminal.
# Detect port conflict and clean up

if lsof -ti :9200 >/dev/null 2>&1; then
    echo "⚠ Port 9200 already bound. Killing existing tunnel..."
    lsof -ti :9200 | xargs -r kill
    sleep 1
fi


INSTANCE_IP="${1:-3.1.46.106}"
echo "→ Opening autossh tunnel to ${INSTANCE_IP}:64298 → localhost:9200"
echo "  (auto-reconnects on drops; Ctrl+C to stop)"
exec autossh -M 0 \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=3 \
    -o ExitOnForwardFailure=yes \
    -i "$HOME/.ssh/cp2_honeypot_ed25519" \
    -p 64295 \
    -L 9200:localhost:64298 \
    -N "ubuntu@${INSTANCE_IP}"