#!/bin/bash
set -euo pipefail
INSTANCE_ID="i-02c73e226b225ce3e"
REGION="ap-southeast-1"
echo "→ Starting ARGUS instance..."
aws ec2 start-instances --instance-ids "$INSTANCE_ID" --region "$REGION" > /dev/null
echo "→ Waiting for running state (~60-90 sec)..."
aws ec2 wait instance-running --instance-ids "$INSTANCE_ID" --region "$REGION"
PUBLIC_IP=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
echo "✓ Instance running at $PUBLIC_IP (EIP preserved)."
echo "→ T-Pot service and Docker containers need ~2-3 min to fully initialise."
echo "  Run ./scripts/session-start.sh after ~3 minutes to open the tunnel and verify."