#!/bin/bash
set -euo pipefail
INSTANCE_ID="i-02c73e226b225ce3e"
REGION="ap-southeast-1"
echo "→ Stopping ARGUS instance..."
aws ec2 stop-instances --instance-ids "$INSTANCE_ID" --region "$REGION" > /dev/null
echo "→ Waiting for stopped state (~60 sec)..."
aws ec2 wait instance-stopped --instance-ids "$INSTANCE_ID" --region "$REGION"
echo "✓ Instance stopped. Compute charges paused (~\$0.16/hr saved). EBS + EIP still cost ~\$0.02/hr."