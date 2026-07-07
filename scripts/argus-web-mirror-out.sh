#!/bin/bash
# Push argus_web/ → Claude Cowork for AI-assisted editing
rsync -av --delete \
    --exclude="__pycache__" --exclude="*.pyc" --exclude="*.bak" \
    ~/cp2-honeypot-iac/argus_web/ \
    "/mnt/c/Users/oscar/Claude Cowork/argus_web/"
