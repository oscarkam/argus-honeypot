#!/bin/bash
# Pull Claude Cowork edits → argus_web/
rsync -av --delete \
    --exclude="__pycache__" --exclude="*.pyc" --exclude="*.bak" \
    "/mnt/c/Users/oscar/Claude Cowork/argus_web/" \
    ~/cp2-honeypot-iac/argus_web/
