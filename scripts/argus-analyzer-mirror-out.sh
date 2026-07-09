#!/bin/bash
rsync -av --delete \
    --exclude="__pycache__" --exclude="*.pyc" --exclude=".venv" --exclude="reports/" \
    ~/cp2-honeypot-iac/analyzer/ \
    "/mnt/c/Users/oscar/Claude Cowork/analyzer/"
