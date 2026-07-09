#!/bin/bash
rsync -av --delete \
    --exclude="__pycache__" --exclude="*.pyc" --exclude=".venv" --exclude="reports/" \
    "/mnt/c/Users/oscar/Claude Cowork/analyzer/" \
    ~/cp2-honeypot-iac/analyzer/
