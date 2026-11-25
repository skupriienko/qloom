#!/usr/bin/env bash
# Installer for standalone qloom package
set -euo pipefail

cd "$(dirname "$0")"
echo "==> Installing qloom in editable mode..."
python3 -m pip install --upgrade pip
python3 -m pip install -e .

echo "==> Verifying qloom CLI..."
qloom verify --json >/dev/null

echo "==> Installation complete! Run 'qloom --help' or 'qloom mcp' to get started."
