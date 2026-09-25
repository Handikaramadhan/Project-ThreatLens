#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

echo "== Python dependencies =="
if command -v pip-audit >/dev/null 2>&1; then
  pip-audit -r backend/requirements.txt || echo "pip-audit reported findings or failed"
else
  echo "pip-audit not installed; install with: python3 -m pip install pip-audit"
fi

echo "== Frontend dependencies =="
if command -v npm >/dev/null 2>&1 && [ -f frontend/package-lock.json ]; then
  (cd frontend && npm audit --omit=dev) || echo "npm audit reported findings or failed"
else
  echo "npm or frontend/package-lock.json not available; skipping npm audit"
fi

echo "== Filesystem/container context =="
if command -v trivy >/dev/null 2>&1; then
  trivy fs --scanners vuln,secret,misconfig --skip-dirs frontend/node_modules --skip-dirs .git . || echo "trivy reported findings or failed"
else
  echo "trivy not installed; install Trivy for filesystem/container scanning"
fi
