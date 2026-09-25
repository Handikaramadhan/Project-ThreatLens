#!/usr/bin/env sh
set -eu

podman build -t threatlens-api:test backend
podman run --rm \
  -e DATABASE_URL=sqlite+pysqlite:///:memory: \
  -e REDIS_URL=redis://localhost:6379/0 \
  -e ALERT_SECRET_KEY=test-alert-secret \
  -v "$PWD/backend:/app:Z" \
  threatlens-api:test \
  python -m pytest /app/tests

podman run --rm \
  -v "$PWD/frontend:/app:Z" \
  -w /app \
  docker.io/library/node:22-alpine \
  sh -lc "npm ci && npm run build"
