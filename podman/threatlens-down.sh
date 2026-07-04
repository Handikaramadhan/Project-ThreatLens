#!/usr/bin/env bash
set -euo pipefail

podman rm -f \
  threatlens-caddy \
  threatlens-api \
  threatlens-worker \
  threatlens-picoclaw-runner \
  threatlens-redis \
  threatlens-postgres >/dev/null 2>&1 || true
