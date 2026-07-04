#!/usr/bin/env bash
set -euo pipefail

APP_DIR=/opt/threatlens
ENV_FILE="$APP_DIR/.env"
NETWORK=threatlens-net

if [ ! -f "$ENV_FILE" ]; then
  if command -v openssl >/dev/null 2>&1; then
    PG_PASSWORD=$(openssl rand -hex 24)
  else
    PG_PASSWORD=$(date +%s%N | sha256sum | awk '{print $1}')
  fi
  cat > "$ENV_FILE" <<ENVEOF
POSTGRES_DB=threatlens
POSTGRES_USER=threatlens
POSTGRES_PASSWORD=$PG_PASSWORD
DATABASE_URL=postgresql+psycopg://threatlens:$PG_PASSWORD@threatlens-postgres:5432/threatlens
REDIS_URL=redis://threatlens-redis:6379/0
API_CORS_ORIGINS=http://localhost:8080,http://homeserver:8080
ENVEOF
  chmod 600 "$ENV_FILE"
fi

if ! grep -q '^PICOCLAW_RUNNER_TOKEN=' "$ENV_FILE"; then
  if command -v openssl >/dev/null 2>&1; then
    RUNNER_TOKEN=$(openssl rand -hex 32)
  else
    RUNNER_TOKEN=$(date +%s%N | sha256sum | awk '{print $1}')
  fi
  {
    echo "AI_ENABLED=false"
    echo "AI_PROVIDER="
    echo "AI_MODEL="
    echo "PICOCLAW_RUNNER_TOKEN=$RUNNER_TOKEN"
    echo "PICOCLAW_RUN_TIMEOUT=180"
  } >> "$ENV_FILE"
fi

set -a
source "$ENV_FILE"
set +a

podman network exists "$NETWORK" || podman network create "$NETWORK"
podman volume exists threatlens-postgres-data || podman volume create threatlens-postgres-data
podman volume exists threatlens-redis-data || podman volume create threatlens-redis-data
podman volume exists threatlens-caddy-data || podman volume create threatlens-caddy-data
podman volume exists threatlens-caddy-config || podman volume create threatlens-caddy-config
podman volume exists threatlens-picoclaw-data || podman volume create threatlens-picoclaw-data

podman build -t threatlens-api:latest "$APP_DIR/backend"
podman build -t threatlens-picoclaw-runner:0.2.9 "$APP_DIR/picoclaw-runner"
podman run --rm \
  -v "$APP_DIR/frontend:/app:Z" \
  -w /app \
  docker.io/library/node:22-alpine \
  sh -lc 'npm install && npm run build'

podman rm -f \
  threatlens-caddy \
  threatlens-api \
  threatlens-worker \
  threatlens-picoclaw-runner \
  threatlens-redis \
  threatlens-postgres >/dev/null 2>&1 || true

podman run -d --name threatlens-postgres \
  --network "$NETWORK" \
  --env-file "$ENV_FILE" \
  -v threatlens-postgres-data:/var/lib/postgresql/data:Z \
  -v "$APP_DIR/infra/postgres/init.sql:/docker-entrypoint-initdb.d/01-init.sql:Z,ro" \
  docker.io/library/postgres:16-alpine

podman run -d --name threatlens-redis \
  --network "$NETWORK" \
  -v threatlens-redis-data:/data:Z \
  docker.io/library/redis:7-alpine redis-server --appendonly yes

for i in {1..30}; do
  if podman exec threatlens-postgres pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB" >/dev/null 2>&1; then
    break
  fi
  sleep 2
  if [ "$i" -eq 30 ]; then
    echo 'PostgreSQL did not become ready in time' >&2
    podman logs threatlens-postgres >&2 || true
    exit 1
  fi
done

podman run -d --name threatlens-picoclaw-runner \
  --network "$NETWORK" \
  --env-file "$ENV_FILE" \
  --read-only \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -v threatlens-picoclaw-data:/data:Z \
  threatlens-picoclaw-runner:0.2.9

podman run -d --name threatlens-api \
  --network "$NETWORK" \
  --env-file "$ENV_FILE" \
  -e PICOCLAW_RUNNER_URL=http://threatlens-picoclaw-runner:8090 \
  threatlens-api:latest

podman run -d --name threatlens-worker \
  --network "$NETWORK" \
  --env-file "$ENV_FILE" \
  threatlens-api:latest \
  celery -A worker.celery_app.celery_app worker --beat --loglevel=INFO

podman run -d --name threatlens-caddy \
  --network "$NETWORK" \
  -p 8080:8080 \
  -v "$APP_DIR/infra/caddy/Caddyfile:/etc/caddy/Caddyfile:Z,ro" \
  -v "$APP_DIR/frontend/dist:/srv/frontend:Z,ro" \
  -v threatlens-caddy-data:/data:Z \
  -v threatlens-caddy-config:/config:Z \
  docker.io/library/caddy:2-alpine

podman ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
