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
SEED_DEMO_DATA=false
NEWS_RETENTION_DAYS=180
IOC_RETENTION_DAYS=180
COLLECTION_RUN_RETENTION_DAYS=30
COLLECTION_RUN_MIN_KEEP=10
ENVEOF
  chmod 600 "$ENV_FILE"
fi

ensure_env_default() {
  local key="$1"
  local value="$2"
  if ! grep -q "^${key}=" "$ENV_FILE"; then
    echo "${key}=${value}" >> "$ENV_FILE"
  fi
}

ensure_env_default SEED_DEMO_DATA false
ensure_env_default NEWS_RETENTION_DAYS 180
ensure_env_default IOC_RETENTION_DAYS 180
ensure_env_default COLLECTION_RUN_RETENTION_DAYS 30
ensure_env_default COLLECTION_RUN_MIN_KEEP 10
ensure_env_default BACKUP_RETENTION_DAYS 14
ensure_env_default POSTGRES_MEMORY 1g
ensure_env_default POSTGRES_CPUS 1
ensure_env_default REDIS_MEMORY 256m
ensure_env_default REDIS_CPUS 0.5
ensure_env_default API_MEMORY 768m
ensure_env_default API_CPUS 1.5
ensure_env_default WORKER_MEMORY 768m
ensure_env_default WORKER_CPUS 1.5
ensure_env_default BEAT_MEMORY 256m
ensure_env_default BEAT_CPUS 0.5
ensure_env_default CADDY_MEMORY 256m
ensure_env_default CADDY_CPUS 0.5
ensure_env_default PICOCLAW_MEMORY 512m
ensure_env_default PICOCLAW_CPUS 1

if ! grep -q '^ALERT_SECRET_KEY=' "$ENV_FILE"; then
  if command -v openssl >/dev/null 2>&1; then
    ALERT_SECRET_KEY=$(openssl rand -hex 32)
  else
    ALERT_SECRET_KEY=$(date +%s%N | sha256sum | awk '{print $1}')
  fi
  echo "ALERT_SECRET_KEY=$ALERT_SECRET_KEY" >> "$ENV_FILE"
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
chmod 600 "$ENV_FILE"

podman network exists "$NETWORK" || podman network create "$NETWORK"
podman volume exists threatlens-postgres-data || podman volume create threatlens-postgres-data
podman volume exists threatlens-redis-data || podman volume create threatlens-redis-data
podman volume exists threatlens-caddy-data || podman volume create threatlens-caddy-data
podman volume exists threatlens-caddy-config || podman volume create threatlens-caddy-config
podman volume exists threatlens-picoclaw-data || podman volume create threatlens-picoclaw-data

podman build -t threatlens-api:latest "$APP_DIR/backend"
podman build -t threatlens-picoclaw-runner:0.2.9 "$APP_DIR/picoclaw-runner"
podman run --rm \
  -v "$APP_DIR/frontend:/app:z" \
  -w /app \
  docker.io/library/node:22-alpine \
  sh -lc 'npm ci && npm run build'

podman rm -f \
  threatlens-caddy \
  threatlens-api \
  threatlens-worker \
  threatlens-beat \
  threatlens-picoclaw-runner \
  threatlens-redis \
  threatlens-postgres >/dev/null 2>&1 || true

podman run -d --name threatlens-postgres \
  --restart=unless-stopped \
  --network "$NETWORK" \
  --env-file "$ENV_FILE" \
  --memory "$POSTGRES_MEMORY" \
  --cpus "$POSTGRES_CPUS" \
  --health-cmd "pg_isready -U $POSTGRES_USER -d $POSTGRES_DB" \
  --health-interval 30s \
  --health-timeout 5s \
  --health-retries 5 \
  -v threatlens-postgres-data:/var/lib/postgresql/data:Z \
  -v "$APP_DIR/infra/postgres/init.sql:/docker-entrypoint-initdb.d/01-init.sql:Z,ro" \
  docker.io/library/postgres:16-alpine

podman run -d --name threatlens-redis \
  --restart=unless-stopped \
  --network "$NETWORK" \
  --memory "$REDIS_MEMORY" \
  --cpus "$REDIS_CPUS" \
  --health-cmd "redis-cli ping" \
  --health-interval 30s \
  --health-timeout 5s \
  --health-retries 5 \
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
  --restart=unless-stopped \
  --network "$NETWORK" \
  --env-file "$ENV_FILE" \
  --memory "$PICOCLAW_MEMORY" \
  --cpus "$PICOCLAW_CPUS" \
  --read-only \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -v threatlens-picoclaw-data:/data:Z \
  threatlens-picoclaw-runner:0.2.9

podman run -d --name threatlens-api \
  --restart=unless-stopped \
  --network "$NETWORK" \
  --env-file "$ENV_FILE" \
  --memory "$API_MEMORY" \
  --cpus "$API_CPUS" \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=128m \
  --health-cmd "python -c \"import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health', timeout=3)\"" \
  --health-interval 30s \
  --health-timeout 5s \
  --health-retries 5 \
  -e PICOCLAW_RUNNER_URL=http://threatlens-picoclaw-runner:8090 \
  threatlens-api:latest

podman run -d --name threatlens-worker \
  --restart=unless-stopped \
  --network "$NETWORK" \
  --env-file "$ENV_FILE" \
  --memory "$WORKER_MEMORY" \
  --cpus "$WORKER_CPUS" \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=128m \
  threatlens-api:latest \
  celery -A worker.celery_app.celery_app worker --loglevel=INFO

podman run -d --name threatlens-beat \
  --restart=unless-stopped \
  --network "$NETWORK" \
  --env-file "$ENV_FILE" \
  --memory "$BEAT_MEMORY" \
  --cpus "$BEAT_CPUS" \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  threatlens-api:latest \
  celery -A worker.celery_app.celery_app beat --loglevel=INFO

podman run -d --name threatlens-caddy \
  --restart=unless-stopped \
  --network "$NETWORK" \
  --memory "$CADDY_MEMORY" \
  --cpus "$CADDY_CPUS" \
  --security-opt no-new-privileges \
  --health-cmd "wget -qO- http://localhost:8080/api/health >/dev/null" \
  --health-interval 30s \
  --health-timeout 5s \
  --health-retries 5 \
  -e API_UPSTREAM=threatlens-api:8000 \
  -p 8080:8080 \
  -v "$APP_DIR/infra/caddy/Caddyfile:/etc/caddy/Caddyfile:Z,ro" \
  -v "$APP_DIR/frontend/dist:/srv/frontend:z,ro" \
  -v threatlens-caddy-data:/data:Z \
  -v threatlens-caddy-config:/config:Z \
  docker.io/library/caddy:2-alpine

podman ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
