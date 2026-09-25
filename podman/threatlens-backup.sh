#!/usr/bin/env bash
set -euo pipefail

APP_DIR=${APP_DIR:-/opt/threatlens}
ENV_FILE="$APP_DIR/.env"
BACKUP_DIR=${BACKUP_DIR:-/var/backups/threatlens/postgres}

if [ ! -f "$ENV_FILE" ]; then
  echo "Missing env file: $ENV_FILE" >&2
  exit 1
fi

set -a
source "$ENV_FILE"
set +a

RETENTION_DAYS=${BACKUP_RETENTION_DAYS:-14}
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
DEST="$BACKUP_DIR/threatlens-${TIMESTAMP}.dump"
FINAL_DEST="$DEST"

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

podman exec threatlens-postgres pg_dump \
  -U "$POSTGRES_USER" \
  -d "$POSTGRES_DB" \
  -Fc \
  --no-owner \
  --no-acl > "$DEST"

chmod 600 "$DEST"

if [ -n "${BACKUP_ENCRYPTION_PASSPHRASE_FILE:-}" ]; then
  if [ ! -f "$BACKUP_ENCRYPTION_PASSPHRASE_FILE" ]; then
    echo "Missing BACKUP_ENCRYPTION_PASSPHRASE_FILE: $BACKUP_ENCRYPTION_PASSPHRASE_FILE" >&2
    exit 1
  fi
  if ! command -v gpg >/dev/null 2>&1; then
    echo "gpg is required for encrypted backups" >&2
    exit 1
  fi
  gpg --batch --yes --symmetric --cipher-algo AES256 \
    --passphrase-file "$BACKUP_ENCRYPTION_PASSPHRASE_FILE" \
    --output "$DEST.gpg" \
    "$DEST"
  chmod 600 "$DEST.gpg"
  rm -f "$DEST"
  FINAL_DEST="$DEST.gpg"
fi

if [ -n "${BACKUP_OFFSITE_RSYNC_TARGET:-}" ]; then
  if ! command -v rsync >/dev/null 2>&1; then
    echo "rsync is required for BACKUP_OFFSITE_RSYNC_TARGET" >&2
    exit 1
  fi
  rsync -az --chmod=F600 "$FINAL_DEST" "$BACKUP_OFFSITE_RSYNC_TARGET/"
fi

find "$BACKUP_DIR" \
  -type f \
  \( -name 'threatlens-*.dump' -o -name 'threatlens-*.dump.gpg' \) \
  -mtime +"$RETENTION_DAYS" \
  -delete

echo "$FINAL_DEST"
