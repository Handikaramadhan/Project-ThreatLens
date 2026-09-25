#!/usr/bin/env bash
set -euo pipefail

APP_DIR=${APP_DIR:-/opt/threatlens}
BACKUP_DIR=${SOURCE_BACKUP_DIR:-/opt/threatlens-source-backups}
RETENTION_DAYS=${SOURCE_BACKUP_RETENTION_DAYS:-14}
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
DEST_DIR="$BACKUP_DIR/$TIMESTAMP"
ARCHIVE="$DEST_DIR/source.tgz"

mkdir -p "$DEST_DIR"
chmod 700 "$BACKUP_DIR" "$DEST_DIR"

tar \
  --exclude=.git \
  --exclude=.env \
  --exclude='*/.env' \
  --exclude='threatlens/.env' \
  --exclude=backups \
  --exclude=frontend/node_modules \
  --exclude=frontend/dist \
  -czf "$ARCHIVE" \
  -C "$(dirname "$APP_DIR")" \
  "$(basename "$APP_DIR")"

chmod 600 "$ARCHIVE"

PASSPHRASE_FILE="${SOURCE_BACKUP_ENCRYPTION_PASSPHRASE_FILE:-${BACKUP_ENCRYPTION_PASSPHRASE_FILE:-}}"
if [ -n "$PASSPHRASE_FILE" ]; then
  if [ ! -f "$PASSPHRASE_FILE" ]; then
    echo "Missing source backup passphrase file: $PASSPHRASE_FILE" >&2
    exit 1
  fi
  if ! command -v gpg >/dev/null 2>&1; then
    echo "gpg is required for encrypted source backups" >&2
    exit 1
  fi
  gpg --batch --yes --symmetric --cipher-algo AES256 \
    --passphrase-file "$PASSPHRASE_FILE" \
    --output "$ARCHIVE.gpg" \
    "$ARCHIVE"
  chmod 600 "$ARCHIVE.gpg"
  rm -f "$ARCHIVE"
  ARCHIVE="$ARCHIVE.gpg"
fi

OFFSITE_TARGET="${SOURCE_BACKUP_OFFSITE_RSYNC_TARGET:-${BACKUP_OFFSITE_RSYNC_TARGET:-}}"
if [ -n "$OFFSITE_TARGET" ]; then
  if ! command -v rsync >/dev/null 2>&1; then
    echo "rsync is required for source backup offsite sync" >&2
    exit 1
  fi
  rsync -az --chmod=F600 "$ARCHIVE" "$OFFSITE_TARGET/"
fi

find "$BACKUP_DIR" \
  -mindepth 1 \
  -maxdepth 1 \
  -type d \
  -mtime +"$RETENTION_DAYS" \
  -exec rm -rf {} +

echo "$ARCHIVE"
