#!/bin/bash
# NothingDNS Backup Script
# Usage: ./scripts/backup.sh [/path/to/backupdir]

set -euo pipefail

BACKUP_DIR="${1:-/var/backups/nothingdns}"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="nothingdns-backup-${DATE}.tar.gz"

mkdir -p "$BACKUP_DIR"

echo "Backing up NothingDNS to $BACKUP_DIR/$BACKUP_FILE..."

# Create backup archive
tar -czf "$BACKUP_DIR/$BACKUP_FILE" \
    /etc/nothingdns/nothingdns.yaml \
    /etc/nothingdns/zones/ 2>/dev/null || true \
    /data/nothingdns/*.kv 2>/dev/null || true \
    /data/nothingdns/*.wal 2>/dev/null || true

# Create md5 checksum
md5sum "$BACKUP_DIR/$BACKUP_FILE" > "$BACKUP_DIR/$BACKUP_FILE.md5"

# Keep only last 7 backups
cd "$BACKUP_DIR"
ls -t nothingdns-backup-*.tar.gz 2>/dev/null | tail -n +8 | xargs rm -f 2>/dev/null || true

echo "Backup complete: $BACKUP_DIR/$BACKUP_FILE"
echo "Checksum: $BACKUP_DIR/$BACKUP_FILE.md5"