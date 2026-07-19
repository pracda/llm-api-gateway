#!/bin/bash
# Postgres → S3 backup for the LLM Gateway. Runs on the EC2 box (via the systemd timer in
# BACKUP.md). Streams a compressed pg_dump straight to S3 — no local disk footprint, no
# secrets on disk (auth comes from the instance's attached IAM role).
#
#   BACKUP_BUCKET   (required)  target S3 bucket, e.g. llm-gateway-backups-<acct>
#   BACKUP_PREFIX   (optional)  key prefix, default "pg"
#   PG_CONTAINER    (optional)  postgres container name, default "gateway-postgres"
#   PG_USER/PG_DB   (optional)  default gateway / llmgateway
#
# Retention is handled by an S3 lifecycle rule on the bucket (see BACKUP.md), not here.
set -euo pipefail

BUCKET="${BACKUP_BUCKET:?BACKUP_BUCKET is required}"
PREFIX="${BACKUP_PREFIX:-pg}"
PG_CONTAINER="${PG_CONTAINER:-gateway-postgres}"
PG_USER="${PG_USER:-gateway}"
PG_DB="${PG_DB:-llmgateway}"

ts="$(date -u +%Y%m%d-%H%M%SZ)"
key="s3://${BUCKET}/${PREFIX}/${PG_DB}-${ts}.sql.gz"

# --clean --if-exists makes the dump safely restorable onto an existing database.
docker exec "$PG_CONTAINER" pg_dump -U "$PG_USER" -d "$PG_DB" --clean --if-exists \
  | gzip -9 \
  | aws s3 cp - "$key" --content-type application/gzip --only-show-errors

echo "$(date -u +%FT%TZ) backup ok -> $key"
