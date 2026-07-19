# Protecting the gateway's Postgres data

The gateway keeps all durable state — users, orgs, API keys, audit logs — in a **single Docker
named volume (`postgres_data`) on one EC2 instance**. That volume survives app rebuilds and
reboots, but it is lost if the instance is terminated or the volume is deleted. This doc makes the
data recoverable.

## Risk model (what keeps vs. destroys data)

| Action | Data |
|---|---|
| In-place deploy: `git pull` + `docker compose up -d --build` | ✅ preserved (named volume) |
| Instance reboot / stop-start | ✅ preserved |
| `docker compose down` (no `-v`) | ✅ preserved |
| `docker compose down -v` | ❌ volume deleted |
| `down.ps1` (terminates the instance) | ❌ gone |
| `up.ps1` (provisions a fresh instance) | ❌ new empty DB + new secrets |
| Instance/EBS failure with no backup | ❌ gone |

## Tier 0 — do this right now (10s, zero infra)

Pull a compressed dump to your local machine before any deploy:

```bash
ssh -i deploy/aws/llm-gateway-key.pem ec2-user@3.81.99.148 \
  'sudo docker exec gateway-postgres pg_dump -U gateway llmgateway | gzip' \
  > "llmgateway-$(date +%Y%m%d-%H%M%S).sql.gz"
```

Keep that file safe. Restore instructions are at the bottom.

## Tier 1 — automated nightly backups to S3 (recommended)

Because the instance has **no IAM role** today, give it one (attachable to the *running* box, no
downtime, no data loss), then install a nightly timer. Run the AWS commands with credentials that
have IAM/S3 admin (the limited `deployuser` will not have IAM permissions).

**1. Bucket with 30-day retention + versioning:**
```bash
ACCT=$(aws sts get-caller-identity --query Account --output text)
BUCKET="llm-gateway-backups-$ACCT"
aws s3api create-bucket --bucket "$BUCKET" --region us-east-1
aws s3api put-bucket-versioning --bucket "$BUCKET" --versioning-configuration Status=Enabled
aws s3api put-bucket-lifecycle-configuration --bucket "$BUCKET" --lifecycle-configuration '{
  "Rules":[{"ID":"expire-30d","Status":"Enabled","Filter":{"Prefix":"pg/"},
            "Expiration":{"Days":30},
            "NoncurrentVersionExpiration":{"NoncurrentDays":30}}]}'
```

**2. IAM role limited to writing this bucket, attached to the running instance:**
```bash
cat > /tmp/trust.json <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
 "Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}
JSON
aws iam create-role --role-name llm-gateway-backup-role --assume-role-policy-document file:///tmp/trust.json
aws iam put-role-policy --role-name llm-gateway-backup-role --policy-name s3-backup-write \
  --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[
    {\"Effect\":\"Allow\",\"Action\":[\"s3:PutObject\"],\"Resource\":\"arn:aws:s3:::$BUCKET/pg/*\"}]}"
aws iam create-instance-profile --instance-profile-name llm-gateway-backup-profile
aws iam add-role-to-instance-profile --instance-profile-name llm-gateway-backup-profile \
  --role-name llm-gateway-backup-role
# Attach to the RUNNING instance (no restart, no data loss):
aws ec2 associate-iam-instance-profile --instance-id i-03a3f93f713ae172c \
  --iam-instance-profile Name=llm-gateway-backup-profile --region us-east-1
```

**3. Install the timer on the box** (`pg-backup.sh` ships in this repo at `/opt/llm-gateway/deploy/aws/`):
```bash
ssh -i deploy/aws/llm-gateway-key.pem ec2-user@3.81.99.148 "sudo bash -s" <<EOF
set -e
install -m 0755 /opt/llm-gateway/deploy/aws/pg-backup.sh /usr/local/bin/pg-backup.sh
cat >/etc/systemd/system/llm-gateway-backup.service <<UNIT
[Unit]
Description=LLM Gateway Postgres backup to S3
After=docker.service
[Service]
Type=oneshot
Environment=BACKUP_BUCKET=$BUCKET
ExecStart=/usr/local/bin/pg-backup.sh
UNIT
cat >/etc/systemd/system/llm-gateway-backup.timer <<UNIT
[Unit]
Description=Nightly LLM Gateway Postgres backup
[Timer]
OnCalendar=*-*-* 03:30:00 UTC
Persistent=true
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now llm-gateway-backup.timer
systemctl start llm-gateway-backup.service   # run one immediately
EOF
```
Verify: `aws s3 ls s3://$BUCKET/pg/` should show a fresh dump.

## Tier 2 — bulletproof (if this becomes production-critical)

Move Postgres off the box to **Amazon RDS** (managed automated backups + point-in-time recovery,
survives instance loss entirely). Bigger change and higher cost than the single-box demo; do it if
uptime/durability guarantees start to matter. Point `SPRING_DATASOURCE_URL` at the RDS endpoint and
drop the `postgres` service from docker-compose.

## Restore

Onto the running box (the dump uses `--clean --if-exists`, so it replaces existing objects):
```bash
# from S3:
aws s3 cp s3://$BUCKET/pg/llmgateway-<TS>.sql.gz - | gunzip \
  | ssh -i deploy/aws/llm-gateway-key.pem ec2-user@3.81.99.148 \
      'sudo docker exec -i gateway-postgres psql -U gateway -d llmgateway'

# from a local Tier-0 dump:
gunzip -c llmgateway-<TS>.sql.gz \
  | ssh -i deploy/aws/llm-gateway-key.pem ec2-user@3.81.99.148 \
      'sudo docker exec -i gateway-postgres psql -U gateway -d llmgateway'
```
