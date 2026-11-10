#!/bin/sh
# bootstrap.sh — one-shot local stack setup: bucket, ILM expiry rules, anonymous pub/ and the
# two non-root S3 users the gate runs with. Mirrors the Helm bootstrap Job
# (helm/artifacts/templates/bootstrap-job.yaml). Root (minioadmin) is used HERE ONLY, to set
# things up; the gate never holds it.
set -eu
# mc ships inside the bitnamilegacy/minio image (see docker-compose.yml)
export PATH="/opt/bitnami/minio-client/bin:$PATH"
: "${BUCKET:=artifacts}"
# dev-only placeholder credentials, same values as the gate service in docker-compose.yml
: "${GATE_USER:=artifact-gate}"
: "${GATE_PASSWORD:=artifact-gate-dev-password}"
: "${READ_USER:=artifact-reader}"
: "${READ_PASSWORD:=artifact-reader-dev-password}"
mc alias set local http://minio:9000 minioadmin minioadmin
mc mb -p "local/$BUCKET" >/dev/null 2>&1 || true

# ILM: ttl-tag rules + bucket-wide 90-day catch-all (covers _plugins/ too).
mc ilm rule rm --all --force "local/$BUCKET" >/dev/null 2>&1 || true
for d in 1 7 14 30; do
  mc ilm rule add --expire-days "$d" --tags "ttl=$d" "local/$BUCKET" >/dev/null
done
mc ilm rule add --expire-days 90 "local/$BUCKET" >/dev/null

# Anonymous pub/ (dev stack only: the host is loopback, never publicly exposed).
cat > /tmp/anonymous-pub.json <<JSON
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::${BUCKET}/pub/*"]}]}
JSON
mc anonymous set-json /tmp/anonymous-pub.json "local/$BUCKET" >/dev/null

# Gate user: ACL + state work (HEAD/GET/tagging on the bucket, writes only to ACLs and _gate/).
cat > /tmp/policy-gate.json <<JSON
{"Version":"2012-10-17","Statement":[
  {"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectTagging"],"Resource":["arn:aws:s3:::${BUCKET}/*"]},
  {"Effect":"Allow","Action":["s3:PutObject"],"Resource":["arn:aws:s3:::${BUCKET}/*/.acl.json","arn:aws:s3:::${BUCKET}/_gate/*"]}]}
JSON
# Read-signing user: signs ONLY the forwarded artifact reads. GetObject on the bucket, nothing
# else, and an explicit Deny on gate state, plugin storage and every ACL file.
cat > /tmp/policy-gate-read.json <<JSON
{"Version":"2012-10-17","Statement":[
  {"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::${BUCKET}/*"]},
  {"Effect":"Deny","Action":["s3:*"],"Resource":["arn:aws:s3:::${BUCKET}/_gate/*","arn:aws:s3:::${BUCKET}/_plugins/*","arn:aws:s3:::${BUCKET}/*/.acl.json","arn:aws:s3:::${BUCKET}/.acl.json"]}]}
JSON
# `policy create` overwrites an existing policy; `user add` updates the secret; attach is
# idempotent. Form: mc admin <cmd> ALIAS NAME ... (never ALIAS/NAME).
mc admin policy create local artifact-gate /tmp/policy-gate.json >/dev/null
mc admin policy create local artifact-gate-read /tmp/policy-gate-read.json >/dev/null
mc admin user add local "$GATE_USER" "$GATE_PASSWORD" >/dev/null
mc admin policy attach local artifact-gate --user "$GATE_USER" >/dev/null
mc admin user add local "$READ_USER" "$READ_PASSWORD" >/dev/null
mc admin policy attach local artifact-gate-read --user "$READ_USER" >/dev/null
echo "bootstrap done: bucket=$BUCKET users=$GATE_USER,$READ_USER"
