#!/bin/sh
# bootstrap.sh — one-shot local stack setup: bucket, ILM expiry rules, anonymous pub/.
# Mirrors the Helm bootstrap Job (helm/artifacts/templates/bootstrap-job.yaml).
set -eu
: "${BUCKET:=artifacts}"
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
echo "bootstrap done: bucket=$BUCKET"
