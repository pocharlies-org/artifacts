#!/bin/sh
# bootstrap.sh — one-shot local stack setup: bucket, ILM expiry rules, anonymous pub/, the
# two non-root S3 users the gate runs with and a non-root publisher user. Mirrors the Helm bootstrap Job
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
: "${PUBLISHER_USER:=artifact-publisher}"
: "${PUBLISHER_PASSWORD:=artifact-publisher-dev-password}"
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
# Publisher user (same policy as the Helm bootstrap Job): writes artifacts and their
# .acl.json (publishing needs it), lists the bucket, and has an explicit Deny on gate state
# (_gate/) and plugin storage (_plugins/). e2e.sh publishes with it and checks the Deny.
cat > /tmp/policy-publisher.json <<JSON
{"Version":"2012-10-17","Statement":[
  {"Effect":"Allow","Action":["s3:PutObject","s3:PutObjectTagging","s3:GetObject","s3:GetObjectTagging"],"Resource":["arn:aws:s3:::${BUCKET}/*"]},
  {"Effect":"Allow","Action":["s3:ListBucket"],"Resource":["arn:aws:s3:::${BUCKET}"]},
  {"Effect":"Deny","Action":["s3:*"],"Resource":["arn:aws:s3:::${BUCKET}/_gate/*","arn:aws:s3:::${BUCKET}/_plugins/*"]}]}
JSON
# `policy create` overwrites an existing policy; `user add` updates the secret; attach is
# idempotent. Form: mc admin <cmd> ALIAS NAME ... (never ALIAS/NAME).
mc admin policy create local artifact-gate /tmp/policy-gate.json >/dev/null
mc admin policy create local artifact-gate-read /tmp/policy-gate-read.json >/dev/null
mc admin user add local "$GATE_USER" "$GATE_PASSWORD" >/dev/null
mc admin policy attach local artifact-gate --user "$GATE_USER" >/dev/null
mc admin user add local "$READ_USER" "$READ_PASSWORD" >/dev/null
mc admin policy attach local artifact-gate-read --user "$READ_USER" >/dev/null
mc admin policy create local artifact-publisher /tmp/policy-publisher.json >/dev/null
mc admin user add local "$PUBLISHER_USER" "$PUBLISHER_PASSWORD" >/dev/null
mc admin policy attach local artifact-publisher --user "$PUBLISHER_USER" >/dev/null

# Plugin users (docs/plugins.md §3, same policy as the Helm bootstrap Job): PLUGIN_USERS is
# `<name>:<secret>[,<name>:<secret>...]` (dev placeholders from the plugin's compose file).
# User plugin-<name>: Get/Put/Delete/Tagging on _plugins/<name>/* and ListBucket restricted
# to that prefix, nothing else.
PLUGINS_DONE=""
for entry in $(printf '%s' "${PLUGIN_USERS:-}" | tr ',' ' '); do
  name="${entry%%:*}"; secret="${entry#*:}"
  if ! printf '%s' "$name" | grep -Eq '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$' || [ "$secret" = "$entry" ] || [ -z "$secret" ]; then
    echo "PLUGIN_USERS entry '$name' must be <dns-1123-name>:<secret>" >&2; exit 1
  fi
  cat > "/tmp/policy-plugin-$name.json" <<JSON
{"Version":"2012-10-17","Statement":[
  {"Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:DeleteObject","s3:GetObjectTagging","s3:PutObjectTagging"],"Resource":["arn:aws:s3:::${BUCKET}/_plugins/${name}/*"]},
  {"Effect":"Allow","Action":["s3:ListBucket"],"Resource":["arn:aws:s3:::${BUCKET}"],"Condition":{"StringLike":{"s3:prefix":["_plugins/${name}/*"]}}}]}
JSON
  mc admin policy create local "plugin-$name" "/tmp/policy-plugin-$name.json" >/dev/null
  mc admin user add local "plugin-$name" "$secret" >/dev/null
  mc admin policy attach local "plugin-$name" --user "plugin-$name" >/dev/null
  PLUGINS_DONE="$PLUGINS_DONE plugin-$name"
done
echo "bootstrap done: bucket=$BUCKET users=$GATE_USER,$READ_USER,$PUBLISHER_USER plugins=[${PLUGINS_DONE# }]"
