#!/usr/bin/env bash
# e2e.sh — end-to-end test of the local stack: publish with the CLI, read anonymously
# (pub/), read gated (302 without login, 200 with a Dex id_token as Bearer), and the
# negative checks (no .acl.json, no _plugins/, no listing, no writes).
# Requires: docker compose, curl, python3 + the python 'markdown' package
# (pip3 install markdown — only needed to publish .md inputs; .html inputs need nothing).
# Run after: docker compose up -d && docker compose up bootstrap
set -uo pipefail
cd "$(dirname "$0")"
BASE=http://127.0.0.1:8080
S3=http://127.0.0.1:9000
fail=0
check() { # <desc> <expected> <actual>
  if [[ "$3" == "$2" ]]; then echo "PASS: $1 ($3)"; else echo "FAIL: $1 (expected $2, got $3)"; fail=1; fi
}

# ---- wait for the stack ---------------------------------------------------------------
for i in $(seq 1 60); do
  curl -sf "$BASE/_gate/healthz" >/dev/null 2>&1 && break
  sleep 2
done
curl -sf "$BASE/_gate/healthz" >/dev/null || { echo "stack not ready"; exit 1; }

# ---- publish a pub/ artifact with the CLI (prints plugin links) ------------------------
RUN="e2e-$(date +%s)"
echo "hello e2e" > /tmp/e2e-note.md
out=$(ARTIFACTS_ACCESS_KEY=minioadmin ARTIFACTS_SECRET_KEY=minioadmin \
  ARTIFACTS_WRITE_BASE="$S3" ARTIFACTS_READ_BASE="$BASE" \
  ARTIFACTS_PLUGINS="canvas=/_canvas/" \
  bash ../../cli/publish.sh -g pub -r "$RUN" -t 1 -a e2e -s compose /tmp/e2e-note.md) \
  || { echo "CLI publish failed"; exit 1; }
echo "$out" | sed 's/^/  cli| /'
echo "$out" | grep -q "open with canvas: $BASE/_canvas/artifacts/pub/$RUN/index.html" \
  && echo "PASS: CLI printed the plugin link" || { echo "FAIL: plugin link missing"; fail=1; }
PUB_URL="$BASE/artifacts/pub/$RUN/index.html"

# ---- anonymous pub/ read ---------------------------------------------------------------
check "anonymous pub read" 200 "$(curl -s -o /dev/null -w '%{http_code}' "$PUB_URL")"
check "pub CSP sandbox" "sandbox allow-scripts" \
  "$(curl -sI "$PUB_URL" | tr -d '\r' | awk -F': ' 'tolower($1)=="content-security-policy"{print $2}' | tr -d '\r')"

# ---- gated read: 302 without login -------------------------------------------------------
RUN2="e2e-priv-$(date +%s)"
ARTIFACTS_ACCESS_KEY=minioadmin ARTIFACTS_SECRET_KEY=minioadmin \
  ARTIFACTS_WRITE_BASE="$S3" ARTIFACTS_READ_BASE="$BASE" \
  bash ../../cli/publish.sh -u test@example.com -r "$RUN2" -t 1 -a e2e -s compose /tmp/e2e-note.md >/dev/null \
  || { echo "CLI private publish failed"; exit 1; }
GATED_URL="$BASE/artifacts/u/$RUN2/index.html"
check "gated read redirects to login" 302 "$(curl -s -o /dev/null -w '%{http_code}' "$GATED_URL")"

# ---- gated read: 200 with a Dex id_token as Bearer --------------------------------------
TOKEN=$(curl -sf -X POST http://127.0.0.1:5556/dex/token \
  -d 'grant_type=password&username=test@example.com&password=test-password&client_id=artifacts-dev&client_secret=artifacts-dev-secret-not-a-real-secret&scope=openid' \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["id_token"])')
check "gated read with Bearer id_token" 200 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$GATED_URL")"

# ---- bootstrap-job regression: two-arg `mc admin user add` against real MinIO -----------
# (helm/artifacts/templates/bootstrap-job.yaml uses the same command shape; the one-arg
# form silently created a user with a wrong secret)
if docker compose exec -T minio sh -ec 'export PATH=/opt/bitnami/minio-client/bin:$PATH
  mc admin user add local e2e-regression-key e2e-secret-key >/dev/null 2>&1
  mc admin user list local | grep -q e2e-regression-key
  mc admin user rm local e2e-regression-key >/dev/null 2>&1'; then
  echo "PASS: mc admin user add two-arg form (bootstrap-job regression)"
else
  echo "FAIL: mc admin user add two-arg form (bootstrap-job regression)"; fail=1
fi

# ---- negatives ---------------------------------------------------------------------------
check "acl.json not served" 404 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$BASE/artifacts/u/$RUN2/.acl.json")"
check "listing not served" 404 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$BASE/artifacts/?list-type=2")"
check "_plugins not served" 404 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$BASE/artifacts/_plugins/canvas/x.bin")"
check "_gate state not served" 404 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$BASE/artifacts/_gate/req/x.json")"
check "writes refused (PUT)" 405 "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -d x "$BASE/artifacts/whatever")"
check "traversal refused" 400 "$(curl -s -o /dev/null -w '%{http_code}' --path-as-is "$BASE/artifacts/u/$RUN2/../..%2f.acl.json" -H "Authorization: Bearer $TOKEN")"

# ---- MCP publish (stdlib lib path; the SDK wiring is unit-tested) ------------------------
mcp_out=$(cd ../../mcp && ARTIFACTS_ENDPOINT="$S3" ARTIFACTS_ACCESS_KEY=minioadmin \
  ARTIFACTS_SECRET_KEY=minioadmin ARTIFACTS_READ_BASE="$BASE" \
  ARTIFACTS_PLUGINS="canvas=/_canvas/" python3 - <<'PY'
import artifacts_lib as al
key = al.key_for_html("mcp e2e", public=True)
al.S3Client().put(key, b"<html><body>mcp</body></html>", "text/html; charset=utf-8", 1)
print(key)
print(al.plugin_links(al.env("ARTIFACTS_READ_BASE"), key)[0]["url"])
PY
) || { echo "MCP publish failed"; fail=1; }
echo "$mcp_out" | sed 's/^/  mcp| /'
MCP_KEY=$(echo "$mcp_out" | head -1)
MCP_URL=$(echo "$mcp_out" | tail -1)
check "MCP artifact readable" 200 "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/artifacts/$MCP_KEY")"
[[ "$MCP_URL" == "$BASE/_canvas/artifacts/$MCP_KEY" ]] \
  && echo "PASS: MCP printed the plugin link" || { echo "FAIL: MCP plugin link wrong: $MCP_URL"; fail=1; }

echo
[[ $fail -eq 0 ]] && echo "E2E: ALL CHECKS PASSED" || echo "E2E: FAILURES (see above)"
exit $fail
