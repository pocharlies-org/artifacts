#!/usr/bin/env bash
# e2e.sh — end-to-end test of the local stack: publish with the CLI, read anonymously
# (pub/), read gated (302 without login, 200 with a Dex id_token as Bearer), and the
# negative checks (no .acl.json, no _plugins/, no listing, no writes, no query strings, no
# client S3 headers, the gate never signs with MinIO root).
# Requires: docker compose, curl, python3. The publisher renders .md inputs with the
# python 'markdown' package (.html inputs need nothing); if it is not importable this
# script creates a local .venv (gitignored) and installs it there.
# Run after: docker compose up -d && docker compose up bootstrap
set -uo pipefail
cd "$(dirname "$0")"

# markdown package for the publisher's .md rendering (PEP 668-safe: local venv)
if ! python3 -c "import markdown" >/dev/null 2>&1; then
  [ -d .venv ] || python3 -m venv .venv
  .venv/bin/pip install -q markdown
  export PATH="$PWD/.venv/bin:$PATH"
fi

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
# oauth2-proxy (the gate's identity backend) must answer too, or gated reads 500
for i in $(seq 1 60); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/oauth2/sign_in")
  [[ "$code" != 000 && "$code" != 502 ]] && break
  sleep 2
done
[[ "$code" != 000 && "$code" != 502 ]] || { echo "oauth2-proxy not ready ($code)"; exit 1; }

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

# ---- pub/ never serves an ACL or a listing anonymously -----------------------------------
# Seed a pub/ .acl.json through the admin path (the publisher refuses to write one): the
# anonymous pub/ rule must 404 it, not hand it out, and must 404 the directory itself.
mc_admin() { docker compose exec -T minio sh -ec "export PATH=/opt/bitnami/minio-client/bin:\$PATH; $1"; }
echo '{"owner":"seeded@example.com","users":["leak@example.com"]}' \
  | mc_admin "mc pipe local/artifacts/pub/$RUN/.acl.json >/dev/null" \
  || { echo "FAIL: could not seed pub/ .acl.json"; fail=1; }
check "anonymous pub .acl.json not served" 404 "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/artifacts/pub/$RUN/.acl.json")"
check "anonymous pub .acl.json body leaks nothing" 0 "$(curl -s "$BASE/artifacts/pub/$RUN/.acl.json" | grep -c 'seeded@example.com')"
check "anonymous pub dir not served" 404 "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/artifacts/pub/$RUN/")"
check "anonymous pub dir is no MinIO XML" 0 "$(curl -s "$BASE/artifacts/pub/$RUN/" | grep -c '<Error>')"

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
  -d 'grant_type=password&username=test@example.com&password=test-password&client_id=artifacts-dev&client_secret=artifacts-dev-secret-not-a-real-secret&scope=openid email profile' \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["id_token"])')
# the second and third static Dex users exist (plugins test sharing and refusals with them)
for n in 2 3; do
  tok=$(curl -sf -X POST http://127.0.0.1:5556/dex/token \
    -d "grant_type=password&username=test$n@example.com&password=test$n-password&client_id=artifacts-dev&client_secret=artifacts-dev-secret-not-a-real-secret&scope=openid email profile" \
    | python3 -c 'import json,sys;print(json.load(sys.stdin)["id_token"])' 2>/dev/null)
  check "Dex user test$n logs in" yes "$([[ -n "$tok" ]] && echo yes || echo no)"
  # signed in, but not on the ACL of a test@example.com artifact: the deny page, never the object
  check "test$n is denied test@example.com's artifact" 403 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $tok" "$GATED_URL")"
done
check "gated read with Bearer id_token" 200 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$GATED_URL")"
check "gated HEAD with Bearer id_token" 200 "$(curl -s -o /dev/null -I -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$GATED_URL")"
check "gated CSP sandbox" "sandbox allow-scripts" \
  "$(curl -sI -H "Authorization: Bearer $TOKEN" "$GATED_URL" | tr -d '\r' | awk -F': ' 'tolower($1)=="content-security-policy"{print $2}')"
# the gate signs the upstream read; MinIO itself serves nothing anonymously off pub/
check "direct anonymous MinIO read of u/ refused" 403 "$(curl -s -o /dev/null -w '%{http_code}' "$S3/artifacts/u/$RUN2/index.html")"
check "S3 response override query refused" 404 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$GATED_URL?response-content-type=text/plain")"

# ---- query strings: allow-list (empty) -> every query 404s, unsigned, never reaches MinIO --
for q in 'lambdaArn=arn:minio:s3-object-lambda::x:webhook' acl ACL '%61cl' 'acl%00' '%20acl' \
         'acl&acl' 'acl;x=1' '' 'v=2'; do
  check "query ?$q refused" 404 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$GATED_URL?$q")"
done
check "?lambdaArn= answer is the gate's page, not MinIO XML" 0 \
  "$(curl -s -H "Authorization: Bearer $TOKEN" "$GATED_URL?lambdaArn=arn:minio:s3-object-lambda::x:webhook" | grep -c '<Error>')"

# ---- client x-amz-*/x-minio-* headers are refused before the gate signs -----------------
check "x-amz SSE-C header refused" 400 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" -H 'X-Amz-Server-Side-Encryption-Customer-Algorithm: AES256' "$GATED_URL")"
check "x-amz-checksum-mode header refused" 400 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" -H 'X-Amz-Checksum-Mode: ENABLED' "$GATED_URL")"
check "x-minio-* header refused" 400 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" -H 'X-Minio-Extract: true' "$GATED_URL")"

# ---- the forwarded-read signature is NOT MinIO root ------------------------------------
# Ask the decision listener directly from inside the gate container (it is never routed) and
# read the Credential of the Authorization header it hands to the proxy.
cred=$(docker compose exec -T -e TOKEN="$TOKEN" -e URI="/artifacts/u/$RUN2/index.html" gate python3 -c '
import os, re, urllib.request
r = urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:8081/_gate/auth", headers={
    "X-Forwarded-Method": "GET", "X-Forwarded-Uri": os.environ["URI"],
    "X-Forwarded-Host": "127.0.0.1:8080", "Authorization": "Bearer " + os.environ["TOKEN"]}))
print(re.search(r"Credential=([^/]+)/", r.headers["Authorization"]).group(1))')
check "forwarded read signed by the read-signing user" artifact-reader "$cred"
[[ "$cred" != minioadmin ]] && echo "PASS: forwarded read not signed with MinIO root ($cred)" \
  || { echo "FAIL: forwarded read signed with MinIO root"; fail=1; }
# plugin authz (docs/plugins.md §1) against the real MinIO: the ttl tag and the expiry come
# back (GetObjectTagging is signed correctly); the anonymous pub/ case runs after the MCP
# publish below (pub/$RUN carries the seeded .acl.json from above)
authz() { # <artifact path> [bearer]
  docker compose exec -T -e A="$1" -e TOKEN="${2:-}" gate python3 -c '
import json, os, urllib.request
h = {"Content-Type": "application/json"}
if os.environ["TOKEN"]: h["Authorization"] = "Bearer " + os.environ["TOKEN"]
r = urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:8081/_gate/plugin/authz",
    data=json.dumps({"artifact": os.environ["A"]}).encode(), headers=h))
a = json.load(r)
print(a["allowed"], a["reason"], a["user"]["id"], a["artifact"]["ttl"], bool(a["artifact"]["expires"]))'
}
check "plugin authz: ACL user on u/ carries ttl + expiry" "True user test@example.com 1 True" \
  "$(authz "/artifacts/u/$RUN2/index.html" "$TOKEN")"
check "plugin authz: anonymous on u/ is unauthenticated" "False unauthenticated None None False" \
  "$(authz "/artifacts/u/$RUN2/index.html")"
# display name: the id_token `name` claim (Dex username), never the e-mail; identity stays the e-mail
authz_user() { # <artifact path> <bearer>
  docker compose exec -T -e A="$1" -e TOKEN="$2" gate python3 -c '
import json, os, urllib.request
r = urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:8081/_gate/plugin/authz",
    data=json.dumps({"artifact": os.environ["A"]}).encode(),
    headers={"Content-Type": "application/json", "Authorization": "Bearer " + os.environ["TOKEN"]}))
u = json.load(r)["user"]
print(u["id"], "|", u["name"])'
}
check "plugin authz: display name from the name claim" "test@example.com | Test One" \
  "$(authz_user "/artifacts/u/$RUN2/index.html" "$TOKEN")"
# oauth2-proxy's /auth (answers 202 + the session's id_token) is never reachable from the
# browser side, in any spelling oauth2-proxy (or a path cleaner in front of it) would route
# to it — oauth2-proxy decodes the path again, so double/triple encodings count too.
# --path-as-is sends each spelling verbatim.
for p in /oauth2/auth /oauth2/auth/ '/oauth2/auth;x' /oauth2/auth%2f /oauth2/auth%2F /oauth2/auth/x \
         '/oauth2/auth?x=1' //oauth2/auth /oauth2//auth /oauth2/./auth /oauth2/x/../auth \
         /oauth2/%61uth /oauth2/%2561uth /oauth2/%252561uth /oauth2/%2561UTH /oauth2/x%252f..%252fauth \
         /oauth2/AUTH /OAUTH2/auth /oauth2/Auth/; do
  hdrs=$(curl -s --path-as-is -D - -o /dev/null -H "Authorization: Bearer $TOKEN" "$BASE$p")
  code=$(printf '%s' "$hdrs" | awk 'NR==1{print $2}')
  leak=$(printf '%s' "$hdrs" | grep -ciE '^(authorization|x-auth-request-email):')
  check "oauth2-proxy /auth not reachable from the browser side: $p" "404 0" "$code $leak"
done
# the browser endpoints oauth2-proxy must keep serving
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/oauth2/sign_in")
[[ "$code" == 200 || "$code" == 302 ]] && echo "PASS: oauth2-proxy sign_in still routed ($code)" \
  || { echo "FAIL: oauth2-proxy sign_in not routed ($code)"; fail=1; }
gate_env=$(docker compose exec -T gate sh -c 'echo "$MINIO_ACCESS_KEY $MINIO_SECRET_KEY $GATE_READ_ACCESS_KEY $GATE_READ_SECRET_KEY"')
check "gate holds no MinIO root credential" 0 "$(echo "$gate_env" | tr ' ' '\n' | grep -cx minioadmin)"
# the read-signing user: reads artifacts, nothing else (ACLs, state, listing, writes denied)
if mc_admin "mc alias set e2e-read http://localhost:9000 artifact-reader artifact-reader-dev-password >/dev/null
  mc cat e2e-read/artifacts/u/$RUN2/index.html >/dev/null"; then
  echo "PASS: read user reads an artifact"; else echo "FAIL: read user cannot read an artifact"; fail=1; fi
for probe in "mc cat e2e-read/artifacts/u/$RUN2/.acl.json" "mc cat e2e-read/artifacts/pub/$RUN/.acl.json" \
             "echo x | mc pipe e2e-read/artifacts/_gate/e2e-probe.json" "mc ls e2e-read/artifacts/" \
             "echo x | mc pipe e2e-read/artifacts/u/$RUN2/index.html"; do
  if mc_admin "$probe >/dev/null 2>&1"; then echo "FAIL: read user allowed: $probe"; fail=1
  else echo "PASS: read user denied: ${probe%% e2e-read*} ${probe##* }"; fi
done
mc_admin "mc alias rm e2e-read >/dev/null" || true

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
# forwardAuth answers 404 for every never-served key (ACLs, state, listings, traversal)
check "traversal refused" 404 "$(curl -s -o /dev/null -w '%{http_code}' --path-as-is "$BASE/artifacts/u/$RUN2/../..%2f.acl.json" -H "Authorization: Bearer $TOKEN")"

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
check "plugin authz: anonymous pub/ carries ttl + expiry" "True pub: anonymous (anonymous-pub enabled) None 1 True" \
  "$(authz "/artifacts/$MCP_KEY")"
[[ "$MCP_URL" == "$BASE/_canvas/artifacts/$MCP_KEY" ]] \
  && echo "PASS: MCP printed the plugin link" || { echo "FAIL: MCP plugin link wrong: $MCP_URL"; fail=1; }

echo
[[ $fail -eq 0 ]] && echo "E2E: ALL CHECKS PASSED" || echo "E2E: FAILURES (see above)"
exit $fail
