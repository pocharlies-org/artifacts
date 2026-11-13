#!/usr/bin/env bash
# e2e.sh — end-to-end test of the local stack: publish with the CLI, read anonymously
# (pub/), read gated (302 without login, 200 with a Dex id_token as Bearer, 200 after a
# browser login through sign_in/Dex/callback), and the
# negative checks (no .acl.json, no _plugins/, no listing, no writes, no query strings, no
# client S3 headers, the gate never signs with MinIO root). The anonymous pub/ route follows
# the caddy service's ARTIFACTS_PUB_MODE (direct by default, or gate: the gate's anonymous
# decision first); the gate-mode checks run when the stack was started with
# ARTIFACTS_PUB_MODE=gate.
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
# The gate's health check is not routed through Caddy (rule 4 keeps /_gate/healthz,
# /_gate/auth and /_gate/plugin/ off the public route), so: the gate answers its own healthz
# inside its container, and a write through Caddy gets the gate's 405 (Caddy and the gate up).
gate_ready() {
  docker compose exec -T gate python3 -c 'import urllib.request
urllib.request.urlopen("http://127.0.0.1:8080/_gate/healthz", timeout=2)' >/dev/null 2>&1 \
    && [[ "$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$BASE/artifacts/_ready")" == 405 ]]
}
for i in $(seq 1 60); do
  gate_ready && break
  sleep 2
done
gate_ready || { echo "stack not ready"; exit 1; }
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
check "pub nosniff" "nosniff" \
  "$(curl -sI "$PUB_URL" | tr -d '\r' | awk -F': ' 'tolower($1)=="x-content-type-options"{print $2}')"
check "pub no-referrer" "no-referrer" \
  "$(curl -sI "$PUB_URL" | tr -d '\r' | awk -F': ' 'tolower($1)=="referrer-policy"{print $2}')"

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

# ---- anonymous pub/: the traversal probe list never returns an object (both modes) ------
# Canaries in u/, g/, acl/ and _gate/ (no ACL, so a mis-decided key would be readable); each
# probe spelling is sent as is (--path-as-is), with no session.
CAN="e2e-canary-$(date +%s)"
CANARIES=("u/$CAN/c.html" "g/team/$CAN/c.html" "acl/$CAN.html" "_gate/$CAN.json")
for k in "${CANARIES[@]}"; do
  echo "CANARY-$CAN" | mc_admin "mc pipe local/artifacts/$k >/dev/null" \
    || { echo "FAIL: could not seed canary $k"; fail=1; }
done
canary_hits=0; probes=0
for k in "${CANARIES[@]}"; do
  for s in "pub/../$k" "pub/%2e%2e/$k" "pub/%252e%252e/$k" "pub//../$k" "pub/x;/../$k" \
           "pub/$RUN/..%2f..%2f$k" "pub/%5c..%5c$k"; do
    probes=$((probes + 1))
    canary_hits=$((canary_hits + $(curl -s --path-as-is "$BASE/artifacts/$s" | grep -c "CANARY-$CAN")))
  done
done
check "anonymous pub/ traversal probes return no canary ($probes probes)" 0 "$canary_hits"

# ---- anonymous pub/ through the gate (ARTIFACTS_PUB_MODE=gate) ---------------------------
# The caddy service says which rule 2 runs: direct (default, straight to MinIO) or gate (the
# gate's anonymous decision, /_gate/pub-auth). In gate mode: a missing key, a key whose pub
# root has an ACL, an .acl.json and a listing all get the gate's one 404 page (same status,
# headers and body, GET and HEAD), with the sandbox CSP and nothing from MinIO; a forwarded
# URI the client sends is ignored; /_gate/auth stays the signed-in decision.
PUB_MODE=$(docker compose exec -T caddy printenv ARTIFACTS_PUB_MODE 2>/dev/null | tr -d '\r')
PUB_MODE=${PUB_MODE:-direct}
echo "INFO: anonymous pub/ route mode: $PUB_MODE"
check "/_gate/pub-auth not routed to the gate" "404 0" \
  "$(curl -s -o /dev/null -w '%{http_code} %{size_download}' "$BASE/_gate/pub-auth")"
if [[ "$PUB_MODE" == gate ]]; then
  # pub/$RUN carries the stray .acl.json seeded above. Seeded here, before any read (no cached
  # answer helps): an open run (no ACL) and a closed one (a stray ACL at its pub root).
  OPEN="e2e-open-$CAN"; CLOSED="e2e-closed-$CAN"
  echo "OPEN-$CAN" | mc_admin "mc pipe local/artifacts/pub/$OPEN/index.html >/dev/null" \
    && echo '<h1>closed</h1>' | mc_admin "mc pipe local/artifacts/pub/$CLOSED/sub/index.html >/dev/null" \
    && echo '{"owner":"test@example.com","users":["test@example.com"]}' \
       | mc_admin "mc pipe local/artifacts/pub/$CLOSED/.acl.json >/dev/null" \
    || { echo "FAIL: could not seed the open and closed pub/ runs"; fail=1; }
  answer() { # <GET|HEAD> <url>: status line, headers without Date, body
    if [[ "$1" == HEAD ]]; then curl -s -I --path-as-is "$2"; else curl -s -D - --path-as-is "$2"; fi \
      | tr -d '\r' | grep -viE '^date:'
  }
  check "gate mode: an open pub/ object is served anonymously" 1 \
    "$(curl -s "$BASE/artifacts/pub/$OPEN/index.html" | grep -c "OPEN-$CAN")"
  MISSING="$BASE/artifacts/pub/e2e-none-$CAN/missing.html"
  ref_get=$(answer GET "$MISSING")
  ref_head=$(answer HEAD "$MISSING")
  check "gate mode: a missing pub/ key answers 404" 1 "$(printf '%s\n' "$ref_get" | head -1 | grep -c ' 404')"
  check "gate mode: the 404 is the gate's page (text/html)" 1 "$(printf '%s\n' "$ref_get" | grep -ci '^content-type: text/html')"
  check "gate mode: the 404 carries the sandbox CSP" 1 "$(printf '%s\n' "$ref_get" | grep -ci '^content-security-policy: sandbox allow-scripts$')"
  check "gate mode: nothing from MinIO (NoSuchKey, XML, server: MinIO)" 0 "$(printf '%s\n' "$ref_get" | grep -ciE 'NoSuchKey|<\?xml|^server: minio')"
  check "gate mode: no login redirect" 0 "$(printf '%s\n' "$ref_get" | grep -ci '^location:')"
  # (not pub/$RUN/index.html: it was read before its stray ACL was seeded, and the gate's ACL
  # cache, GATE_ACL_CACHE_SECONDS, may still hold "no ACL" for it; $CLOSED is that case)
  for u in "pub/$CLOSED/sub/index.html" "pub/$CLOSED/.acl.json" \
           "pub/$RUN/.acl.json" "pub/$RUN/" "pub/$OPEN/" "pub/$OPEN/a%3bb.html" "pub/$OPEN/a..b.html" \
           "pub/$OPEN/index.html%2500"; do
    check "gate mode: $u answers like a missing key (GET)" same \
      "$([[ "$(answer GET "$BASE/artifacts/$u")" == "$ref_get" ]] && echo same || echo different)"
    check "gate mode: $u answers like a missing key (HEAD)" same \
      "$([[ "$(answer HEAD "$BASE/artifacts/$u")" == "$ref_head" ]] && echo same || echo different)"
  done
  check "gate mode: the stray ACL leaks nothing" 0 "$(curl -s "$BASE/artifacts/pub/$CLOSED/.acl.json" | grep -c 'test@example.com')"
  # the client cannot pick what the gate decides: Caddy sets X-Forwarded-Uri itself
  check "gate mode: a client X-Forwarded-Uri is ignored (the pub/ object is served)" 1 \
    "$(curl -s -H "X-Forwarded-Uri: /artifacts/u/$CAN/c.html" "$BASE/artifacts/pub/$OPEN/index.html" | grep -c "OPEN-$CAN")"
  check "gate mode: a client X-Forwarded-Uri never reads the canary" 0 \
    "$(curl -s -H "X-Forwarded-Uri: /artifacts/u/$CAN/c.html" "$BASE/artifacts/pub/$RUN/missing.html" | grep -c "CANARY-$CAN")"
  # the decision listener itself (never routed): a forwarded target aimed at u/ or g/ gets the
  # uniform answer; /_gate/auth without a session never answers 200 for a pub/ key
  pubauth() { # <x-forwarded-uri> [path]
    docker compose exec -T -e U="$1" -e P="${2:-/_gate/pub-auth}" gate python3 -c '
import os, urllib.error, urllib.request
req = urllib.request.Request("http://127.0.0.1:8081" + os.environ["P"], headers={
    "X-Forwarded-Method": "GET", "X-Forwarded-Uri": os.environ["U"], "X-Forwarded-Host": "127.0.0.1:8080"})
try:
    r = urllib.request.urlopen(req); print(r.status, "Authorization" in r.headers)
except urllib.error.HTTPError as e:
    print(e.code, "Authorization" in e.headers)'
  }
  check "gate mode: pub-auth allows the open pub/ key, signed" "200 True" "$(pubauth "/artifacts/pub/$OPEN/index.html")"
  check "gate mode: pub-auth aimed at u/ gets the uniform answer" "404 False" "$(pubauth "/artifacts/u/$CAN/c.html")"
  check "gate mode: pub-auth aimed at g/ gets the uniform answer" "404 False" "$(pubauth "/artifacts/g/team/$CAN/c.html")"
  check "gate mode: /_gate/auth without a session is never 200 on pub/" "401 False" \
    "$(pubauth "/artifacts/pub/$OPEN/index.html" /_gate/auth)"
  mc_admin "mc rm --recursive --force local/artifacts/pub/$OPEN local/artifacts/pub/$CLOSED >/dev/null 2>&1" || true
else
  echo "INFO: pub/ is served straight from MinIO in this mode; the gate-mode checks need ARTIFACTS_PUB_MODE=gate"
fi
for k in "${CANARIES[@]}"; do mc_admin "mc rm local/artifacts/$k >/dev/null 2>&1" || true; done

# ---- gated read: 302 without login -------------------------------------------------------
RUN2="e2e-priv-$(date +%s)"
# published with the non-root publisher user (bootstrap.sh): artifact + .acl.json writes work
ARTIFACTS_ACCESS_KEY=artifact-publisher ARTIFACTS_SECRET_KEY=artifact-publisher-dev-password \
  ARTIFACTS_WRITE_BASE="$S3" ARTIFACTS_READ_BASE="$BASE" \
  bash ../../cli/publish.sh -u test@example.com -r "$RUN2" -t 1 -a e2e -s compose /tmp/e2e-note.md >/dev/null \
  || { echo "CLI private publish (publisher user) failed"; exit 1; }
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
check "gated nosniff" "nosniff" \
  "$(curl -sI -H "Authorization: Bearer $TOKEN" "$GATED_URL" | tr -d '\r' | awk -F': ' 'tolower($1)=="x-content-type-options"{print $2}')"
check "gated no-referrer" "no-referrer" \
  "$(curl -sI -H "Authorization: Bearer $TOKEN" "$GATED_URL" | tr -d '\r' | awk -F': ' 'tolower($1)=="referrer-policy"{print $2}')"
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

# ---- the ACL lives at the artifact root ------------------------------------------------
# A file in a subfolder answers to u/<run>/.acl.json; a stray .acl.json below the root (here
# in the file's own folder, listing test2 only) is never read or served; a key with no
# artifact root is denied whatever ACL objects exist; _mcp/ is never served. Seeded through
# the admin path (the CLI publishes flat runs), before any read, so no cached answer helps.
TOKEN2=$(curl -sf -X POST http://127.0.0.1:5556/dex/token \
  -d 'grant_type=password&username=test2@example.com&password=test2-password&client_id=artifacts-dev&client_secret=artifacts-dev-secret-not-a-real-secret&scope=openid email profile' \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["id_token"])')
echo 'body{}' | mc_admin "mc pipe local/artifacts/u/$RUN2/assets/css/app.css >/dev/null" \
  || { echo "FAIL: could not seed a nested object"; fail=1; }
echo '{"owner":"test2@example.com","users":["test2@example.com"]}' \
  | mc_admin "mc pipe local/artifacts/u/$RUN2/assets/css/.acl.json >/dev/null" \
  || { echo "FAIL: could not seed a nested .acl.json"; fail=1; }
NESTED_URL="$BASE/artifacts/u/$RUN2/assets/css/app.css"
check "nested file opens for the root ACL's user" 200 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$NESTED_URL")"
check "nested .acl.json never consulted (test2 listed only there)" 403 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN2" "$NESTED_URL")"
check "nested .acl.json never served" 404 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN2" "$BASE/artifacts/u/$RUN2/assets/css/.acl.json")"
check "plugin authz: nested file answers to the root ACL" "True user test@example.com None True" \
  "$(authz "/artifacts/u/$RUN2/assets/css/app.css" "$TOKEN")"
check "plugin authz: nested .acl.json grants nothing" "False denied test2@example.com None False" \
  "$(authz "/artifacts/u/$RUN2/assets/css/app.css" "$TOKEN2")"
echo '{"owner":"test@example.com","users":["test@example.com"]}' \
  | mc_admin "mc pipe local/artifacts/u/.acl.json >/dev/null" \
  && echo x | mc_admin "mc pipe local/artifacts/u/$RUN2.html >/dev/null" \
  || { echo "FAIL: could not seed a key without artifact root"; fail=1; }
check "key with no artifact root denied (u/<file>, u/.acl.json present)" 403 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$BASE/artifacts/u/$RUN2.html")"
mc_admin "mc rm local/artifacts/u/.acl.json local/artifacts/u/$RUN2.html >/dev/null" || true
check "_mcp/ not served" 404 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$BASE/artifacts/_mcp/x.json")"
# oauth2-proxy (--upstream=static://202, --set-authorization-header) answers 202 + the
# session's id_token for EVERY path its router does not claim: /auth, but also /zzz, /,
# /ping, /sign_inX, /SIGN_IN... Caddy routes an allow-list only (sign_in, start, callback,
# sign_out, static/<file>). tests/oauth2_probe.py sends each spelling verbatim over a raw
# socket with the valid Bearer id_token: no 202, no Authorization / X-Auth-Request-* answer,
# 400/404 for the blocked ones; the browser endpoints still reach oauth2-proxy.
probe_out=$(OAUTH2_PROBE_TOKEN="$TOKEN" python3 -I ../../tests/oauth2_probe.py probe 127.0.0.1:8080)
probe_rc=$?
echo "$probe_out"
[[ $probe_rc -eq 0 ]] || { echo "FAIL: oauth2 raw probe (exit $probe_rc)"; fail=1; }
# browser login end to end (no Bearer): gated read -> sign_in -> Dex login -> approval ->
# callback (session cookie) -> the same gated read answers 200 with the artifact
login_out=$(python3 -I ../../tests/oauth2_probe.py login test@example.com test-password "$GATED_URL" "Run $RUN2")
login_rc=$?
echo "$login_out"
[[ $login_rc -eq 0 ]] || { echo "FAIL: browser login flow (exit $login_rc)"; fail=1; }
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
# the publisher user: writes artifacts and their .acl.json, never _plugins/ or _gate/
if mc_admin "mc alias set e2e-pub http://localhost:9000 artifact-publisher artifact-publisher-dev-password >/dev/null
  mc stat e2e-pub/artifacts/u/$RUN2/.acl.json >/dev/null"; then
  echo "PASS: publisher wrote the artifact's .acl.json"; else echo "FAIL: publisher .acl.json missing"; fail=1; fi
for probe in "echo x | mc pipe e2e-pub/artifacts/_plugins/canvas/e2e-probe.bin" \
             "echo x | mc pipe e2e-pub/artifacts/_plugins/e2e-probe.bin" \
             "echo x | mc pipe e2e-pub/artifacts/_gate/e2e-probe.json" \
             "echo x | mc pipe e2e-pub/artifacts/_gate/req/e2e-probe.json"; do
  if mc_admin "$probe >/dev/null 2>&1"; then echo "FAIL: publisher allowed: $probe"; fail=1
  else echo "PASS: publisher denied: ${probe##* }"; fi
done
check "publisher probes left no object" 0 "$(mc_admin "mc find local/artifacts --name 'e2e-probe*' 2>/dev/null | wc -l" | tr -d ' ')"
mc_admin "mc alias rm e2e-pub >/dev/null" || true

# ---- the gate's own S3 user writes an ACL only at an artifact root --------------------
# bootstrap.sh's gate policy, probed with the gate's own client (MinioClient in /app/gate.py,
# the same signing and request shape as an approval): u/<run>/.acl.json, g/<slug>/<run>/.acl.json
# and _gate/ state are writable; an .acl.json below a root, without a root, a non-ACL object
# are refused by the store (a policy `*` crosses `/`: the explicit Deny is what refuses depth).
# The root ACL write also carries its tags (x-amz-tagging) and is conditional (If-Match): the
# store must answer 412 to a stale ETag, or a grant could not tell it lost a race. Last,
# grant_access itself against this store with another writer slipped between its read and
# its write (a wrapper around the client, the gate code unchanged): 412, re-read, merged; and
# twice: it gives up and the other writer's ACL stays as written.
PROBE="e2e-policy-$(date +%s)"
gate_put_out=$(docker compose exec -T -e P="$PROBE" gate python3 - <<'PY'
import importlib.util, json, os
spec = importlib.util.spec_from_file_location("g", "/app/gate.py")
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
p = os.environ["P"]
for key in ("u/P/.acl.json", "g/P/r/.acl.json", "_gate/P.json", "u/P/a/.acl.json",
            "u/P/a/b/.acl.json", "g/P/r/a/.acl.json", "g/P/.acl.json", "pub/P/.acl.json",
            "u/P/index.html"):
    print(key, g.MINIO.put(key.replace("P", p), b"{}", "application/json"))
for key in ("u/P/.acl.json", "g/P/r/.acl.json", "u/P/a/.acl.json"):
    print("tagged:" + key, g.MINIO.put(key.replace("P", p), b'{"v":1}', "application/json",
                                       tagging="ttl=1"))
k = f"u/{p}/.acl.json"
print("tags-read", g.MINIO.get_tags_checked(k)[0].get("ttl"))
_, _, etag = g.MINIO.get_with_etag(k)
print("if-match:wrong", g.MINIO.put(k, b'{"v":2}', "application/json", if_match='"0123456789abcdef0123456789abcdef"'))
print("if-match:current", g.MINIO.put(k, b'{"v":2}', "application/json", if_match=etag))
print("if-match:stale", g.MINIO.put(k, b'{"v":3}', "application/json", if_match=etag))
print("plain", g.MINIO.put(k, b'{"v":3}', "application/json"))


class Racer:
    """The gate's client, with another writer's plain PUT right after each of the next n reads."""
    def __init__(self, inner, n):
        self.inner, self.n = inner, n

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def get_with_etag(self, key):
        out = self.inner.get_with_etag(key)
        if self.n:
            self.n -= 1
            acl = json.loads(out[1])
            acl["users"].append(f"other{self.n}@example.com")
            self.inner.put(key, json.dumps(acl).encode(), "application/json", tagging="ttl=1")
        return out


for case, n in (("race-once", 1), ("race-twice", 2)):
    g.MINIO.put(k, json.dumps({"owner": "o@example.com", "users": []}).encode(),
                "application/json", tagging="ttl=1")
    res = g.grant_access(Racer(g.MINIO, n), f"/artifacts/u/{p}/x.html", "new@example.com")
    print(case, json.dumps([res[0], res[1], sorted(json.loads(g.MINIO.get(k)[1])["users"]),
                            g.MINIO.get_tags_checked(k)[0].get("ttl")], separators=(",", ":")))
PY
)
gate_put() { echo "$gate_put_out" | awk -v k="$1" '$1==k{sub(/^[^ ]+ /, ""); print}'; }
for k in u/P/.acl.json g/P/r/.acl.json _gate/P.json tagged:u/P/.acl.json tagged:g/P/r/.acl.json; do
  check "gate S3 user may write $k" 200 "$(gate_put "$k")"
done
for k in u/P/a/.acl.json u/P/a/b/.acl.json g/P/r/a/.acl.json g/P/.acl.json pub/P/.acl.json u/P/index.html \
         tagged:u/P/a/.acl.json; do
  check "gate S3 user may not write $k" 403 "$(gate_put "$k")"
done
check "gate reads the root ACL's tags" 1 "$(gate_put tags-read)"
check "conditional PUT, wrong ETag" 412 "$(gate_put if-match:wrong)"
check "conditional PUT, current ETag" 200 "$(gate_put if-match:current)"
check "conditional PUT, stale ETag" 412 "$(gate_put if-match:stale)"
check "plain PUT" 200 "$(gate_put plain)"
check "grant raced once on the store: 412, re-read, both writers kept, ttl kept" \
  '[true,"added",["new@example.com","other0@example.com"],"1"]' "$(gate_put race-once)"
check "grant raced twice on the store: gives up, other writer's ACL as written" \
  '[false,"put HTTP 412",["other0@example.com","other1@example.com"],"1"]' "$(gate_put race-twice)"
for d in u g pub; do mc_admin "mc rm --recursive --force local/artifacts/$d/$PROBE >/dev/null 2>&1" || true; done
mc_admin "mc rm --force local/artifacts/_gate/$PROBE.json >/dev/null 2>&1" || true
check "gate policy probes left no object" 0 "$(mc_admin "mc ls --recursive local/artifacts/u/$PROBE local/artifacts/g/$PROBE local/artifacts/pub/$PROBE local/artifacts/_gate/$PROBE.json 2>/dev/null | wc -l" | tr -d ' ')"

# ---- an approval end to end on the real store --------------------------------------------
# test2 is denied an artifact owned by test@example.com, requests access, the owner approves
# (the approve token is minted in the gate container with the dev HMAC key, as the DM would
# carry it): the ACL write goes through MinIO with If-Match and the ACL's ttl tag, the owner
# and the other fields stay, the tag is the same after the write, and test2 reads.
RUN3="e2e-grant-$(date +%s)"
ARTIFACTS_OWNER=test@example.com ARTIFACTS_ACCESS_KEY=artifact-publisher \
  ARTIFACTS_SECRET_KEY=artifact-publisher-dev-password ARTIFACTS_WRITE_BASE="$S3" ARTIFACTS_READ_BASE="$BASE" \
  bash ../../cli/publish.sh -u test@example.com -r "$RUN3" -t 7 -a e2e -s compose /tmp/e2e-note.md >/dev/null \
  || { echo "CLI publish for the approval flow failed"; exit 1; }
GRANT_PATH="/artifacts/u/$RUN3/index.html"
acl_tags() { mc_admin "mc tag list --json local/artifacts/u/$RUN3/.acl.json" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin).get("tagset"))'; }
tags_before=$(acl_tags)
check "approval flow: the published ACL carries ttl=7" "{'ttl': '7'}" "$tags_before"
deny_page=$(curl -s -H "Authorization: Bearer $TOKEN2" "$BASE$GRANT_PATH")
check "approval flow: test2 denied before" 403 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN2" "$BASE$GRANT_PATH")"
csrf=$(printf '%s' "$deny_page" | python3 -c 'import html,re,sys; m=re.search(r"name=csrf value=\"([^\"]+)\"", sys.stdin.read()); print(html.unescape(m.group(1)) if m else "")')
check "approval flow: request-access recorded" 200 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN2" \
  --data-urlencode "csrf=$csrf" --data-urlencode "artifact=$GRANT_PATH" "$BASE/_gate/request")"
rid=$(docker compose logs gate 2>/dev/null | grep -o "request-access id=[0-9a-f]* requester=test2@example.com artifact=$GRANT_PATH" | tail -1 | sed 's/^request-access id=\([0-9a-f]*\) .*/\1/')
check "approval flow: request id from the gate log" yes "$([[ -n "$rid" ]] && echo yes || echo no)"
approve_token=$(docker compose exec -T -e RID="$rid" gate python3 - <<'PY'
import importlib.util, os, time
spec = importlib.util.spec_from_file_location("g", "/app/gate.py")
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
print(g.make_action_token(os.environ["RID"], "approve", g._KEY, int(time.time())))
PY
)
confirm_page=$(curl -s -H "Authorization: Bearer $TOKEN" --get --data-urlencode "token=$approve_token" "$BASE/_gate/approve")
check "approval flow: the confirm page says the whole artifact is granted" 1 \
  "$(printf '%s' "$confirm_page" | grep -c "access to the whole artifact <code>/artifacts/u/$RUN3/</code>")"
approve_page=$(curl -s -H "Authorization: Bearer $TOKEN" --data-urlencode "token=$approve_token" "$BASE/_gate/approve")
check "approval flow: owner's POST approves" 1 "$(printf '%s' "$approve_page" | grep -c '<title>Request approved</title>')"
check "approval flow: the result page says the whole artifact" 1 \
  "$(printf '%s' "$approve_page" | grep -c "can now open the whole artifact <code>/artifacts/u/$RUN3/</code>")"
check "approval flow: test2 reads after approval" 200 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN2" "$BASE$GRANT_PATH")"
check "approval flow: the ACL keeps its ttl tag" "$tags_before" "$(acl_tags)"
check "approval flow: owner, users and expiry kept, test2 added" "test@example.com ['test2@example.com', 'test@example.com'] True" \
  "$(mc_admin "mc cat local/artifacts/u/$RUN3/.acl.json" | python3 -c 'import json,sys; a=json.load(sys.stdin); print(a["owner"], sorted(a["users"]), bool(a["expires"]))')"

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
# rule 4: the gate's health check and decision endpoints are not routed (Caddy's empty 404,
# not the gate's page); the request-access surface is
gate_body=$(mktemp)
for p in /_gate/healthz /_gate/auth /_gate/plugin/authz /_gate/plugin/; do
  check "$p not routed to the gate" "404 0" \
    "$(curl -s -o "$gate_body" -w '%{http_code}' "$BASE$p") $(wc -c <"$gate_body" | tr -d ' ')"
done
rm -f "$gate_body"
check "/_gate/approve routed to the gate" 410 "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/_gate/approve?token=x")"
# the gate's own pages cannot be framed; request bodies are refused unread before login
check "gate page X-Frame-Options" DENY \
  "$(curl -s -D - -o /dev/null -X PUT "$BASE/artifacts/whatever" | tr -d '\r' | awk -F': ' 'tolower($1)=="x-frame-options"{print $2}')"
check "gate page CSP frame-ancestors" 1 \
  "$(curl -s -D - -o /dev/null -X PUT "$BASE/artifacts/whatever" | tr -d '\r' | grep -ci "^content-security-policy:.*frame-ancestors 'none'")"
check "oversized request-access body refused" 413 \
  "$(head -c 20000 /dev/zero | tr '\0' x | curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @- "$BASE/_gate/request")"
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
