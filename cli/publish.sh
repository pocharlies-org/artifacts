#!/usr/bin/env bash
# publish.sh — publish one or more files as an artifact: uploads to S3/MinIO with a ttl
# expiry tag, renders markdown to HTML (house style) and generates an index.html.
# Stamps provenance (author, session, date) as x-amz-meta-* and in the HTML.
#
# The host in the delivered links is the READ host (the artifact-gate host). Publishing
# signs against the WRITE host: the gate host refuses PUT with 405, so the write host is
# an S3-capable endpoint (MinIO directly, or a signed write route). In the simplest
# deployment they are the same host only if writes are allowed there.
#
# Configuration comes from the environment or a config file (default
# ~/.config/artifacts/publish.conf, override with ARTIFACTS_CONFIG; KEY=VALUE lines;
# already-exported environment variables win over the file). Required:
#   ARTIFACTS_ACCESS_KEY, ARTIFACTS_SECRET_KEY
# Defaults (override for your deployment):
#   ARTIFACTS_WRITE_BASE=https://artifacts-write.example.com
#   ARTIFACTS_READ_BASE=https://artifacts.example.com
#   ARTIFACTS_BUCKET=artifacts  ARTIFACTS_REGION=us-east-1
# Optional:
#   ARTIFACTS_OWNER=<upn>                 owner in the gate ACL (request-access notifies them)
#   ARTIFACTS_GROUPS="team-a=<group-id>;team-b=<group-id>"   slug -> group id for -g
#   ARTIFACTS_PLUGINS="canvas=/_canvas/"  enabled plugins; one link each is printed (§8.5)
#
# Usage: publish.sh (-u email[,email...] | -g <slug|pub>) [-r run-id] [-t ttl-days]
#                   [-a author] [-s session] <file>...
# -u: individual people (the default way to share): the artifact lives under u/<run>/
#     and only the listed emails can open it (gate ACL). Emails are not resolved against
#     any directory: the gate matches them against the login claim.
# -g: group slug from ARTIFACTS_GROUPS (its id goes into the gate ACL), or pub for
#     anonymous reads. -u and -g are mutually exclusive.
# Requires: curl >= 8 (sigv4), python3; 'markdown' for .md input.
set -euo pipefail

CONF="${ARTIFACTS_CONFIG:-$HOME/.config/artifacts/publish.conf}"
if [[ -f "$CONF" ]]; then
  while IFS='=' read -r k v; do
    k="${k%%$'\r'}"
    case "$k" in ''|\#*) continue ;; esac
    [[ "$k" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    v="${v#\"}"; v="${v%\"}"; v="${v%\'}"; v="${v#\'}"
    [[ -n "${!k:-}" ]] || export "$k=$v"
  done < "$CONF"
fi
: "${ARTIFACTS_WRITE_BASE:=https://artifacts-write.example.com}"
: "${ARTIFACTS_READ_BASE:=https://artifacts.example.com}"
: "${ARTIFACTS_BUCKET:=artifacts}"
: "${ARTIFACTS_REGION:=us-east-1}"
WRITE_BASE="${ARTIFACTS_WRITE_BASE%/}"; READ_BASE="${ARTIFACTS_READ_BASE%/}"

GROUP="" USERS="" RUN="" TTL=7 AUTHOR="${USER:-unknown}" SESSION=""
while getopts "g:u:r:t:a:s:h" o; do
  case "$o" in
    g) GROUP="$OPTARG" ;;
    u) USERS="$OPTARG" ;;
    r) RUN="$OPTARG" ;;
    t) TTL="$OPTARG" ;;
    a) AUTHOR="$OPTARG" ;;
    s) SESSION="$OPTARG" ;;
    h) grep '^# ' "$0" | sed 's/^# //'; exit 0 ;;
    *) echo "usage: publish.sh -u email[,email...] | -g <slug|pub> [-r run-id] [-t ttl] [-a author] [-s session] <file>..." >&2; exit 2 ;;
  esac
done
shift $((OPTIND-1))
[[ $# -ge 1 ]] || { echo "at least one file is required" >&2; exit 2; }
if [[ -n "$GROUP" && -n "$USERS" ]]; then
  echo "-g and -u are mutually exclusive: pick a group OR a list of people" >&2; exit 2
fi
if [[ -z "$GROUP" && -z "$USERS" ]]; then
  echo "missing -u <email[,email...]> or -g <slug|pub>" >&2; exit 2
fi
for f in "$@"; do [[ -f "$f" ]] || { echo "no such file: $f" >&2; exit 2; }; done
[[ -n "${ARTIFACTS_ACCESS_KEY:-}" && -n "${ARTIFACTS_SECRET_KEY:-}" ]] || {
  echo "ARTIFACTS_ACCESS_KEY / ARTIFACTS_SECRET_KEY are required (env or $CONF)" >&2; exit 1; }
RUN="${RUN:-run-$(date +%Y%m%d-%H%M)}"
SESSION="${SESSION:-no-id}"
# The gate only accepts keys without traversal segments: reject bad run-ids here rather
# than publish something unreadable. The run-id enters the published path
# (pub/<run>/, g/<slug>/<run>/, u/<run>/), not just the ACL.
if [[ ! "$RUN" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "invalid run-id (letters, digits, dot, underscore, hyphen only): $RUN" >&2; exit 2
fi
if [[ "$RUN" == *..* ]]; then
  echo "invalid run-id (contains '..'): $RUN" >&2; exit 2
fi
# HTTP headers: printable ASCII without quotes (accents transliterated) and TRUNCATED to
# 100 chars. S3 allows 2 KB of user-metadata in total, but MinIO REFUSES TO SERVE the
# object (MetadataToolLarge on every GET) above its own limit: the PUT succeeds, the link
# is delivered and the artifact is born broken. Keep it short and descriptive.
sanitize() { printf '%s' "$1" | iconv -c -f UTF-8 -t ASCII//TRANSLIT 2>/dev/null | tr -cd '\040-\176' | tr -d '"' | cut -c1-100; }
AUTHOR="$(sanitize "$AUTHOR")"; SESSION="$(sanitize "$SESSION")"
PUB_AT="$(date '+%Y-%m-%dT%H:%M:%S%z')"

# ---- resolve the audience --------------------------------------------------------------
# pub/ is anonymous (while the host is not publicly exposed, see README); groups live
# under g/<slug>/; people under u/<run>/.
if [[ -n "$USERS" ]]; then
  PREFIX="${ARTIFACTS_BUCKET}/u/${RUN}"; AUDIENCE="users"
  USERS_JSON="["
  first=1
  IFS=',' read -ra ADDRS <<< "$USERS"
  for addr in "${ADDRS[@]}"; do
    addr="$(printf '%s' "$addr" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
    [[ "$addr" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || { echo "invalid address: '$addr'" >&2; exit 1; }
    [[ $first -eq 1 ]] || USERS_JSON+=","
    first=0
    USERS_JSON+="\"$addr\""
  done
  USERS_JSON+="]"
elif [[ "$GROUP" == "pub" ]]; then
  PREFIX="${ARTIFACTS_BUCKET}/pub/${RUN}"; AUDIENCE="pub"; USERS_JSON="[]"
else
  GID=""
  IFS=';' read -ra PAIRS <<< "${ARTIFACTS_GROUPS:-}"
  for pair in ${PAIRS[@]+"${PAIRS[@]}"}; do
    [[ "${pair%%=*}" == "$GROUP" ]] && GID="${pair#*=}"
  done
  [[ -n "$GID" ]] || { echo "unknown group slug '$GROUP' (set ARTIFACTS_GROUPS='slug=<id>;...'; 'pub' is always valid)" >&2; exit 1; }
  PREFIX="${ARTIFACTS_BUCKET}/g/${GROUP}/${RUN}"; AUDIENCE="$GROUP"; USERS_JSON="[]"
  GATE_GROUPS_JSON="[$GID]"
fi

# ---- gate ACL (format of gate/gate.py decide()) -----------------------------------------
# {"owner":UPN, "users":[...], "groups":[id...], "expires":"YYYY-MM-DD"|null}.
# Lives in the objects' directory (<prefix>/.acl.json). NEVER under pub/ (there the gate
# lets any signed-in user through and the host serves it anonymously: an ACL makes no
# sense and the smoke tests forbid it). Expires with the objects (ttl tag).
GATE_ACL=""
if [[ -z "${GATE_GROUPS_JSON:-}" ]]; then GATE_GROUPS_JSON="[]"; fi
if [[ "$AUDIENCE" != "pub" ]]; then
  EXPIRES="$(python3 -c "import datetime,sys;print((datetime.date.today()+datetime.timedelta(days=int(sys.argv[1]))).isoformat())" "$TTL")"
  GATE_ACL="$(mktemp)"
  trap 'rm -f "$GATE_ACL"' EXIT
  python3 -c '
import json,sys
owner, users, groups, expires = sys.argv[1], json.loads(sys.argv[2]), json.loads(sys.argv[3]), sys.argv[4]
print(json.dumps({"owner": owner.lower() if owner else "", "users": users, "groups": groups, "expires": expires}))
' "${ARTIFACTS_OWNER:-}" "$USERS_JSON" "$GATE_GROUPS_JSON" "$EXPIRES" > "$GATE_ACL"
fi

# ---- render: md->HTML, .html as is, the rest copied; index.html always last --------------
OUT="$(mktemp -d)"; MANIFEST="$OUT.manifest"
trap 'rm -rf "$OUT" "$MANIFEST" ${GATE_ACL:-}' EXIT
python3 "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/render.py" \
  --dir "$OUT" --run "$RUN" --audience "$AUDIENCE" --ttl "$TTL" \
  --author "$AUTHOR" --session "$SESSION" "$@" > "$MANIFEST"

put() { # $1=local_path $2=content_type $3=full_path_under_write_base
  curl -fsS --noproxy '*' --aws-sigv4 "aws:amz:${ARTIFACTS_REGION}:s3" \
    --user "${ARTIFACTS_ACCESS_KEY}:${ARTIFACTS_SECRET_KEY}" \
    -X PUT -T "$1" -H "Content-Type: $2" -H "x-amz-tagging: ttl=${TTL}" \
    -H "Cache-Control: no-cache" \
    -H "x-amz-meta-publisher: ${AUTHOR}" \
    -H "x-amz-meta-session: ${SESSION}" \
    -H "x-amz-meta-published-at: ${PUB_AT}" \
    "${WRITE_BASE}/$3"
}

# The ACL goes up BEFORE the objects: a visible u/ or g/ object without its ACL would be
# a 403 for everyone during the gap (fail-closed, but broken).
if [[ -n "$GATE_ACL" ]]; then
  put "$GATE_ACL" "application/json" "${PREFIX}/.acl.json"
fi

URLS=()
while IFS=$'\t' read -r path ct name; do
  put "$path" "$ct" "${PREFIX}/${name}"
  URLS+=("${READ_BASE}/${PREFIX}/${name}")
done < "$MANIFEST"

# The index is the last manifest entry; the link delivered is that one (on the read host).
INDEX_URL="${READ_BASE}/${PREFIX}/index.html"

# Verification: the PUT -fsS already aborts on non-2xx. Signed header GETs are not
# routed (only signed PUT/POST and presigned queries): authenticated reads are the
# browser's job via forwardAuth. Retry with backoff up to ~30 s: the gate caches ACLs
# (positive and negative) for 15 s, so a freshly published read can lag one cycle.
verify_anon() { # <url> <expected: 200|302>
  local url="$1" want="$2" out code deadline=$(( SECONDS + 30 ))
  while :; do
    out=$(curl -sk --noproxy '*' -o /dev/null -w '%{http_code} %{redirect_url}' "$url")
    code="${out%% *}"
    if [[ "$want" == "200" && "$code" == "200" ]]; then
      echo "anonymous GET on ${url#*://}: 200 (public)"; return 0
    fi
    # any 302 means the login redirect is in place (the gate's errors middleware sends
    # the visitor to the proxy's sign_in, which then redirects to the IdP)
    if [[ "$want" == "302" && "$code" == "302" ]]; then
      echo "anonymous GET on ${url#*://}: 302 -> login (gate OK)"; return 0
    fi
    if (( SECONDS >= deadline )); then
      echo "FAIL: anonymous GET of $url returned '$out', expected $want. Do not deliver this link." >&2
      return 1
    fi
    sleep 3
  done
}

if [[ "$AUDIENCE" == "pub" ]]; then
  verify_anon "$INDEX_URL" 200
else
  verify_anon "$INDEX_URL" 302
fi
echo "INDEX (deliver this link): ${INDEX_URL}"
# Plugin links (docs/plugins.md §8.5): one per enabled plugin, on the read host.
IFS=';' read -ra PLUGINS <<< "${ARTIFACTS_PLUGINS:-}"
for pair in ${PLUGINS[@]+"${PLUGINS[@]}"}; do
  [[ -n "$pair" ]] || continue
  pname="${pair%%=*}"; pprefix="${pair#*=}"
  [[ "$pprefix" == /*/ ]] || { echo "plugin '$pname': pathPrefix must look like /_<name>/ (got '$pprefix')" >&2; continue; }
  echo "  open with ${pname}: ${READ_BASE}${pprefix}${PREFIX}/index.html"
done
for u in "${URLS[@]}"; do echo "  $u"; done
if [[ "$AUDIENCE" == "pub" ]]; then
  echo "Expires in ${TTL} days. Public, no login (while the host is not publicly exposed)."
else
  echo "Expires in ${TTL} days. Requires login; access per the artifact ACL."
fi
echo "Provenance stamped: author=${AUTHOR} session=${SESSION} date=${PUB_AT} (x-amz-meta-* on every object)."
