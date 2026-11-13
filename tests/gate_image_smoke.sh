#!/usr/bin/env bash
# Smoke test of a built gate image (gate/Dockerfile). Docker required; nothing is pushed.
#
#   tests/gate_image_smoke.sh <image> [<expected 40-hex revision>]
#
# Checks: OCI labels (source; revision when given), numeric non-root user, no bytecode writes,
# /app holds exactly gate.py and it is byte-identical to gate/gate.py; then starts the gate the
# way the chart runs it (read-only root filesystem, uid 1000, no capabilities, no privilege
# escalation) with placeholder settings and expects /_gate/healthz 200 on both listeners, the
# decision endpoint 404 on the public listener, the process running as 1000:1000 and no file
# written. The placeholders reach no MinIO or proxy: healthz needs neither.
set -euo pipefail

image="${1:?usage: $0 <image> [<expected revision>]}"
want_rev="${2:-}"
here="$(cd "$(dirname "$0")/.." && pwd)"
fail() { echo "FAIL: $*" >&2; exit 1; }

label() { docker image inspect --format "{{ index .Config.Labels \"$1\" }}" "$image"; }
src="$(label org.opencontainers.image.source)"
rev="$(label org.opencontainers.image.revision)"
[ -n "$src" ] || fail "label org.opencontainers.image.source is empty"
if [ -n "$want_rev" ] && [ "$rev" != "$want_rev" ]; then
  fail "label org.opencontainers.image.revision is '$rev', expected '$want_rev'"
fi
user="$(docker image inspect --format '{{.Config.User}}' "$image")"
[ "$user" = "1000:1000" ] || fail "image user is '$user', expected 1000:1000"
docker image inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$image" \
  | grep -qx 'PYTHONDONTWRITEBYTECODE=1' || fail "PYTHONDONTWRITEBYTECODE=1 not set"
echo "labels: source=$src revision=${rev:-<empty>}; user=$user; PYTHONDONTWRITEBYTECODE=1"

want_sum="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$here/gate/gate.py")"
got="$(docker run --rm --read-only --user 1000:1000 --cap-drop ALL --network none "$image" \
  python3 -c 'import hashlib,os; print(sorted(os.listdir("/app")), hashlib.sha256(open("/app/gate.py","rb").read()).hexdigest())')"
[ "$got" = "['gate.py'] $want_sum" ] || fail "/app is '$got', expected ['gate.py'] $want_sum"
echo "/app: ['gate.py'], sha256 equal to gate/gate.py ($want_sum)"

name="gate-smoke-$$"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
docker run -d --name "$name" --read-only --user 1000:1000 --cap-drop ALL \
  --security-opt no-new-privileges \
  -p 127.0.0.1::8080 -p 127.0.0.1::8081 \
  -e MINIO_ENDPOINT=http://127.0.0.1:9 \
  -e MINIO_ACCESS_KEY=smoke-gate -e MINIO_SECRET_KEY=placeholder \
  -e GATE_READ_ACCESS_KEY=smoke-reader -e GATE_READ_SECRET_KEY=placeholder \
  -e OAUTH2_AUTH_URL=http://127.0.0.1:9/oauth2/auth \
  -e HMAC_KEY_B64="$(head -c 32 /dev/urandom | base64)" \
  "$image" >/dev/null
pub="$(docker port "$name" 8080/tcp | head -1)"
dec="$(docker port "$name" 8081/tcp | head -1)"

code() { curl -s -o /dev/null -w '%{http_code}' "http://$1$2" || true; }
for _ in $(seq 1 30); do
  [ "$(code "$pub" /_gate/healthz)" = 200 ] && break
  [ "$(docker inspect --format '{{.State.Running}}' "$name")" = true ] \
    || { docker logs "$name" >&2; fail "the gate exited"; }
  sleep 1
done
for check in "$pub /_gate/healthz 200" "$dec /_gate/healthz 200" "$pub /_gate/auth 404"; do
  read -r addr path want <<<"$check"
  got="$(code "$addr" "$path")"
  [ "$got" = "$want" ] || { docker logs "$name" >&2; fail "GET $path on $addr answered $got, expected $want"; }
  echo "GET $path on $addr -> $got"
done
ids="$(docker exec "$name" python3 -c 'import os; print(os.getuid(), os.getgid())')"
[ "$ids" = "1000 1000" ] || fail "the gate runs as '$ids', expected 1000 1000"
changed="$(docker diff "$name")"
[ -z "$changed" ] || fail "files written in the container: $changed"
echo "process uid/gid: $ids; read-only root filesystem, no file written"
logs="$(docker logs "$name" 2>&1)"
grep -q 'artifact-gate starting' <<<"$logs" || fail "no start line in the logs"
echo "OK: $image"
