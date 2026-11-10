#!/usr/bin/env python3
"""
artifact-gate — per-artifact authorization for an artifacts host.

Role in the chain (Traefik IngressRoute `artifacts-routes`, ns minio):

    browser ──(Entra cookie)──► Traefik ──forwardAuth──► THIS GATE ──/auth──► oauth2-proxy-artifacts
                                        │                                        (Entra session check)
                                        └──(allowed)──► MinIO GET/HEAD, SigV4-signed by the gate
                                                         (Authorization/X-Amz-* from the forwardAuth
                                                         answer; see upstream_auth_headers)

The gate answers Traefik's forwardAuth (`GET /_gate/auth`): it authenticates the visitor by calling
oauth2-proxy's own `/auth` endpoint with the visitor's cookie (so it NEVER trusts client-supplied
X-Auth-Request-* headers), then decides against the artifact's `<dir>/.acl.json`:

    { "owner": "<UPN>", "users": ["<UPN>", ...], "groups": ["<entra object id>", ...],
      "expires": "YYYY-MM-DD" | ISO datetime | null }

  - ACL allows: owner, any UPN in `users`, any member of any Entra object id in `groups`.
  - `pub/` objects WITHOUT an ACL: any signed-in user of the tenant.
  - Anything else without an ACL: deny (the request-access button on the deny page goes nowhere).
  - `expires` in the past: deny (still requestable: the owner still exists).
  - Groups in the ACL but no `groups` claim from Entra (overage or user with no groups): deny + log.
  - Missing artifact and "not allowed" answer with the SAME 403 page (no existence leak) and the
    request-access POST silently does nothing when the artifact does not exist or has no owner.

The gate also serves the request-access flow (all state in MinIO under `_gate/`, written with the
gate's own least-privilege S3 user):

    POST /_gate/request   CSRF-bound, rate limited per user+artifact -> records the request under
                          _gate/req/<id>.json and DMs the owner (Slack) Approve/Deny links.
    GET  /_gate/approve   renders a confirmation page (GET never changes state: Slack unfurls GETs).
    POST /_gate/approve   single-use signed token, acts only for the ACL owner: adds the requester
                          to the ACL and DMs them. /_gate/deny mirrors it without touching the ACL.

Two listeners, one process (— the forwardAuth decision endpoint and the
public surface must not share a port):

    GATE_PORT      (default 8080) public listener: the request-access surface only
                   (/_gate/request|approve|deny, 405 on writes, /_gate/healthz). It NEVER serves
                   /_gate/auth: a server without an explicit gate_mode is treated as public, so the
                   decision endpoint is fail-closed here even if a route misdirects public traffic.
    GATE_AUTH_PORT (default 8081) decision listener: /_gate/auth (traefik's forwardAuth target,
                   helm/artifacts/templates/gate-middlewares.yaml), /_gate/plugin/authz (the plugin
                   authorization API) plus /_gate/healthz. The public IngressRoute excludes
                   /_gate/auth and /_gate/healthz
                   (helm/artifacts/templates/artifacts-routes.yaml): the browser reaches the gate
                   only on 8080, and the decision endpoints only exist on 8081 (healthz answers on
                   both, it leaks nothing and the kubelet probes 8080).

Plugin contract (docs/plugins.md): the gate is the single source of the authorization decision —
plugins must call POST /_gate/plugin/authz (internal listener only, never routed publicly) instead
of re-implementing decide(). It answers {allowed, reason, user:{id,name,anonymous},
artifact:{key,expires,ttl}} using the one and only decide(). Anonymous visitors are allowed only
for pub/ keys and only while GATE_ANONYMOUS_PUB_ENABLED is true. Keys under the plugin storage
prefix (GATE_PLUGIN_PREFIX, default "_plugins") and gate state (GATE_STATE_PREFIX) are never
served on any route.

Single file, stdlib only, mounted from a ConfigMap onto a digest-pinned python:3.12-slim.
Configuration is env-only (see CONFIG below); secrets come from k8s secrets.
"""

import base64
import hashlib
import hmac
import html
import json
import logging
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = logging.getLogger("artifact-gate")

# --------------------------------------------------------------------------------------------
# CONFIG (env only; the Deployment wires k8s secrets into these)
# --------------------------------------------------------------------------------------------
def _env(name, default=None, required=False):
    v = os.environ.get(name, default)
    if required and not v:
        raise RuntimeError(f"required env var {name} is not set")
    return v


BUCKET = _env("GATE_BUCKET", "artifacts")
BUCKET_PATH = "/" + BUCKET.strip("/") + "/"  # bucket public path prefix (path-style links)
MINIO_ENDPOINT = _env("MINIO_ENDPOINT", "http://minio-s3.minio.svc.cluster.local:9000")
MINIO_ACCESS_KEY = _env("MINIO_ACCESS_KEY", required=True)   # gate user: ACL/state work
MINIO_SECRET_KEY = _env("MINIO_SECRET_KEY", required=True)
# Read-signing user: signs ONLY the forwarded artifact reads (upstream_auth_headers). Its S3
# policy is s3:GetObject on the bucket with an explicit Deny on _gate/*, _plugins/* and every
# .acl.json, nothing else, so a signature that leaks or is replayed can only read what a reader
# of the artifact could read anyway. It must be a different user from MINIO_ACCESS_KEY (the gate
# user can write ACLs and state); the gate refuses to start otherwise.
READ_ACCESS_KEY = _env("GATE_READ_ACCESS_KEY", required=True)
READ_SECRET_KEY = _env("GATE_READ_SECRET_KEY", required=True)
if READ_ACCESS_KEY == MINIO_ACCESS_KEY:
    raise RuntimeError("GATE_READ_ACCESS_KEY must be a dedicated read-signing user, "
                       "not the gate user MINIO_ACCESS_KEY")
OAUTH2_AUTH_URL = _env("OAUTH2_AUTH_URL", required=True)  # oauth2-proxy /auth of the artifacts proxy
HMAC_KEY = (_env("HMAC_KEY_B64") or "").strip()
HMAC_KEY_FILE = _env("HMAC_KEY_FILE", "/secrets/hmac-key")
SLACK_BOT_TOKEN = _env("SLACK_BOT_TOKEN", "")
PUBLIC_HOST = _env("PUBLIC_HOST", "artifacts.example.com")
STATE_PREFIX = _env("GATE_STATE_PREFIX", "_gate")            # non-routed MinIO prefix for gate state
PUB_PREFIXES = tuple(p for p in _env("GATE_PUB_PREFIXES", "pub/").split(",") if p)
# Anonymous (no session) reads of pub/ — only meaningful for the plugin authz endpoint, since
# plain anonymous pub/ reads are an edge (route) decision. Fail-closed default: the chart must set
# it explicitly, and it must be false before any public hostname or tunnel (docs/plugins.md).
ANONYMOUS_PUB_ENABLED = _env("GATE_ANONYMOUS_PUB_ENABLED", "false").lower() in ("1", "true", "yes", "on")
PLUGIN_PREFIX = _env("GATE_PLUGIN_PREFIX", "_plugins")  # plugin storage prefix: never served
RATE_LIMIT_MAX = int(_env("GATE_RATE_LIMIT_MAX", "5"))
RATE_LIMIT_WINDOW = int(_env("GATE_RATE_LIMIT_WINDOW_SECONDS", "86400"))
TOKEN_TTL = int(_env("GATE_TOKEN_TTL_SECONDS", "604800"))    # approve/deny links: 7 days
CSRF_TTL = int(_env("GATE_CSRF_TTL_SECONDS", "3600"))
# Negative/positive ACL cache TTL. This 15 s is the REAL default (the
# README said "30 s" — the docs now follow the code; keep them in sync if this ever changes).
ACL_CACHE_TTL = int(_env("GATE_ACL_CACHE_SECONDS", "15"))
LISTEN_PORT = int(_env("GATE_PORT", "8080"))           # public surface (see module docstring)
AUTH_LISTEN_PORT = int(_env("GATE_AUTH_PORT", "8081"))  # forwardAuth decision endpoint only

def _load_hmac_key(b64, path):
    """Load the HMAC key from base64 env (HMAC_KEY_B64) or a file (HMAC_KEY_FILE).

    PR #9 review ( re-review), Warning 1: a corrupt secret must fail with a clear
    RuntimeError naming the source, not a raw traceback from b64decode/open. validate=True
    rejects payloads with stray characters (without it base64 silently DROPS invalid chars,
    which could turn a truncated/corrupted key into a shorter-but-valid one)."""
    if b64:
        try:
            # binascii.Error (raised by validate=True) subclasses ValueError
            key = base64.b64decode(b64, validate=True)
        except ValueError as e:
            raise RuntimeError(f"HMAC_KEY_B64 is not valid base64: {e}") from e
    else:
        try:
            with open(path, "rb") as f:
                key = f.read().strip()
        except OSError as e:
            raise RuntimeError(f"cannot read HMAC key file {path}: {e}") from e
    if len(key) < 32:
        raise RuntimeError("HMAC key must be at least 32 bytes")
    return key


_KEY = _load_hmac_key(HMAC_KEY, HMAC_KEY_FILE)

# --------------------------------------------------------------------------------------------
# SigV4 + MinIO client (stdlib; same signing math as scripts/smoke.sh presigning)
# --------------------------------------------------------------------------------------------
def _q(value, encode_slash):
    return urllib.parse.quote(str(value), safe="-._~/" if not encode_slash else "-._~")


def sigv4_headers(method, host, path, query_pairs, extra_headers, payload, access_key, secret_key,
                  region="us-east-1", service="s3", amzdate=None):
    """Return the headers to sign a request SigV4-style (host, x-amz-date, x-amz-content-sha256,
    Authorization). `path` is the raw (unquoted) path; `query_pairs` a list of (k, v)."""
    if amzdate is None:
        amzdate = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    datestamp = amzdate[:8]
    payload_hash = hashlib.sha256(payload or b"").hexdigest()

    canon_path = "/".join(_q(seg, True) for seg in path.split("/")) or "/"
    if canon_path != "/" and not canon_path.startswith("/"):
        canon_path = "/" + canon_path
    enc = sorted((_q(k, True), _q(v, True)) for k, v in query_pairs)
    canon_query = "&".join(f"{k}={v}" for k, v in enc)

    headers = {"host": host, "x-amz-content-sha256": payload_hash, "x-amz-date": amzdate}
    headers.update({k.lower(): v for k, v in (extra_headers or {}).items()})
    signed = sorted(headers)
    canon_headers = "".join(f"{h}:{' '.join(headers[h].split())}\n" for h in signed)

    canon_request = "\n".join([method.upper(), canon_path, canon_query, canon_headers,
                               ";".join(signed), payload_hash])
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope,
                                hashlib.sha256(canon_request.encode()).hexdigest()])

    def h(key, msg):
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()
    k = h(h(h(h(("AWS4" + secret_key).encode(), datestamp), region), service), "aws4_request")
    signature = hmac.new(k, string_to_sign.encode(), hashlib.sha256).hexdigest()
    headers["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
        f"SignedHeaders={';'.join(signed)}, Signature={signature}")
    return headers


class MinioClient:
    """Tiny path-style S3 client: get/head/put of one object, signed with the gate's own user."""

    def __init__(self, endpoint, access_key, secret_key, bucket):
        self.endpoint = endpoint.rstrip("/")
        self.host = urllib.parse.urlsplit(endpoint).netloc
        self.ak, self.sk, self.bucket = access_key, secret_key, bucket

    def _url(self, key, query=""):
        path = f"/{self.bucket}/{key}" if key else f"/{self.bucket}"
        # join with "/": the first segment is empty (path starts with "/"), which yields the
        # leading slash. Must match canon_path in sigv4_headers.
        u = self.endpoint + "/".join(_q(seg, True) for seg in path.split("/"))
        return u + (("?" + query) if query else "")

    def _call(self, method, key, body=None, ctype=None, query=""):
        path = f"/{self.bucket}/{key}" if key else f"/{self.bucket}"
        qp = urllib.parse.parse_qsl(query)
        headers = sigv4_headers(method, self.host, path, qp,
                                {"content-type": ctype} if ctype else None,
                                body or b"", self.ak, self.sk)
        req = urllib.request.Request(self._url(key, query), data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except OSError as e:
            raise ConnectionError(f"minio {method} {key}: {e}") from e

    def get(self, key):
        return self._call("GET", key)

    def head(self, key):
        status, _ = self._call("HEAD", key)
        return status

    def head_full(self, key):
        """HEAD keeping the response headers (Last-Modified feeds the plugin authz expiry)."""
        path = f"/{self.bucket}/{key}"
        headers = sigv4_headers("HEAD", self.host, path, [], None, b"", self.ak, self.sk)
        req = urllib.request.Request(self._url(key), method="HEAD", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers or {})
        except OSError as e:
            raise ConnectionError(f"minio HEAD {key}: {e}") from e

    def get_tags(self, key):
        """GetObjectTagging as {tag: value}. Best-effort: {} on any failure — expiry reporting
        must never change the allow/deny decision."""
        try:
            status, body = self._call("GET", key, query="tagging")
        except ConnectionError:
            return {}
        if status != 200:
            return {}
        try:
            root = ET.fromstring(body)
        except ET.ParseError:
            return {}
        out = {}
        for tag in root.iter():
            if tag.tag.rsplit("}", 1)[-1] == "Tag":
                fields = {c.tag.rsplit("}", 1)[-1]: (c.text or "") for c in tag}
                if fields.get("Key"):
                    out[fields["Key"]] = fields.get("Value", "")
        return out

    def put(self, key, data, ctype="application/octet-stream"):
        status, _ = self._call("PUT", key, data, ctype)
        return status


class MinioStateStore:
    """Gate state (ACLs, requests, rate limits) as JSON objects under STATE_PREFIX/."""

    def __init__(self, minio):
        self.minio = minio

    def get_json(self, rel):
        status, body = self.minio.get(f"{STATE_PREFIX}/{rel}")
        if status == 404:
            return None
        if status != 200:
            raise ConnectionError(f"state get {rel}: HTTP {status}")
        return json.loads(body)

    def put_json(self, rel, obj):
        status = self.minio.put(f"{STATE_PREFIX}/{rel}",
                                json.dumps(obj, separators=(",", ":")).encode(), "application/json")
        if status not in (200, 204):
            raise ConnectionError(f"state put {rel}: HTTP {status}")


# --------------------------------------------------------------------------------------------
# Tokens: signed (HMAC-SHA256, base64url payload . base64url signature). Used for approve/deny
# links (with exp) and CSRF tokens (with u/a/t binding). Never a secret itself: the key is.
#
# Domain separation : CSRF tokens and approve/deny action tokens are
# signed with DIFFERENT subkeys derived from the root key — HMAC(root, "artifact-gate/<purpose>/v1").
# One root key still lives in one secret, but a token can no longer cross purposes even if the
# `purp` field check were ever dropped: a token signed with the CSRF subkey fails signature
# verification against the action subkey and vice versa. The `purp` check is kept anyway
# (defense in depth). Callers keep passing the ROOT key; the subkey is derived inside.
# --------------------------------------------------------------------------------------------
def _derive_subkey(key, label):
    return hmac.new(key, label, hashlib.sha256).digest()


CSRF_SUBKEY_LABEL = b"artifact-gate/csrf/v1"
ACTION_SUBKEY_LABEL = b"artifact-gate/action/v1"


def _b64u(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign_token(payload, key):
    body = _b64u(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    return f"{body}.{_b64u(hmac.new(key, body.encode(), hashlib.sha256).digest())}"


def verify_token(token, key):
    """Return the payload dict, or None when the signature (or the encoding) is invalid."""
    try:
        body, sig = token.split(".", 1)
        want = hmac.new(key, body.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(want, _unb64u(sig)):
            return None
        obj = json.loads(_unb64u(body))
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def make_csrf(email, artifact, key, now):
    return sign_token({"v": 1, "purp": "csrf", "u": email, "a": artifact, "t": now,
                       "n": secrets.token_hex(8)}, _derive_subkey(key, CSRF_SUBKEY_LABEL))


def check_csrf(token, key, email, artifact, now, ttl=CSRF_TTL):
    # wrong-subkey signature fails first (domain separation); purp kept as defense in depth
    p = verify_token(token, _derive_subkey(key, CSRF_SUBKEY_LABEL))
    if not p or p.get("purp") != "csrf":
        return False
    if (p.get("u") or "").lower() != (email or "").lower():
        return False
    if p.get("a") != artifact:
        return False
    t = p.get("t", 0)
    return 0 <= now - t <= ttl


def make_action_token(request_id, action, key, now):
    return sign_token({"v": 1, "purp": "action", "id": request_id, "act": action,
                       "exp": now + TOKEN_TTL}, _derive_subkey(key, ACTION_SUBKEY_LABEL))


def check_action_token(token, key, now):
    # wrong-subkey signature fails first (domain separation); purp kept as defense in depth
    p = verify_token(token, _derive_subkey(key, ACTION_SUBKEY_LABEL))
    if not p or p.get("purp") != "action" or p.get("act") not in ("approve", "deny"):
        return None
    if not isinstance(p.get("exp"), int) or p["exp"] <= now:
        return None
    return p


# --------------------------------------------------------------------------------------------
# Authorization decision (pure function: unit-tested in tests/test_gate.py)
# --------------------------------------------------------------------------------------------
def _parse_expires(value):
    """ISO date (end of that day, UTC) or ISO datetime; naive datetimes are read as UTC."""
    if not value or not isinstance(value, str):
        return None
    try:
        if len(value) == 10:
            d = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            return d.timestamp() + 86399
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return None


def decide(user_email, user_groups, key, acl, now, pub_prefixes=PUB_PREFIXES):
    """(allowed, reason). acl=None means the .acl.json does not exist."""
    if acl is None:
        if key.startswith(pub_prefixes):
            return True, "pub: any signed-in tenant user"
        return False, "no-acl: deny by default (no owner to ask)"
    if not isinstance(acl, dict):
        return False, "bad-acl"
    exp = _parse_expires(acl.get("expires"))
    if exp is not None and now > exp:
        return False, "expired"
    email = (user_email or "").lower()
    if email and email == (acl.get("owner") or "").lower():
        return True, "owner"
    if email and email in [u.lower() for u in (acl.get("users") or []) if isinstance(u, str)]:
        return True, "user"
    acl_groups = {str(g).lower() for g in (acl.get("groups") or [])}
    if acl_groups:
        ug = {str(g).lower() for g in (user_groups or [])}
        if not ug:
            # Entra sent no groups claim: overage (>~200 groups) or the user has none. Deny and say
            # so loudly in the log (DESIGN/README: no Graph lookup in the PoC).
            return False, "groups-claim-empty (possible Entra overage)"
        if ug & acl_groups:
            return True, "group"
    return False, "not-listed"


def key_from_path(path):
    """Object key if `path` is under the bucket's public path, else None.

    Delivered links (CLI/MCP, docs/plugins.md §5) embed the configured bucket name
    (path-style), so the gate must accept `/<bucket>/<key>` — never a hardcoded
    /artifacts/. With the default bucket this is /artifacts/<key>."""
    if not path.startswith(BUCKET_PATH):
        return None
    return urllib.parse.unquote(path[len(BUCKET_PATH):])


def _bad_key(key):
    """Keys the gate must never serve, on any route (forwardAuth and plugin authz share this):
    empty, directory listing, ACL files, gate state, plugin storage, traversal segments."""
    if not key or key.endswith("/"):
        return True                                          # bucket root / dir listing: never
    if key == ".acl.json" or key.endswith("/.acl.json"):
        return True                                          # ACLs are never served
    if key == STATE_PREFIX or key.startswith(STATE_PREFIX + "/"):
        return True                                          # gate state is never served
    if key == PLUGIN_PREFIX or key.startswith(PLUGIN_PREFIX + "/"):
        return True                                          # plugin storage is never served
    if any(seg in (".", "..") for seg in key.split("/")):
        return True                                          # traversal attempts
    return False


# Query strings on a gate-signed upstream read: ALLOW-LIST. Any query key MinIO understands can
# turn a plain GetObject into another handler (sub-resources like ?acl/?tagging, ?lambdaArn= ->
# GetObjectLambdaHandler, response-* overrides, X-Amz-* presign params, ...), and a deny-list can
# never keep up with MinIO's router. No documented flow needs a query on an artifact read:
# delivered links (CLI, MCP) are bare paths and plugins (docs/plugins.md §5) receive the path, not
# a query. So the allowed set is EMPTY: any "?" in the forwarded URI, even an empty one, is
# refused with the same 404 as a never-served key. To allow a key later, add its exact raw form
# here; the parser below still refuses percent-escapes, duplicates and ';' in every key.
_ALLOWED_QUERY_KEYS = frozenset()


def _allowed_query_pairs(raw_query):
    """[(k, v), ...] when every key of `raw_query` is in _ALLOWED_QUERY_KEYS, else None.

    Fail-closed parsing: keys are compared byte-for-byte as sent (no case folding, no
    percent-decoding: `%61cl`, `acl%00`, `%20acl`, `ACL` are all simply "not allowed"), a key may
    appear once, and ';' (a separator for some parsers) is refused outright."""
    if raw_query == "" or ";" in raw_query:
        return None
    pairs, seen = [], set()
    for part in raw_query.split("&"):
        k, sep, v = part.partition("=")
        if not k or "%" in k or "+" in k or k in seen or k not in _ALLOWED_QUERY_KEYS:
            return None
        seen.add(k)
        pairs.append((k, urllib.parse.unquote(v)))
    return pairs


def upstream_auth_headers(method, host, uri, access_key, secret_key, amzdate=None):
    """SigV4 headers for the proxy's upstream request to MinIO, returned on a forwardAuth ALLOW.

    The artifact bucket has no anonymous read policy outside pub/ (and none at all on a host
    with anonymous pub/ disabled), so after the gate allows a read the reverse proxy forwards it
    to MinIO carrying these headers (Traefik forwardAuth `authResponseHeaders`, Caddy
    `forward_auth copy_headers`). They are signed with the dedicated read-signing S3 user
    (GATE_READ_ACCESS_KEY) and bind the method, the Host MinIO will see (the proxy passes the
    visitor's Host through), the exact path and the exact query sent; they never reach the
    visitor. Returns None (the read is refused) when the URI carries any query that is not on
    the allow-list (_ALLOWED_QUERY_KEYS, empty today: any "?" is refused)."""
    path, qmark, raw_query = uri.partition("?")
    raw_query = raw_query.split("#", 1)[0]
    pairs = []
    if qmark:
        pairs = _allowed_query_pairs(raw_query)
        if pairs is None:
            return None
    h = sigv4_headers(method, host, urllib.parse.unquote(path), pairs, None, b"",
                      access_key, secret_key, amzdate=amzdate)
    return {"Authorization": h["Authorization"], "X-Amz-Date": h["x-amz-date"],
            "X-Amz-Content-Sha256": h["x-amz-content-sha256"]}


# Request headers the visitor must never send on a forwarded read: MinIO acts on x-amz-* and
# x-minio-* request headers (SSE-C, checksum mode, snowball extract, ...) even when they are not
# part of the gate's SignedHeaders, so a client header would ride next to the gate's signature.
_REFUSED_HEADER_PREFIXES = ("x-amz-", "x-minio-")


def refused_client_headers(headers):
    """Names of the visitor's headers that a forwarded read must not carry (lowercased)."""
    return sorted({k.lower() for k in headers.keys()
                   if k.lower().startswith(_REFUSED_HEADER_PREFIXES)})


def plugin_authz_decision(email, groups, key, acl, now, head_status, tags=None, last_modified=None):
    """Build the /_gate/plugin/authz answer (docs/plugins.md §1) from the SAME decide() the
    forwardAuth path uses — plugins must never re-implement the decision. `email` empty means
    anonymous (the caller has already checked pub/ + GATE_ANONYMOUS_PUB_ENABLED). `tags` is the
    object's tag set (ttl) and `last_modified` a unix timestamp: together they give the ILM
    expiry when the ACL has no `expires`, so plugins can delete their data when the artifact dies.
    """
    anonymous = not email
    allowed, reason = decide(email, groups, key, acl, now)
    if allowed and head_status != 200:
        # same no-existence-leak rule as forwardAuth: "allowed but not there" answers as denied
        allowed, reason = False, "object-missing"
    if allowed and anonymous:
        reason = "pub: anonymous (anonymous-pub enabled)"
    expires = None
    if isinstance(acl, dict) and acl.get("expires"):
        exp_ts = _parse_expires(acl.get("expires"))
        if exp_ts is not None:
            expires = datetime.fromtimestamp(exp_ts, timezone.utc).isoformat()
    ttl = None
    if tags:
        try:
            ttl = int(tags.get("ttl"))
        except (TypeError, ValueError):
            ttl = None
    if expires is None and ttl is not None and last_modified is not None:
        expires = datetime.fromtimestamp(last_modified + ttl * 86400, timezone.utc).isoformat()
    return {"allowed": allowed, "reason": reason,
            "user": {"id": email or None, "name": email or "anonymous", "anonymous": anonymous},
            "artifact": {"key": key, "expires": expires, "ttl": ttl}}


class RateLimiter:
    """Per (user, artifact) request-access limit. State: one JSON object per pair; last-write-wins
    (acceptable for the PoC; a race can at most let one extra request through)."""

    def __init__(self, store, max_n=RATE_LIMIT_MAX, window=RATE_LIMIT_WINDOW):
        self.store, self.max_n, self.window = store, max_n, window

    def _key(self, email, artifact):
        return "rl/" + hashlib.sha256(f"{email}\n{artifact}".encode()).hexdigest() + ".json"

    def allow(self, email, artifact, now):
        k = self._key(email, artifact)
        try:
            rec = self.store.get_json(k) or {"ts": []}
        except (ConnectionError, ValueError):
            # corrupt/unreadable state: treat as empty (rate limiting is an abuse control, not an
            # authz control; failing open here cannot grant access to an artifact).
            rec = {"ts": []}
        ts = [t for t in rec.get("ts", []) if isinstance(t, int) and now - t < self.window]
        if len(ts) >= self.max_n:
            return False
        ts.append(now)
        self.store.put_json(k, {"ts": ts})
        return True


class RequestStore:
    """Pending access requests as _gate/req/<id>.json. status: pending -> approved|denied (single-use)."""

    def __init__(self, store):
        self.store = store

    def create(self, requester, artifact, owner, now):
        rid = secrets.token_hex(16)
        self.store.put_json(f"req/{rid}.json", {"id": rid, "requester": requester,
                                                "artifact": artifact, "owner": owner,
                                                "created": now, "status": "pending"})
        return rid

    def get(self, rid):
        if not rid or not all(c in "0123456789abcdef" for c in rid) or len(rid) > 64:
            return None
        try:
            return self.store.get_json(f"req/{rid}.json")
        except (ConnectionError, ValueError):
            return None

    def mark(self, rid, status, now):
        """Transition pending -> approved|denied. Returns the record ONLY when this call performed
        the transition; None when missing or already decided. Single-use without a CAS primitive:
        two concurrent POSTs that both read `pending` can both act (grant is idempotent; the
        requester could get a duplicate DM) — acceptable for the PoC, see README residual risks."""
        rec = self.get(rid)
        if rec is None or rec.get("status") != "pending":
            return None
        rec["status"], rec["updated"] = status, now
        self.store.put_json(f"req/{rid}.json", rec)
        return rec


# --------------------------------------------------------------------------------------------
# Notifier: small interface so email (Workspace) can replace Slack DMs later.
# --------------------------------------------------------------------------------------------
class SlackNotifier:
    """DM the artifact owner / requester through the DevopsAI bot. `send` never raises and never
    logs the token: it returns (ok, detail) where detail is the Slack API error or status."""

    def __init__(self, bot_token):
        self.token = bot_token

    def _api(self, method, fields):
        data = urllib.parse.urlencode(fields).encode()
        req = urllib.request.Request(f"https://slack.com/api/{method}", data=data,
                                     headers={"Authorization": f"Bearer {self.token}"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except Exception:
                return e.code, {}
        except OSError as e:
            return 0, {"error": type(e).__name__}

    def send(self, email, text):
        if not self.token:
            LOG.warning("notify %s: no slack token configured", email)
            return False, "no-token"
        st, body = self._api("users.lookupByEmail", {"email": email})
        if st != 200 or not body.get("ok"):
            err = body.get("error") or f"HTTP {st}"
            LOG.warning("users.lookupByEmail(%s) failed: %s", email, err)
            return False, f"lookupByEmail: {err}"
        uid = (body.get("user") or {}).get("id")
        if not uid:
            return False, "lookupByEmail: no user id"
        st, body = self._api("chat.postMessage", {"channel": uid, "text": text,
                                                  "unfurl_links": False, "unfurl_media": False})
        if st != 200 or not body.get("ok"):
            err = body.get("error") or f"HTTP {st}"
            LOG.warning("chat.postMessage(%s) failed: %s", email, err)
            return False, f"chat.postMessage: {err}"
        LOG.info("slack DM sent to %s (ok:true)", email)
        return True, "ok"


class LogNotifier:
    def send(self, email, text):  # noqa: ARG002
        LOG.info("notify (no transport): %s", email)
        return False, "no-transport"


# --------------------------------------------------------------------------------------------
# HTTP service
# --------------------------------------------------------------------------------------------
PAGE_CSS = ("body{font-family:system-ui,sans-serif;max-width:640px;margin:4rem auto;padding:0 1rem;"
            "color:#1f1f1f;line-height:1.55}code{background:#f2f2f2;padding:2px 4px;border-radius:4px}"
            "button{font:inherit;padding:.5rem 1rem;border-radius:6px;border:1px solid #444;"
            "background:#1a73e8;color:#fff;cursor:pointer;margin-right:.5rem}"
            ".muted{color:#666;font-size:.9rem}")
PAGE_CSP = "default-src 'none'; style-src 'unsafe-inline'"


class GateHandler(BaseHTTPRequestHandler):
    server_version = "artifact-gate/1.0"
    protocol_version = "HTTP/1.1"

    # -- plumbing ------------------------------------------------------------------
    def log_message(self, fmt, *args):  # route access logs through logging
        LOG.info("%s %s", self.address_string(), fmt % args)

    def _send(self, status, body=b"", ctype="text/html; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", PAGE_CSP)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    BODY_CAP = 64 * 1024

    def _read_body(self):
        """Read the request body fully so the keep-alive connection stays in sync: Traefik
        reuses backend connections and BaseHTTPRequestHandler does not drain bodies, so a
        byte left unread becomes the first byte of the NEXT request line on that connection
        (observed live as method 'xPOST' -> 501). Only the first BODY_CAP bytes are kept;
        the rest is read and discarded. Sets _body_truncated when the body was larger."""
        self._body_truncated = False
        if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            out = b""
            while True:
                line = self.rfile.readline(65536)
                try:
                    n = int(line.split(b";", 1)[0], 16)
                except ValueError:
                    break
                if n == 0:
                    self.rfile.readline(65536)          # final CRLF
                    break
                chunk = self.rfile.read(n)
                self.rfile.readline(65536)               # CRLF after each chunk
                if len(out) < self.BODY_CAP:
                    out += chunk[: self.BODY_CAP - len(out)]
                    if len(out) >= self.BODY_CAP:
                        self._body_truncated = True
            return out
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return b""
        if length < 0:
            return b""
        self._body_truncated = length > self.BODY_CAP
        data = b""
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                break
            remaining -= len(chunk)
            if len(data) < self.BODY_CAP:
                data += chunk[: self.BODY_CAP - len(data)]
        return data

    def _form(self):
        if getattr(self, "_body_truncated", False):
            return {}
        return {k: v[0] for k, v in urllib.parse.parse_qs(self._body.decode("utf-8", "replace")).items()}

    # -- identity ------------------------------------------------------------------
    # Contract with oauth2-proxy . The proxy image is pinned in
    # helm/artifacts/values.yaml (`image: quay.io/oauth2-proxy/oauth2-proxy:v7.7.1`) and the artifacts
    # proxy runs it with --proxy-prefix=/oauth2-artifacts --upstream=static://202
    # --set-xauthrequest=true --oidc-email-claim=preferred_username --oidc-groups-claim=groups
    # (helm/artifacts/templates/oauth2-proxy-artifacts.yaml). The gate calls
    # GET <OAUTH2_AUTH_URL> (= /oauth2-artifacts/auth) forwarding the visitor's Cookie (and an Authorization bearer when present), and
    # depends on exactly this behaviour of that pinned version:
    #   - valid session   -> HTTP 202 (the static://202 upstream) with X-Auth-Request-* response
    #     headers: X-Auth-Request-Email (the identity: the UPN, because the email claim is
    #     preferred_username) and X-Auth-Request-Groups (comma-separated Entra group object ids,
    #     absent when the user has no groups / Entra sends an overage claim).
    #   - no/invalid session -> HTTP 401.
    #   - any other status is unexpected -> identity backend error, fail closed (500).
    # Identity is taken ONLY from X-Auth-Request-Email. The proxy also emits
    # X-Auth-Request-Preferred-Username (same value today, since the email claim is
    # preferred_username), but it is deliberately NOT accepted as a fallback: the ACLs are keyed on
    # the email/UPN, and a second accepted header would widen the identity surface and silently
    # change identity semantics if --oidc-email-claim is ever reconfigured. A 202 without
    # X-Auth-Request-Email fails closed (500, logged), never a login.
    def _authenticate(self):
        """Ask oauth2-proxy about the visitor's cookie. Returns (email, groups, status).
        status: None = authenticated, 401 = no session, 500 = proxy unreachable or unexpected
        answer (fail closed). Only headers from THIS response are trusted; incoming
        X-Auth-Request-* are ignored. See the contract comment above."""
        # PUBLIC_HOST is used here on purpose: the gate talks to the proxy over the cluster
        # network and oauth2-proxy validates rd=/redirect against its own --whitelist-domain, so
        # the Host it sees must be the configured artifacts host, not whatever the visitor asked
        # for. If a public hostname ever fronts the deployment, the edge must rewrite Host/SNI to
        # PUBLIC_HOST: this request must present Host: PUBLIC_HOST, never the public name, or the
        # proxy's whitelist-domain check and the cookie host break.
        headers = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": PUBLIC_HOST}
        cookie = self.headers.get("Cookie")
        if cookie:
            headers["Cookie"] = cookie
        # A visitor may also present a bearer id_token (scripted checks against the OIDC issuer):
        # forward it too — it is the visitor's own credential, sent only to the trusted proxy.
        # Identity is still taken ONLY from the proxy's response headers.
        bearer = self.headers.get("Authorization")
        if bearer:
            headers["Authorization"] = bearer
        req = urllib.request.Request(OAUTH2_AUTH_URL, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                status, hdrs = r.status, r.headers
        except urllib.error.HTTPError as e:
            status, hdrs = e.code, e.headers
        except OSError as e:
            LOG.error("oauth2-proxy /auth unreachable: %s", e)
            return None, [], 500
        if status == 401:
            return None, [], 401
        if status != 202:
            LOG.error("oauth2-proxy /auth answered %s (expected 202/401)", status)
            return None, [], 500
        email = hdrs.get("X-Auth-Request-Email")
        groups = [g.strip() for g in (hdrs.get("X-Auth-Request-Groups") or "").split(",") if g.strip()]
        if not email:
            # fail closed: no X-Auth-Request-Email means no identity (see contract comment)
            LOG.error("oauth2-proxy /auth 202 without X-Auth-Request-Email — failing closed")
            return None, [], 500
        return email.lower(), groups, None

    # -- pages ---------------------------------------------------------------------
    def _page(self, title, body, status=200):
        return (f"<!doctype html><meta charset=utf-8><title>{html.escape(title)}</title>"
                f"<style>{PAGE_CSS}</style><h1>{html.escape(title)}</h1>{body}")

    def _deny_page(self, artifact):
        art = html.escape(artifact, quote=True)
        csrf = make_csrf(self._email, artifact, _KEY, int(time.time()))
        return self._page("Access required", (
            f"<p>You do not have access to <code>{art}</code>.</p>"
            f"<p>If you need it, ask the owner. The request is recorded and the owner is notified "
            f"and can approve or deny it with one click.</p>"
            f"<form method=POST action=https://{PUBLIC_HOST}/_gate/request>"
            f"<input type=hidden name=csrf value=\"{html.escape(csrf, quote=True)}\">"
            f"<input type=hidden name=artifact value=\"{art}\">"
            f"<button type=submit>Request access</button></form>"
            f"<p class=muted>artifact-gate</p>"), status=403)

    # -- forwardAuth ---------------------------------------------------------------
    def _authz_for(self, uri):
        """Shared by /_gate/auth and the request flow. Returns (verdict, artifact_key, acl).
        verdict: allow | deny | not_found | bad_path | unauth_401 | unauth_500"""
        path = urllib.parse.urlsplit(uri).path
        key = key_from_path(path)
        if key is None:
            return "bad_path", path, None
        if _bad_key(key):
            # dir listings, ACLs, gate state, plugin storage, traversal: never served
            return "bad_path", path, None
        email, groups, status = self._authenticate()
        if status == 401:
            return "unauth_401", key, None
        if status == 500:
            return "unauth_500", key, None
        self._email, self._groups = email, groups
        acl, err = read_acl(MINIO, key, now=int(time.time()))
        if err:
            LOG.error("acl read failed for %s: %s — denying (fail closed)", key, err)
            return "deny", key, None
        allowed, reason = decide(email, groups, key, acl, int(time.time()))
        LOG.info("authz user=%s key=%s allowed=%s reason=%s", email, key, allowed, reason)
        if allowed and MINIO.head(key) != 200:
            # allowed by policy but the object is not there (or MinIO errored): answer exactly like
            # "not allowed" so a 404 never reaches the client as MinIO's NoSuchKey XML — that XML was
            # the existence leak for pub/ objects without an ACL, where decide() allows first.
            LOG.info("authz user=%s key=%s allowed but object not readable -> deny page", email, key)
            return "deny", key, acl
        return ("allow" if allowed else "deny"), key, acl

    def _handle_forward_auth(self, method, uri):
        # X-Forwarded-Method/Uri come from Traefik's forwardAuth request itself (the /_gate/auth
        # path is not routed publicly, so only Traefik can call it).
        if method not in ("GET", "HEAD"):
            return self._send(405, self._page("Method not allowed", "<p>Only GET and HEAD are served.</p>"))
        # forwardAuth passes the visitor's headers along: refuse x-amz-*/x-minio-* before any
        # identity call or signing (fail closed), they would reach MinIO next to our signature.
        bad = refused_client_headers(self.headers)
        if bad:
            LOG.warning("forwardAuth: refused client S3 headers %s on %s", ",".join(bad), uri)
            return self._send(400, self._page("Bad request",
                                              "<p>S3 request headers are not accepted here.</p>"))
        verdict, key, _acl = self._authz_for(uri)
        if verdict == "allow":
            # the proxy's upstream read is signed by the gate (see upstream_auth_headers); the
            # Host is the one the proxy will pass through to MinIO
            host = (self.headers.get("X-Forwarded-Host") or self.headers.get("Host")
                    or PUBLIC_HOST).split(",")[0].strip()
            sig = upstream_auth_headers(method, host, uri, READ_ACCESS_KEY, READ_SECRET_KEY)
            if sig is None:
                LOG.warning("forwardAuth: query not on the allow-list refused: %s", uri)
                return self._send(404, self._page("Not found", "<p>Nothing here.</p>"))
            return self._send(200, b"ok", "text/plain", extra=sig)
        if verdict == "unauth_401":
            return self._send(401, b"login required", "text/plain")   # errors middleware -> 302 sign_in
        if verdict == "unauth_500":
            return self._send(500, b"identity backend error", "text/plain")
        if verdict == "bad_path":
            return self._send(404, self._page("Not found", "<p>Nothing here.</p>"))
        # deny AND missing artifact answer identically (no existence leak)
        return self._send(403, self._deny_page(urllib.parse.urlsplit(uri).path))

    # -- plugin authorization API (docs/plugins.md) ------------------------------------
    def _handle_plugin_authz(self, method):
        """POST /_gate/plugin/authz — the plugin authorization API (docs/plugins.md §1). Body:
        JSON {"artifact": "/<bucket>/<key>"} (default bucket: /artifacts/<key>) or form-encoded
        `artifact=`. Answers
        {allowed, reason, user:{id,name,anonymous}, artifact:{key,expires,ttl}} through the one
        and only decide(). Anonymous visitors are allowed only for pub/ keys and only while
        GATE_ANONYMOUS_PUB_ENABLED is true."""
        if method != "POST":
            return self._send(405, json.dumps({"error": "POST required"}), "application/json")
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype == "application/json":
            artifact = None
            try:
                obj = json.loads((self._body or b"").decode("utf-8", "replace"))
                if isinstance(obj, dict):
                    artifact = obj.get("artifact")
            except ValueError:
                pass
            if not isinstance(artifact, str):
                return self._send(400, json.dumps({"error": "artifact required"}),
                                  "application/json")
        else:
            artifact = self._form().get("artifact", "")
        path = urllib.parse.urlsplit(artifact).path
        key = key_from_path(path)
        if key is None:
            return self._send(400, json.dumps(
                {"error": f"artifact must be a {BUCKET_PATH.rstrip('/')}/ path"}),
                "application/json")
        if _bad_key(key):
            return self._send(400, json.dumps({"error": "artifact path not allowed"}),
                              "application/json")
        email, groups, status = self._authenticate()
        if status == 500:
            return self._send(500, json.dumps({"error": "identity backend error"}),
                              "application/json")
        if status == 401:
            # anonymous: only pub/ keys, and only while anonymous pub access is enabled at all
            if not (ANONYMOUS_PUB_ENABLED and key.startswith(PUB_PREFIXES)):
                ans = {"allowed": False, "reason": "unauthenticated",
                       "user": {"id": None, "name": "anonymous", "anonymous": True},
                       "artifact": {"key": key, "expires": None, "ttl": None}}
                LOG.info("plugin-authz anonymous key=%s allowed=False reason=unauthenticated", key)
                return self._send(200, json.dumps(ans), "application/json")
            email, groups = "", []
        acl, err = read_acl(MINIO, key, now=int(time.time()))
        if err:
            LOG.error("plugin-authz acl read failed for %s: %s — denying (fail closed)", key, err)
            ans = {"allowed": False, "reason": "acl-error",
                   "user": {"id": email or None, "name": email or "anonymous",
                            "anonymous": not email},
                   "artifact": {"key": key, "expires": None, "ttl": None}}
            return self._send(200, json.dumps(ans), "application/json")
        head_status, hdrs = MINIO.head_full(key)
        tags = MINIO.get_tags(key) if head_status == 200 else {}
        last_modified = None
        if head_status == 200 and hdrs.get("Last-Modified"):
            try:
                last_modified = parsedate_to_datetime(hdrs["Last-Modified"]).timestamp()
            except (TypeError, ValueError):
                last_modified = None
        ans = plugin_authz_decision(email, groups, key, acl, int(time.time()),
                                    head_status, tags, last_modified)
        LOG.info("plugin-authz user=%s key=%s allowed=%s reason=%s",
                 email or "-", key, ans["allowed"], ans["reason"])
        return self._send(200, json.dumps(ans), "application/json")

    # -- request access --------------------------------------------------------------
    def _handle_request_access(self):
        form = self._form()
        artifact = form.get("artifact") or ""
        path = urllib.parse.urlsplit(artifact).path
        if key_from_path(path) is None:
            return self._send(400, self._page("Bad request", "<p>Missing artifact.</p>"))
        email, groups, status = self._authenticate()
        if status == 401:
            return self._send(401, self._page("Session expired",
                                              "<p>Go back and sign in again, then request access.</p>"))
        if status == 500:
            return self._send(500, self._page("Error", "<p>Identity backend error.</p>"))
        self._email, self._groups = email, groups
        if not check_csrf(form.get("csrf", ""), _KEY, email, path, int(time.time())):
            LOG.warning("csrf rejected user=%s artifact=%s", email, path)
            return self._send(403, self._page("Bad request",
                                              "<p>Stale form. Go back, reload the page and try again.</p>"))
        key = key_from_path(path)
        if not RATE_LIMITER.allow(email, path, int(time.time())):
            LOG.warning("rate limit user=%s artifact=%s (no notification sent)", email, path)
            return self._send(429, self._page("Too many requests",
                                              "<p>You already asked for this artifact recently. "
                                              "Please wait before asking again.</p>"))
        # Same response whether or not the artifact exists / has an owner (no existence leak);
        # the request is only recorded when it can actually be answered.
        acl, err = read_acl(MINIO, key, now=int(time.time()))
        exists = MINIO.head(key) == 200
        owner = (acl or {}).get("owner") if isinstance(acl, dict) else None
        if err:
            # Distinguishable line for log grepping : the HTTP answer stays
            # the uniform 200 above (deliberate — telling "ACL unreadable" apart from "no owner"
            # would be an existence leak), but ops must be able to tell this case apart in logs.
            LOG.error("request-access acl-error key=%s err=%s", key, err)
        if exists and owner:
            rid = REQUESTS.create(email, path, owner, int(time.time()))
            approve = f"https://{PUBLIC_HOST}/_gate/approve?token=" + \
                urllib.parse.quote(make_action_token(rid, "approve", _KEY, int(time.time())))
            deny = f"https://{PUBLIC_HOST}/_gate/deny?token=" + \
                urllib.parse.quote(make_action_token(rid, "deny", _KEY, int(time.time())))
            text = (f":lock: *Access requested*\n"
                    f"Requester: `{email}`\nArtifact: `{path}`\n"
                    f"[Approve]({approve}) · [Deny]({deny})\n"
                    f"Links expire in {TOKEN_TTL // 86400} days and work once, only for you.")
            ok, detail = NOTIFIER.send(owner, text)
            LOG.info("request-access id=%s requester=%s artifact=%s owner=%s notify_ok=%s detail=%s",
                     rid, email, path, owner, ok, detail)
        else:
            LOG.info("request-access ignored (missing artifact or owner) requester=%s artifact=%s",
                     email, path)
        return self._send(200, self._page("Request sent",
                                          "<p>The owner has been notified. You will get a message "
                                          "when they decide.</p>"))

    # -- approve / deny ----------------------------------------------------------------
    def _handle_action(self, action, via_post):
        """GET renders a confirmation page (never changes state: Slack unfurls/prefetches links);
        POST performs the action. Both require the signed-in viewer to be the ACL owner."""
        if via_post:
            token = self._form().get("token", "")
        else:
            token = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("token", [""])[0]
        p = check_action_token(token, _KEY, int(time.time()))
        if p and p.get("act") != action:
            # a deny token must never approve (and vice versa): the token's verb binds the endpoint
            LOG.warning("action token for %s presented to /_gate/%s: refused", p.get("act"), action)
            p = None
        if not p:
            return self._send(410, self._page("Link invalid or expired",
                                              "<p>This link is broken, already used, or older than "
                                              f"{TOKEN_TTL // 86400} days.</p>"))
        rec = REQUESTS.get(p["id"])
        if rec is None:
            return self._send(410, self._page("Request not found", "<p>Nothing to do here.</p>"))
        email, _groups, status = self._authenticate()
        if status == 401:
            loc = f"https://{PUBLIC_HOST}/oauth2-artifacts/sign_in?rd=" + \
                urllib.parse.quote(f"https://{PUBLIC_HOST}/_gate/{action}?token={token}", safe="")
            return self._send(302, b"", "text/plain", {"Location": loc})
        if status == 500:
            return self._send(500, self._page("Error", "<p>Identity backend error.</p>"))
        self._email = email
        if email != (rec.get("owner") or "").lower():
            LOG.warning("action %s by non-owner viewer=%s owner=%s", action, email, rec.get("owner"))
            return self._send(403, self._page("Not the owner",
                                              "<p>Only the artifact owner listed in the ACL can act "
                                              "on this request.</p>"))
        if rec["status"] != "pending":
            # stored status is the action verb ("approve"/"deny"); show the past participle.
            decided = "approved" if rec["status"] == "approve" else "denied"
            return self._send(410, self._page("Already decided",
                                              f"<p>This request was already <b>{decided}</b>.</p>"))
        art = html.escape(rec["artifact"], quote=True)
        if not via_post:
            return self._send(200, self._page(f"Confirm: {action} access?", (
                f"<p><b>{html.escape(rec['requester'])}</b> asked for <code>{art}</code>.</p>"
                f"<p>Clicking the button below ({action}) is final: the link works once.</p>"
                f"<form method=POST action=https://{PUBLIC_HOST}/_gate/{action}>"
                f"<input type=hidden name=token value=\"{html.escape(token, quote=True)}\">"
                f"<button type=submit>Confirm {action}</button></form>")))
        # POST: perform. Single-use: only a still-pending request transitions (last-writer-wins).
        updated = REQUESTS.mark(rec["id"], action, int(time.time()))
        if updated is None or updated["status"] != action:
            return self._send(410, self._page("Already decided", "<p>Another decision won the race.</p>"))
        note = ""
        if action == "approve":
            ok, note = grant_access(MINIO, rec["artifact"], rec["requester"])
            if not ok:
                LOG.error("approve %s: ACL write failed: %s", rec["id"], note)
        msg = (f"Your access request for `{rec['artifact']}` was "
               f"{'approved — the link works now.' if action == 'approve' else 'denied.'}")
        ok, detail = NOTIFIER.send(rec["requester"], msg)
        LOG.info("action=%s id=%s by=%s requester=%s artifact=%s acl_note=%s notify_ok=%s detail=%s",
                 action, rec["id"], email, rec["requester"], rec["artifact"], note, ok, detail)
        return self._send(200, self._page(f"Request {action}d",
                                          f"<p>{html.escape(rec['requester'])} was notified.</p>"))

    # -- routing ---------------------------------------------------------------------
    def do_GET(self):  # noqa: N802
        self._route("GET")

    def do_HEAD(self):  # noqa: N802
        self._route("HEAD")

    def do_POST(self):  # noqa: N802
        self._route("POST")

    def do_PUT(self):  # noqa: N802
        self._read_body()   # drain: Traefik reuses the connection (see _read_body)
        self._send(405, self._page("Method not allowed", "<p>Writes go through the publisher path.</p>"))

    do_DELETE = do_PUT
    do_PATCH = do_PUT
    do_OPTIONS = do_PUT

    def _route(self, method):
        self._body = self._read_body()   # always drain the body (keep-alive sync, see _read_body)
        path = urllib.parse.urlsplit(self.path).path
        # Which listener this request arrived on (see module docstring). A server without an
        # explicit gate_mode is treated as PUBLIC: fail-closed for the decision endpoint.
        mode = getattr(self.server, "gate_mode", "public")
        if path == "/_gate/healthz":
            return self._send(200, b"ok", "text/plain")   # kubelet probes; answers on both listeners
        if path == "/_gate/auth":
            # forwardAuth target. Served ONLY on the decision listener (GATE_AUTH_PORT), which the
            # public IngressRoute never points at : even if a route
            # misdirected public traffic to the public listener, the decision endpoint 404s here.
            if mode != "auth":
                return self._send(404, self._page("Not found", "<p>Nothing here.</p>"))
            fwd_method = self.headers.get("X-Forwarded-Method", method)
            fwd_uri = self.headers.get("X-Forwarded-Uri", self.path)
            return self._handle_forward_auth(fwd_method, fwd_uri)
        if path == "/_gate/plugin/authz":
            # Plugin authorization API (docs/plugins.md): internal listener only, exactly like
            # /_gate/auth. The public IngressRoute never points at 8081, and a request that
            # somehow arrives on the public listener 404s (fail-closed).
            if mode != "auth":
                return self._send(404, self._page("Not found", "<p>Nothing here.</p>"))
            return self._handle_plugin_authz(method)
        if mode == "auth":
            # the decision listener serves nothing but /_gate/auth (+ healthz): no public endpoints
            return self._send(404, self._page("Not found", "<p>Nothing here.</p>"))
        if path == "/_gate/request" and method == "POST":
            return self._handle_request_access()
        if path == "/_gate/approve":
            return self._handle_action("approve", method == "POST")
        if path == "/_gate/deny":
            return self._handle_action("deny", method == "POST")
        if path.startswith(BUCKET_PATH):
            # Traefik only routes non-GET/HEAD here; GET/HEAD never reach the gate except via
            # /_gate/auth. Anything else is a write: refuse it.
            return self._send(405, self._page("Method not allowed",
                                              "<p>Only GET and HEAD are served on this host.</p>"))
        return self._send(404, self._page("Not found", "<p>Nothing here.</p>"))


# --------------------------------------------------------------------------------------------
# ACL access with a short cache (MinIO read is on every artifact request)
# --------------------------------------------------------------------------------------------
_acl_cache = {}
_acl_lock = threading.Lock()


def read_acl(minio, key, now, bypass_cache=False):
    """Return (acl|None, error|None). acl=None means the .acl.json does not exist."""
    acl_key = key.rsplit("/", 1)[0] + "/.acl.json" if "/" in key else ".acl.json"
    if not bypass_cache:
        with _acl_lock:
            hit = _acl_cache.get(acl_key)
            if hit and now - hit[0] < ACL_CACHE_TTL:
                return hit[1], hit[2]
    err = None
    acl = None
    try:
        status, body = minio.get(acl_key)
        if status == 200:
            try:
                acl = json.loads(body)
            except ValueError:
                err = "malformed JSON"
        elif status != 404:
            err = f"HTTP {status}"
    except ConnectionError as e:
        err = str(e)
    if not bypass_cache:
        with _acl_lock:
            _acl_cache[acl_key] = (now, acl, err)
    return acl, err


# Per-ACL-key locks serialising grant_access . The gate is a single
# replica but ThreadingHTTPServer: two owners approving two requests for the SAME directory at
# the same time used to read-modify-write concurrently and one grant could be silently lost
# (MinIO has no CAS/If-Match support here). One lock per acl_key serialises the read-modify-write
# inside the process. The dict grows one entry per directory with an approved grant — bounded by
# the number of published directories; fine at PoC volume (no eviction by design: a lock with
# waiters must not be dropped).
_grant_locks = {}
_grant_locks_guard = threading.Lock()


def _grant_lock(acl_key):
    with _grant_locks_guard:
        lock = _grant_locks.get(acl_key)
        if lock is None:
            lock = _grant_locks[acl_key] = threading.Lock()
        return lock


def grant_access(minio, artifact_path, requester):
    """Add `requester` to the ACL users of `artifact_path`. (ok, note).

    Serialised per ACL directory (see _grant_lock): concurrent approvals of the same directory
    can no longer lose a grant."""
    key = key_from_path(artifact_path)
    if key is None:
        return False, "bad artifact path"
    acl_key = key.rsplit("/", 1)[0] + "/.acl.json" if "/" in key else ".acl.json"
    with _grant_lock(acl_key):
        acl, err = read_acl(minio, key, now=int(time.time()), bypass_cache=True)  # write path: no cache
        if err or not isinstance(acl, dict):
            return False, f"acl unreadable: {err or 'missing'}"
        users = acl.get("users") or []
        if requester.lower() not in [u.lower() for u in users if isinstance(u, str)]:
            users.append(requester)
        acl["users"] = users
        status = minio.put(acl_key, json.dumps(acl, indent=2).encode(), "application/json")
    if status not in (200, 204):
        return False, f"put HTTP {status}"
    with _acl_lock:
        _acl_cache.pop(acl_key, None)
    return True, "added"


# --------------------------------------------------------------------------------------------
MINIO = MinioClient(MINIO_ENDPOINT, MINIO_ACCESS_KEY, MINIO_SECRET_KEY, BUCKET)
STATE = MinioStateStore(MINIO)
RATE_LIMITER = RateLimiter(STATE)
REQUESTS = RequestStore(STATE)
NOTIFIER = SlackNotifier(SLACK_BOT_TOKEN) if SLACK_BOT_TOKEN else LogNotifier()


def _build_servers():
    """Build (public_server, auth_server) exactly as main() runs them, WITHOUT serving (PR #9
    review, Warning 5): tests can assert the gate_mode/port wiring of the real production path
    instead of hand-rolling servers that could drift from main(). main() owns the threads."""
    auth_server = ThreadingHTTPServer(("0.0.0.0", AUTH_LISTEN_PORT), GateHandler)
    auth_server.gate_mode = "auth"
    public_server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), GateHandler)
    public_server.gate_mode = "public"
    return public_server, auth_server


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    LOG.info("artifact-gate starting: host=%s bucket=%s oauth2=%s pub_prefixes=%s rate=%d/%ds "
             "token_ttl=%ds slack=%s anonymous_pub=%s plugin_prefix=%s",
             PUBLIC_HOST, BUCKET, OAUTH2_AUTH_URL, PUB_PREFIXES,
             RATE_LIMIT_MAX, RATE_LIMIT_WINDOW, TOKEN_TTL, bool(SLACK_BOT_TOKEN),
             ANONYMOUS_PUB_ENABLED, PLUGIN_PREFIX)
    # Two listeners (see module docstring): the decision endpoint lives ONLY on the auth one.
    public_server, auth_server = _build_servers()
    threading.Thread(target=auth_server.serve_forever, daemon=True).start()
    LOG.info("listening: public=%d (request-access) forwardAuth=%d (decision endpoint)",
             LISTEN_PORT, AUTH_LISTEN_PORT)
    public_server.serve_forever()


if __name__ == "__main__":
    main()
