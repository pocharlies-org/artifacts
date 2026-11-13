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
X-Auth-Request-* headers), then decides against the ACL at the artifact's root (acl_key_for):
`u/<run>/.acl.json` for every key `u/<run>/...` and `g/<slug>/<run>/.acl.json` for every key
`g/<slug>/<run>/...`, at any depth (a zip with subfolders is one artifact, one ACL):

    { "owner": "<UPN>", "users": ["<UPN>", ...], "groups": ["<entra object id>", ...],
      "expires": "YYYY-MM-DD" | ISO datetime | null }

  - ACL allows: owner, any UPN in `users`, any member of any Entra object id in `groups`.
  - An `.acl.json` below the artifact root is never read and never served.
  - No artifact root (a key directly under `u/` or `g/<slug>/`, `acl/...`, anything outside the
    pub prefixes, `u/` and `g/`): deny, whatever ACL objects exist.
  - `pub/` is anonymous read by design (see "Anonymous pub/ reads" below): a `pub/` key whose
    root has no ACL is open to every caller, signed in or not; decide() gives a signed-in
    caller that answer. A `pub/` ACL, where one exists (no publisher writes one), is the one at
    the key's pub root: `pub/<run>/.acl.json` for `pub/<run>/...` at any depth, `pub/.acl.json`
    for a single file directly under `pub/` (acl_key_for); decide() evaluates it for a
    signed-in caller, and the anonymous decision refuses every key under it.
  - Anything else without an ACL: deny (the request-access button on the deny page goes nowhere).
  - An identity containing `#EXT#` (a directory guest's UPN) is refused on every endpoint.
  - `expires` in the past: deny (still requestable: the owner still exists).
  - Groups in the ACL but no `groups` claim from Entra (overage or user with no groups): deny + log.
  - Missing artifact and "not allowed" answer with the SAME 403 page (no existence leak) and the
    request-access POST silently does nothing when the artifact does not exist or has no owner.
  - `pub/` takes no access requests and the gate never writes a `pub/` ACL: pub/ is
    anonymous-readable by design, so there is nothing to ask for; its deny page offers no
    request, the request POST is refused on the path alone and grant_access refuses it.

Anonymous pub/ reads: `pub/` is anonymous read by design, for a host that is reachable on a
private network only, never publicly (the chart refuses artifactsGate.anonymousPubEnabled with
publicExposure). Where that anonymous decision lives depends on the route:

  - artifactsGate.anonymousPubThroughGate (compose: ARTIFACTS_PUB_MODE=gate): every `pub/` read
    asks `GET /_gate/pub-auth` on the decision listener through its own forwardAuth middleware
    (`gate-pub-auth`, on the `pub/` rules only) and is signed like any other allowed read; see
    pub_auth_decision. It asks no identity, allows only an existing object whose pub root has
    no ACL, and answers everything else with one uniform 404 (no login redirect).
  - otherwise: the route serves `pub/` straight from the store under its anonymous `pub/*` read
    policy, and the gate never sees those reads.

`/_gate/auth` stays the signed-in decision: it never answers 200 without a valid session.

The gate also serves the request-access flow (all state in MinIO under `_gate/`, written with the
gate's own least-privilege S3 user):

    POST /_gate/request   CSRF-bound, rate limited per user + decoded object key and per user
                          across artifacts -> records the request under _gate/req/<id>.json and
                          DMs the owner (Slack) Approve/Deny links, unless the owner already has
                          GATE_OWNER_PENDING_MAX open requests (then it is recorded, not sent).
    GET  /_gate/approve   renders a confirmation page (GET never changes state: Slack unfurls GETs).
    POST /_gate/approve   single-use signed token, acts only for the ACL owner: adds the requester
                          to the root ACL (a conditional write, see grant_access) and DMs them; a
                          failed write is never reported as approved and leaves the request
                          pending, and when the store may have applied it (a lost reply or a
                          5xx that one re-read did not settle) the owner is told so, never
                          "nothing was changed". /_gate/deny mirrors it without touching the ACL.

Two listeners, one process (— the forwardAuth decision endpoint and the
public surface must not share a port):

    GATE_PORT      (default 8080) public listener: the request-access surface only
                   (/_gate/request|approve|deny, 405 on writes, /_gate/healthz). It NEVER serves
                   /_gate/auth: a server without an explicit gate_mode is treated as public, so the
                   decision endpoint is fail-closed here even if a route misdirects public traffic.
    GATE_AUTH_PORT (default 8081) decision listener: /_gate/auth (traefik's forwardAuth target,
                   helm/artifacts/templates/gate-middlewares.yaml), /_gate/pub-auth (the anonymous
                   pub/ decision, target of the gate-pub-auth forwardAuth), /_gate/plugin/authz
                   (the plugin authorization API) plus /_gate/healthz. The public IngressRoute
                   excludes /_gate/auth and /_gate/healthz
                   (helm/artifacts/templates/artifacts-routes.yaml): the browser reaches the gate
                   only on 8080, and the decision endpoints only exist on 8081 (healthz answers on
                   both, it leaks nothing and the kubelet probes 8080).

Plugin contract (docs/plugins.md): the gate is the single source of the authorization decision —
plugins must call POST /_gate/plugin/authz (internal listener only, never routed publicly) instead
of re-implementing decide(). It answers {allowed, reason, user:{id,name,anonymous},
artifact:{key,expires,ttl}} using the one and only decide(). Anonymous visitors are allowed only
for pub/ keys and only while GATE_ANONYMOUS_PUB_ENABLED is true. Keys under the plugin storage
prefix (GATE_PLUGIN_PREFIX, default "_plugins"), gate state (GATE_STATE_PREFIX) and `_mcp/`
are never served on any route.

Single file, stdlib only, mounted from a ConfigMap onto a digest-pinned python:3.12-slim.
Configuration is env-only (see CONFIG below); secrets come from k8s secrets.
"""

import base64
import hashlib
import hmac
import html
import http.client
import io
import json
import logging
import os
import re
import secrets
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import OrderedDict
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = logging.getLogger("artifact-gate")

# Every log line is one line: control characters (C0, DEL, C1) and the Unicode line and
# paragraph separators in a message are written as escapes, so a client-chosen value (a key,
# a form field, a request line) can never start a forged line of its own.
_LOG_ESCAPES = {c: f"\\x{c:02x}" for c in (*range(0x20), *range(0x7f, 0xa0))}
_LOG_ESCAPES.update({0x2028: "\\u2028", 0x2029: "\\u2029"})


class _OneLineLogFilter(logging.Filter):
    def filter(self, record):
        msg = record.getMessage()
        safe = msg.translate(_LOG_ESCAPES)
        if safe != msg or record.args:
            record.msg, record.args = safe, None
        return True


LOG.addFilter(_OneLineLogFilter())

# --------------------------------------------------------------------------------------------
# CONFIG (env only; the Deployment wires k8s secrets into these)
# --------------------------------------------------------------------------------------------
def _env(name, default=None, required=False):
    v = os.environ.get(name, default)
    if required and not v:
        raise RuntimeError(f"required env var {name} is not set")
    return v


def _positive_int_env(name, default):
    """A whole number from 1 to 999999 from the environment (default when unset); the gate
    refuses to start on anything else, so a typo never turns a limit off."""
    raw = _env(name, str(default)).strip()
    if not re.fullmatch(r"[1-9][0-9]{0,5}", raw):
        raise RuntimeError(f"{name} must be a whole number from 1 to 999999, got {raw!r}")
    return int(raw)


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
# Anonymous (no session) reads of pub/: the plugin authz endpoint and /_gate/pub-auth (the
# anonymous pub/ decision, used when the route sends pub/ through the gate) allow them only while
# this is true; a route that serves pub/ straight from the store does not ask the gate. Fail-closed
# default: the chart must set it explicitly, and it must be false before any public hostname or
# tunnel (docs/plugins.md).
ANONYMOUS_PUB_ENABLED = _env("GATE_ANONYMOUS_PUB_ENABLED", "false").lower() in ("1", "true", "yes", "on")
PLUGIN_PREFIX = _env("GATE_PLUGIN_PREFIX", "_plugins")  # plugin storage prefix: never served
# Reserved for an MCP publisher's own bookkeeping objects: never an artifact, never served.
MCP_PREFIX = "_mcp"
RATE_LIMIT_MAX = int(_env("GATE_RATE_LIMIT_MAX", "5"))     # access requests per requester + file
RATE_LIMIT_WINDOW = int(_env("GATE_RATE_LIMIT_WINDOW_SECONDS", "86400"))
# Access requests one requester may send per window, across every artifact.
REQUESTER_RATE_LIMIT_MAX = _positive_int_env("GATE_REQUESTER_RATE_LIMIT_MAX", 20)
# Open requests an owner is sent at once: above it a request is recorded but not sent.
OWNER_PENDING_MAX = _positive_int_env("GATE_OWNER_PENDING_MAX", 10)
TOKEN_TTL = int(_env("GATE_TOKEN_TTL_SECONDS", "604800"))    # approve/deny links: 7 days
CSRF_TTL = int(_env("GATE_CSRF_TTL_SECONDS", "3600"))
# Negative/positive ACL cache TTL. This 15 s is the REAL default (the
# README said "30 s" — the docs now follow the code; keep them in sync if this ever changes).
ACL_CACHE_TTL = int(_env("GATE_ACL_CACHE_SECONDS", "15"))
# Upper bound of that cache (least recently used entries go first): one entry per ACL key
# asked about (an artifact root), so without a bound any visitor could grow it without limit.
ACL_CACHE_MAX = max(1, int(_env("GATE_ACL_CACHE_MAX_ENTRIES", "10000")))
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


def _lower_headers(headers):
    """Response headers as {lower-case name: value} (a repeated header keeps its last value)."""
    return {k.lower(): v for k, v in (headers.items() if headers else ())}


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

    def _call(self, method, key, body=None, ctype=None, query="", headers=None):
        """(status, body, response headers) of one signed request. `headers` are sent AND
        signed (If-Match, x-amz-tagging): the store refuses a signed request whose signed
        headers were changed. Response header names come back lower-case."""
        path = f"/{self.bucket}/{key}" if key else f"/{self.bucket}"
        # keep_blank_values: a bare subresource (`?tagging`) must be signed as `tagging=`;
        # dropping it made every GetObjectTagging a 403 (SignatureDoesNotMatch) on real MinIO,
        # so the plugin authz never reported the ttl/expiry.
        qp = urllib.parse.parse_qsl(query, keep_blank_values=True)
        extra = {k.lower(): v for k, v in (headers or {}).items()}
        if ctype:
            extra["content-type"] = ctype
        signed = sigv4_headers(method, self.host, path, qp, extra or None,
                               body or b"", self.ak, self.sk)
        req = urllib.request.Request(self._url(key, query), data=body, method=method, headers=signed)
        try:
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    return r.status, r.read(), _lower_headers(r.headers)
            except urllib.error.HTTPError as e:
                return e.code, e.read(), _lower_headers(e.headers)   # reading the body can fail too
        except OSError as e:
            raise ConnectionError(f"minio {method} {key}: {e}") from e
        except http.client.HTTPException as e:
            # A reply cut short or malformed (IncompleteRead, BadStatusLine, ...) is not an
            # OSError but is the same failure: the store could not be read. Only the class
            # name is kept: the exception's text can carry bytes of the store's reply.
            raise ConnectionError(f"minio {method} {key}: {type(e).__name__}") from e

    def get(self, key):
        status, body, _ = self._call("GET", key)
        return status, body

    def get_with_etag(self, key):
        """(status, body, ETag as sent by the store or None): the read half of a conditional
        write (put(..., if_match=etag))."""
        status, body, headers = self._call("GET", key)
        return status, body, headers.get("etag")

    def head(self, key):
        status, _, _ = self._call("HEAD", key)
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

    def get_tags_checked(self, key):
        """GetObjectTagging as ({tag: value}, None), or (None, error) when the tag set could not
        be read: a write that must keep the tags fails closed on a read it cannot trust."""
        try:
            status, body, _ = self._call("GET", key, query="tagging")
        except ConnectionError as e:
            return None, str(e)
        if status != 200:
            return None, f"HTTP {status}"
        try:
            root = ET.fromstring(body)
        except ET.ParseError:
            return None, "malformed tagging XML"
        out = {}
        for tag in root.iter():
            if tag.tag.rsplit("}", 1)[-1] == "Tag":
                fields = {c.tag.rsplit("}", 1)[-1]: (c.text or "") for c in tag}
                if fields.get("Key"):
                    out[fields["Key"]] = fields.get("Value", "")
        return out, None

    def get_tags(self, key):
        """GetObjectTagging as {tag: value}. Best-effort: {} on any failure — expiry reporting
        must never change the allow/deny decision."""
        tags, err = self.get_tags_checked(key)
        return tags if err is None else {}

    def put(self, key, data, ctype="application/octet-stream", if_match=None, tagging=None):
        """PUT one object, returns the status. if_match: the ETag the caller read; the store
        then writes only if the object is still that version and answers 412 otherwise.
        tagging: the object's tag set in x-amz-tagging form (`ttl=7`); a PUT replaces the tag
        set, so an overwrite without it leaves the object untagged."""
        headers = {}
        if if_match:
            headers["if-match"] = if_match
        if tagging:
            headers["x-amz-tagging"] = tagging
        status, _, _ = self._call("PUT", key, data, ctype, headers=headers)
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


# Audience prefixes of an artifact root: u/<run>/ (people) and g/<slug>/<run>/ (a group).
_ROOT_SEGMENTS = {"u": 2, "g": 3}


def acl_key_for(key, pub_prefixes=PUB_PREFIXES):
    """The one ACL object that governs `key`, or None when no ACL can (the key is denied).

    The single derivation of an ACL key: read_acl, grant_access and decide() all call it, so
    the forwardAuth decision, the plugin authz answer and the approval write agree on it.

        u/<run>/<path>           -> u/<run>/.acl.json          (the artifact root)
        g/<slug>/<run>/<path>    -> g/<slug>/<run>/.acl.json   (the artifact root)
        pub/<run>/<path>         -> pub/<run>/.acl.json        (the artifact root)
        pub/<file>               -> pub/.acl.json              (a single-file pub artifact)
        anything else            -> None

    <path> is one or more segments: every file of an artifact, at any depth, answers to the
    root ACL, and an .acl.json below the root is never read. None covers a key with no object
    below an artifact root (`u/x`, `g/<slug>/x`, an empty <run> or <slug>), `acl/...`, `_gate/...`
    and every key outside the pub prefixes, `u/` and `g/`.

    The pub roots (shown for the default prefix `pub/`; every entry of GATE_PUB_PREFIXES ends
    in "/", a prefix without one has no root) follow how pub/ is published: the CLI writes a
    run directory, `pub/<run>/<file>`, the same shape as `u/<run>/`; the MCP writes one file
    directly under the prefix, `pub/<name>-<id>.<ext>`, whose only directory is the prefix
    itself. No publisher writes an ACL under pub/ (anonymous read by design, see decide()).
    One that exists anyway is honoured at its root, at every depth below it, like `u/` and
    `g/`: it closes its root to anonymous callers and narrows it for signed-in ones."""
    if not isinstance(key, str) or not key:
        return None
    for prefix in pub_prefixes:
        if key.startswith(prefix):
            if not prefix.endswith("/"):
                return None
            rest = key[len(prefix):].split("/")
            if len(rest) == 1:
                return prefix + ".acl.json" if rest[0] else None
            if not rest[0] or not "/".join(rest[1:]):
                return None
            return prefix + rest[0] + "/.acl.json"
    parts = key.split("/")
    n = _ROOT_SEGMENTS.get(parts[0])
    if n is None or len(parts) <= n or not all(parts[:n]) or not "/".join(parts[n:]):
        return None
    return "/".join(parts[:n]) + "/.acl.json"


# decide()'s reason for a pub/ key whose root has no ACL: pub/ is the anonymous-read prefix by
# design, so such a key is open to every caller. A signed-in caller gets this answer from
# decide(); an anonymous one from pub_auth_decision (or the plugin authz answer), and only while
# GATE_ANONYMOUS_PUB_ENABLED is true.
PUB_OPEN_REASON = "pub: no ACL (anonymous read by design)"


def decide(user_email, user_groups, key, acl, now, pub_prefixes=PUB_PREFIXES):
    """(allowed, reason). acl is the object at acl_key_for(key); None means it does not exist."""
    if acl_key_for(key, pub_prefixes) is None:
        # no artifact root: no ACL can allow it, whatever objects exist (see acl_key_for)
        return False, "no-artifact-root: deny"
    if acl is None:
        if key.startswith(pub_prefixes):
            return True, PUB_OPEN_REASON
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


def artifact_root_path(artifact_path):
    """What an access grant for `artifact_path` covers, as a path: the directory of the ACL that
    governs it (acl_key_for), e.g. `/artifacts/u/<run>/` for any file of that artifact at any
    depth. None when no ACL can govern the path."""
    key = key_from_path(artifact_path)
    acl_key = acl_key_for(key) if key is not None else None
    if acl_key is None:
        return None
    return BUCKET_PATH + acl_key[:-len(".acl.json")]


def key_from_path(path):
    """Object key if `path` is under the bucket's public path, else None.

    Delivered links (CLI/MCP, docs/plugins.md §5) embed the configured bucket name
    (path-style), so the gate must accept `/<bucket>/<key>` — never a hardcoded
    /artifacts/. With the default bucket this is /artifacts/<key>."""
    if not path.startswith(BUCKET_PATH):
        return None
    return urllib.parse.unquote(path[len(BUCKET_PATH):])


def canonical_artifact_path(path):
    """`/<bucket>/<key>` with the key decoded once (key_from_path) and percent-encoded again in
    one fixed way, or None outside the bucket. Every spelling of one object key gives the same
    string (`…/index.html`, `…/%69ndex.html` and `…/%69%6edex.html` are one artifact), and
    key_from_path() of the result is that key again, never a second decode of it. Access
    requests are counted, recorded and shown under this name."""
    key = key_from_path(path)
    if key is None:
        return None
    return BUCKET_PATH + urllib.parse.quote(key, safe="/")


def _bad_key(key):
    """Keys the gate must never serve, on any route (forwardAuth and plugin authz share this):
    empty, directory listing, ACL files (at the root or nested), gate state, plugin storage,
    `_mcp/`, traversal segments, an empty segment or NUL."""
    if not key or key.endswith("/"):
        return True                                          # bucket root / dir listing: never
    if "//" in key or key.startswith("/") or "\x00" in key:
        return True                                          # empty segment or NUL: the store
                                                             # refuses both, never decided
    if key == ".acl.json" or key.endswith("/.acl.json"):
        return True                                          # ACLs are never served
    if key == STATE_PREFIX or key.startswith(STATE_PREFIX + "/"):
        return True                                          # gate state is never served
    if key == PLUGIN_PREFIX or key.startswith(PLUGIN_PREFIX + "/"):
        return True                                          # plugin storage is never served
    if key == MCP_PREFIX or key.startswith(MCP_PREFIX + "/"):
        return True                                          # MCP bookkeeping is never served
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


def split_forwarded_uri(uri):
    """(path, query) of a forwarded request target (X-Forwarded-Uri), or None when it is refused.

    The decision (_authz_for) and the signature (upstream_auth_headers) both take the path from
    this one function, so they always read the same key. Accepted: origin-form only, i.e. one
    leading "/" and nothing but printable ASCII without "#". Everything else could be read two
    ways and is refused before any identity call: a fragment ("/pub/x#y" was decided as pub/x and
    signed as pub/x#y), a scheme or an authority ("http://h/..." and "//h/..." put the host
    into the path one parser sees), spaces, control characters (urlsplit drops tab, CR and LF;
    a plain split keeps them) and non-ASCII bytes (a proxy sends them percent-encoded).
    `query` is None when there is no "?", else the raw text after it ("" for a bare "?")."""
    if not isinstance(uri, str) or not uri.startswith("/") or uri.startswith("//"):
        return None
    if "#" in uri or any(not "!" <= ch <= "~" for ch in uri):
        return None
    path, qmark, query = uri.partition("?")
    return path, (query if qmark else None)


def upstream_auth_headers(method, host, uri, access_key, secret_key, amzdate=None):
    """SigV4 headers for the proxy's upstream request to MinIO, returned on a forwardAuth ALLOW.

    The artifact bucket has no anonymous read policy outside pub/ (and none at all on a host
    with anonymous pub/ disabled), so after the gate allows a read the reverse proxy forwards it
    to MinIO carrying these headers (Traefik forwardAuth `authResponseHeaders`, Caddy
    `forward_auth copy_headers`). They are signed with the dedicated read-signing S3 user
    (GATE_READ_ACCESS_KEY) and bind the method, the Host MinIO will see (the proxy passes the
    visitor's Host through), the exact path and the exact query sent; they never reach the
    visitor. Returns None (the read is refused) when split_forwarded_uri refuses the URI or it
    carries any query that is not on the allow-list (_ALLOWED_QUERY_KEYS, empty today: any "?"
    is refused)."""
    target = split_forwarded_uri(uri)
    if target is None:
        return None
    path, raw_query = target
    pairs = []
    if raw_query is not None:
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


# --------------------------------------------------------------------------------------------
# Anonymous pub/ reads: GET /_gate/pub-auth (decision listener only; see the module docstring)
# --------------------------------------------------------------------------------------------
# What a pub/ key may not contain after its one decode, on the anonymous path: a second encoding
# (`%`), a dot-dot anywhere, an empty segment, a backslash, a path parameter (`;`), a fragment or
# query marker, and every control character (C0, DEL, C1). Each is a way for the key the gate
# decides and the key the store serves to differ; the signature binds them anyway, this refuses
# them before any store read.
_PUB_REFUSED_SUBSTRINGS = ("..", "//", "\\", ";", "%", "#", "?")


def pub_key_refused(key):
    """True when an anonymous pub/ read of `key` (already decoded once) is refused on its
    characters alone (the list above)."""
    if any(s in key for s in _PUB_REFUSED_SUBSTRINGS):
        return True
    return any(ord(c) < 0x20 or 0x7f <= ord(c) <= 0x9f for c in key)


def pub_auth_decision(method, uri, minio, now, header_names=(), enabled=None):
    """(allowed, key, reason) of one anonymous read, as /_gate/pub-auth decides it.

    Allowed only while anonymous pub/ is enabled (GATE_ANONYMOUS_PUB_ENABLED, or `enabled`),
    for a GET or HEAD of /<bucket>/<pub prefix>... with no query and no client x-amz-*/x-minio-*
    header (header_names), whose key, decoded once, is a key the gate serves (_bad_key) and
    passes pub_key_refused, whose pub root (acl_key_for) holds NO ACL object, and whose object
    exists. Nothing else is asked: no identity (a session cookie changes nothing here; the
    signed-in decision is /_gate/auth), no second decode. A store that cannot be read refuses
    (fail closed). `key` is the decided key (None when the URI was refused before one was
    read); `reason` is for the log only: the caller answers every refusal the same way."""
    if not (ANONYMOUS_PUB_ENABLED if enabled is None else enabled):
        return False, None, "anonymous pub/ disabled"
    if method not in ("GET", "HEAD"):
        return False, None, "method"
    if any(str(h).lower().startswith(_REFUSED_HEADER_PREFIXES) for h in header_names):
        return False, None, "client S3 header"
    target = split_forwarded_uri(uri)
    if target is None or target[1] is not None:
        return False, None, "malformed URI or a query"
    path = target[0]
    if not path.startswith(BUCKET_PATH):
        return False, None, "outside the bucket"
    try:
        # the same one decode as key_from_path, but bytes that are not UTF-8 are refused
        # instead of replaced (the store would read them differently)
        key = urllib.parse.unquote(path[len(BUCKET_PATH):], errors="strict")
    except UnicodeDecodeError:
        return False, None, "not UTF-8"
    if not key.startswith(PUB_PREFIXES):
        return False, key, "not pub/"
    if _bad_key(key) or pub_key_refused(key):
        return False, key, "never served"
    if acl_key_for(key) is None:
        return False, key, "no pub root"
    acl, err = read_acl(minio, key, now)
    if err:
        # unreadable, or an ACL object that is not JSON (one exists): refuse
        return False, key, f"acl unreadable ({err})"
    if acl is not None:
        return False, key, "acl present"
    try:
        exists = minio.head(key) == 200
    except ConnectionError:
        exists = False
    if not exists:
        return False, key, "object missing"
    return True, key, "pub: anonymous, no ACL"


# The one `reason` a denied visitor is told (docs/plugins.md §1), whatever decide() said:
# `not-listed`, `no-acl: ...`, `bad-acl` and `groups-claim-empty ...` would tell a stranger
# whether a directory has an ACL and what kind. The detailed reason stays in the gate's log.
DENIED_REASON = "denied"


def plugin_authz_decision(email, groups, key, acl, now, head_status, tags=None, last_modified=None,
                          name=None):
    """The /_gate/plugin/authz answer; see plugin_authz_decision_detail."""
    return plugin_authz_decision_detail(email, groups, key, acl, now, head_status, tags,
                                        last_modified, name)[0]


def plugin_authz_decision_detail(email, groups, key, acl, now, head_status, tags=None,
                                 last_modified=None, name=None):
    """(answer, detail): the /_gate/plugin/authz answer (docs/plugins.md §1) and the reason
    decide() gave, for the log. Built from the SAME decide() the
    forwardAuth path uses — plugins must never re-implement the decision. `email` empty means
    anonymous (the caller has already checked pub/ + GATE_ANONYMOUS_PUB_ENABLED). `tags` is the
    object's tag set (ttl) and `last_modified` a unix timestamp: together they give the ILM
    expiry when the ACL has no `expires`, so plugins can delete their data when the artifact dies.
    `name` is the visitor's display name (display only; falls back to the email).

    No existence leak: `expired` and `object-missing` (and the artifact's expiry/ttl) are told
    ONLY to a visitor who would otherwise be allowed. Anyone else gets DENIED_REASON, the same
    answer for a live artifact, an expired one, a missing one and a directory with or without
    an ACL — a plugin answering 410 vs 403 on that reason must not reveal to a stranger that an
    artifact exists or has expired.
    """
    anonymous = not email
    allowed, reason = decide(email, groups, key, acl, now)
    detail = reason
    if not allowed and reason == "expired":
        live_acl = {k: v for k, v in acl.items() if k != "expires"}
        would, live_reason = decide(email, groups, key, live_acl, now)
        if not would:
            reason = live_reason
            detail = f"expired ({live_reason})"
    if allowed and head_status != 200:
        # same no-existence-leak rule as forwardAuth: "allowed but not there" answers as denied
        allowed, reason = False, "object-missing"
        detail = reason
    if allowed and anonymous:
        reason = "pub: anonymous (anonymous-pub enabled)"
    if not allowed and reason not in ("expired", "object-missing"):
        reason = DENIED_REASON
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
    if not allowed and reason not in ("expired", "object-missing"):
        # a denied stranger learns nothing about the artifact's life either
        expires, ttl = None, None
    return ({"allowed": allowed, "reason": reason,
             "user": {"id": email or None, "name": (name or email) if email else "anonymous",
                      "anonymous": anonymous},
             "artifact": {"key": key, "expires": expires, "ttl": ttl}}, detail)


_NAME_MAX = 128


def display_name_from_auth_headers(hdrs, email):
    """Display name for plugins (docs/plugins.md §1 `user.name`), from the `name` claim of the
    id_token that oauth2-proxy returns in the Authorization header of its /auth answer
    (--set-authorization-header=true). DISPLAY ONLY: identity and every ACL decision stay on
    X-Auth-Request-Email. The token comes from the same trusted proxy response as the email, and
    it is used only when it belongs to that same identity (its email / preferred_username / upn
    equals the email); otherwise, or when there is no usable name, the email is the name."""
    auth = hdrs.get("Authorization") or ""
    parts = auth.split()
    if len(parts) != 2 or parts[0].lower() != "bearer" or parts[1].count(".") != 2:
        return email
    try:
        claims = json.loads(_unb64u(parts[1].split(".")[1]))
    except (ValueError, TypeError):
        return email
    if not isinstance(claims, dict):
        return email
    owners = {str(claims.get(c) or "").lower() for c in ("email", "preferred_username", "upn")}
    if (email or "").lower() not in owners:
        return email
    raw = claims.get("name")
    if not isinstance(raw, str):
        return email
    clean = " ".join("".join(ch for ch in raw if ch.isprintable()).split())[:_NAME_MAX].strip()
    return clean or email


# A directory guest's UPN carries `#EXT#` (`alice_example.org#EXT#@tenant.example`). The gate
# refuses such an identity on every endpoint, whatever the ACLs say. Defence in depth only: the
# identity the gate sees is the proxy's email claim, which for a guest is usually the guest's
# own address, so the login proxy's domain or group restriction stays the control.
_REFUSED_IDENTITY_MARKERS = ("#ext#",)


def refused_identity(email):
    """True when the gate must refuse this identity even with a valid session."""
    e = (email or "").lower()
    return any(m in e for m in _REFUSED_IDENTITY_MARKERS)


class RateLimiter:
    """Request-access limit over a sliding window: at most max_n requests per window.

    Per (user, artifact) by default: `allow(email, artifact_path, now)`. The artifact is its
    decoded object key (canonical_artifact_path), never the path as the client spelled it, so
    `…/index.html` and `…/%69ndex.html` count against one limit. With per_requester=True, per
    user across every artifact: `allow(email, None, now)`.

    State: one JSON object per bucket (rl/ per user and artifact, rq/ per user); last-write-wins
    (acceptable for the PoC; a race can at most let one extra request through)."""

    def __init__(self, store, max_n=RATE_LIMIT_MAX, window=RATE_LIMIT_WINDOW, per_requester=False):
        self.store, self.max_n, self.window = store, max_n, window
        self.per_requester = per_requester

    def _key(self, email, artifact):
        if self.per_requester:
            return "rq/" + hashlib.sha256(email.encode()).hexdigest() + ".json"
        ident = canonical_artifact_path(artifact) or artifact
        return "rl/" + hashlib.sha256(f"{email}\n{ident}".encode()).hexdigest() + ".json"

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
    """Access requests as _gate/req/<id>.json. status: pending -> approve|deny (single-use).

    A request names its artifact by the decoded object key (canonical_artifact_path): every
    spelling of one file is one artifact in the record, in the owner's message and in the grant.

    Per owner, _gate/owner/<sha256(owner)>.json lists the pending requests that owner was sent
    ([id, created]): reserve_owner_slot admits one more only while fewer than max_pending are
    listed, release_owner_slot drops one once it is decided or could not be sent, and an entry
    older than the approve/deny links (link_ttl) is dropped when read, since its links no
    longer work. Last-write-wins between gate processes, like RateLimiter."""

    def __init__(self, store, max_pending=OWNER_PENDING_MAX, link_ttl=TOKEN_TTL):
        self.store, self.max_pending, self.link_ttl = store, max_pending, link_ttl
        self._owner_lock = threading.Lock()

    def create(self, requester, artifact, owner, now):
        rid = secrets.token_hex(16)
        self.store.put_json(f"req/{rid}.json", {"id": rid, "requester": requester,
                                                "artifact": canonical_artifact_path(artifact)
                                                or artifact,
                                                "owner": owner, "created": now,
                                                "status": "pending"})
        return rid

    @staticmethod
    def _owner_rel(owner):
        return "owner/" + hashlib.sha256((owner or "").lower().encode()).hexdigest() + ".json"

    def _owner_pending(self, owner, now):
        """[[id, created], ...] of the requests `owner` was sent whose links still work. State
        that cannot be read or is malformed reads as none (an abuse control, like
        RateLimiter: it never decides who can read what)."""
        try:
            rec = self.store.get_json(self._owner_rel(owner))
        except (ConnectionError, ValueError):
            rec = None
        items = rec.get("pending") if isinstance(rec, dict) else None
        return [[i[0], i[1]] for i in (items if isinstance(items, list) else ())
                if isinstance(i, list) and len(i) == 2 and isinstance(i[0], str)
                and isinstance(i[1], int) and now - i[1] < self.link_ttl]

    def reserve_owner_slot(self, owner, rid, now):
        """True when request `rid` may be sent to `owner` (fewer than max_pending of their
        requests are open) and is now listed; False at the cap. Raises ConnectionError when
        the list cannot be written (then nothing is sent either)."""
        with self._owner_lock:
            pending = self._owner_pending(owner, now)
            if len(pending) >= self.max_pending:
                return False
            self.store.put_json(self._owner_rel(owner), {"pending": pending + [[rid, now]]})
            return True

    def release_owner_slot(self, owner, rid, now):
        """Drop request `rid` from `owner`'s open requests (decided, or never sent). Raises
        ConnectionError when the list cannot be written; the entry then goes when its links
        expire."""
        with self._owner_lock:
            pending = self._owner_pending(owner, now)
            kept = [p for p in pending if p[0] != rid]
            if len(kept) != len(pending):
                self.store.put_json(self._owner_rel(owner), {"pending": kept})

    def get(self, rid):
        if not rid or not all(c in "0123456789abcdef" for c in rid) or len(rid) > 64:
            return None
        try:
            return self.store.get_json(f"req/{rid}.json")
        except (ConnectionError, ValueError):
            return None

    def mark(self, rid, status, now):
        """Transition pending -> approve|deny. Returns the record ONLY when this call performed
        the transition; None when missing or already decided. An approval calls it only after
        the grant succeeded (_handle_action). Single-use without a CAS primitive:
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
    """DM the artifact owner / requester through a Slack bot. `send` never raises and never
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
# frame-ancestors (not covered by default-src) and X-Frame-Options: no gate page, the
# "Request access" and "Confirm" forms included, can be framed by another site.
PAGE_CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"

# Request bodies, read before any authentication. Only the POST endpoints below take one, and
# only with a Content-Length of at most POST_BODY_MAX bytes (their forms and JSON are a few
# hundred bytes). Everything else is refused before a byte of the body is read: any
# Transfer-Encoding (chunked), a missing, repeated or malformed Content-Length, a larger
# length, and a body on a method that takes none. A refused body is never read into memory.
POST_BODY_MAX = 16 * 1024
_POST_PATHS = {"public": ("/_gate/request", "/_gate/approve", "/_gate/deny"),
               "auth": ("/_gate/plugin/authz",)}
_CONTENT_LENGTH_RE = re.compile(r"[0-9]{1,10}")
# After a refusal that leaves request bytes unsent or unread, the gate closes the connection
# and first discards at most this much, for at most this long, so the client (or the proxy in
# front) reads the answer instead of a TCP reset.
_LINGER_MAX = 64 * 1024
_LINGER_SECONDS = 2
# Approve/deny tokens never reach a log line (the request line of /_gate/approve?token=...).
_TOKEN_IN_LOG_RE = re.compile(r"(token=)[^&\s\"']+")
# Total deadlines, not per-read timeouts: a client that sends one byte at a time still holds a
# thread (one per connection) for at most this long.
#   REQUEST_HEAD_SECONDS: from the start of a request (on a kept-alive connection, from the end
#     of the previous answer: the idle wait counts) to the end of its headers. Missed: the
#     connection is closed without an answer, as for an idle connection.
#   POST_BODY_SECONDS: from the end of the headers to the end of the body (at most
#     POST_BODY_MAX bytes). Missed: 408 and the connection is closed.
REQUEST_HEAD_SECONDS = 30
POST_BODY_SECONDS = 10


class _DeadlineReader(io.RawIOBase):
    """The raw reads of one connection (GateHandler.rfile reads through it), each bounded by
    the socket timeout and, while `deadline` (a time.monotonic() value) is set, by that
    deadline too. A read at or after the deadline raises socket.timeout, which
    BaseHTTPRequestHandler answers by closing the connection. A connection reset by the
    client reads as its end (no traceback for a client that went away)."""

    def __init__(self, sock, timeout):
        super().__init__()
        self._sock, self._timeout = sock, timeout
        self.deadline = None

    def readable(self):
        return True

    def readinto(self, buf):
        if self.deadline is None:
            return self._recv_into(buf)
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise socket.timeout("read deadline passed")     # = TimeoutError since 3.10
        self._sock.settimeout(left if self._timeout is None else min(left, self._timeout))
        try:
            return self._recv_into(buf)
        finally:
            self._sock.settimeout(self._timeout)      # writes and later reads: the usual timeout

    def _recv_into(self, buf):
        try:
            return self._sock.recv_into(buf)
        except ConnectionResetError:
            return 0


class GateHandler(BaseHTTPRequestHandler):
    server_version = "artifact-gate/1.0"
    protocol_version = "HTTP/1.1"
    # Socket timeout of every single read and write; the request line and headers, and a POST
    # body, have total deadlines on top (REQUEST_HEAD_SECONDS, POST_BODY_SECONDS).
    timeout = 30

    # -- plumbing ------------------------------------------------------------------
    def setup(self):
        super().setup()
        # every read of the request goes through the deadline reader (same buffering as the
        # stock socket file it replaces)
        stock, self._reader = self.rfile, _DeadlineReader(self.connection, self.timeout)
        self.rfile = io.BufferedReader(self._reader)
        stock.close()

    def handle_one_request(self):
        # the request line and headers (and the idle wait before them) must arrive in time:
        # a miss raises socket.timeout in the read, and the connection is closed
        self._reader.deadline = time.monotonic() + REQUEST_HEAD_SECONDS
        try:
            super().handle_one_request()
        finally:
            self._reader.deadline = None

    def parse_request(self):
        try:
            return super().parse_request()      # reads the headers
        finally:
            self._reader.deadline = None        # the head is in: no deadline for the handler

    def version_string(self):
        return self.server_version          # no Python version in the Server header

    def log_message(self, fmt, *args):  # route access logs through logging
        LOG.info("%s %s", self.address_string(), _TOKEN_IN_LOG_RE.sub(r"\1<redacted>", fmt % args))

    def log_request(self, code="-", size="-"):
        """Access log line with the path only: a query string (the approve/deny token) is
        replaced by `?<redacted>`."""
        if isinstance(code, HTTPStatus):
            code = code.value
        parts = self.requestline.split(" ")
        if len(parts) >= 2 and "?" in parts[1]:
            parts[1] = parts[1].split("?", 1)[0] + "?<redacted>"
        self.log_message('"%s" %s %s', " ".join(parts), str(code), str(size))

    def _send(self, status, body=b"", ctype="text/html; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", PAGE_CSP)
        self.send_header("X-Frame-Options", "DENY")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        drop = getattr(self, "_drop_body", False)
        if drop:
            self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        if drop:
            self._linger()

    def _linger(self):
        """Close after a refusal without reading the request body: send FIN after the answer,
        then discard what is still arriving (at most _LINGER_MAX bytes, at most _LINGER_SECONDS,
        nothing kept) so the answer is read before the close (RFC 9112 §9.6)."""
        sock = self.connection
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            return
        deadline = time.monotonic() + _LINGER_SECONDS
        left = _LINGER_MAX
        try:
            while left > 0:
                wait = deadline - time.monotonic()
                if wait <= 0:
                    break
                sock.settimeout(wait)
                got = sock.recv(min(left, 16384))
                if not got:
                    break
                left -= len(got)
        except OSError:
            pass

    def _refuse(self, status, text, as_json=False):
        """Answer `status` and close the connection without reading the request body."""
        self._drop_body = True
        if as_json:
            return self._send(status, json.dumps({"error": text}), "application/json")
        return self._send(status, self._page(HTTPStatus(status).phrase,
                                             f"<p>{html.escape(text)}</p>"))

    def send_error(self, code, message=None, explain=None):
        """The answers the HTTP layer writes itself (an unsupported method, a malformed request
        line or header, a request line or header block too long) carry the same headers as
        every gate page: no framing, no caching, no Python version. (http.server answers a
        request line whose version it cannot read the HTTP/0.9 way, without any header.)
        The status line keeps the standard reason phrase; the detail (which can echo the
        client's request line) is escaped into the page only. The connection is closed."""
        try:
            phrase, long_text = self.responses[code]
        except KeyError:
            phrase, long_text = "Error", ""
        message = phrase if message is None else message
        explain = long_text if explain is None else explain
        self.log_error("code %d, message %s", code, message)
        self.send_response(code)
        self.send_header("Connection", "close")
        body = b""
        if code >= 200 and code not in (HTTPStatus.NO_CONTENT, HTTPStatus.RESET_CONTENT,
                                        HTTPStatus.NOT_MODIFIED):
            body = self._page(phrase, f"<p>{html.escape(message)}</p>"
                                      f"<p class=muted>{html.escape(explain)}</p>").encode()
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", PAGE_CSP)
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def _body_framing(self):
        """How the request delimits its body: ("transfer-encoding", None) for any
        Transfer-Encoding, ("none", 0) without Content-Length, ("invalid", None) for a repeated
        or malformed one, else ("length", n)."""
        if self.headers.get_all("Transfer-Encoding"):
            return "transfer-encoding", None
        values = self.headers.get_all("Content-Length")
        if not values:
            return "none", 0
        # only space and tab around the digits (RFC 9110 OWS): str.strip() would also take
        # Unicode whitespace such as NBSP, which no HTTP parser in front of the gate accepts
        if len(values) != 1 or not _CONTENT_LENGTH_RE.fullmatch(values[0].strip(" \t")):
            return "invalid", None
        return "length", int(values[0].strip(" \t"))

    def _has_body(self):
        return self._body_framing() not in (("none", 0), ("length", 0))

    def _read_post_body(self, as_json=False):
        """The body of a POST endpoint, or None after a refusal (connection closed). Requires one
        valid Content-Length of at most POST_BODY_MAX; reads exactly that many bytes within
        POST_BODY_SECONDS in total (a miss: 408). Keeps keep-alive in sync: an accepted body is
        read in full."""
        kind, n = self._body_framing()
        if kind in ("transfer-encoding", "none"):
            return self._refuse(411, "Send the body with a Content-Length "
                                     "(a chunked or other Transfer-Encoding is refused).", as_json)
        if kind == "invalid":
            return self._refuse(400, "Invalid Content-Length.", as_json)
        if n > POST_BODY_MAX:
            return self._refuse(413, f"Request body larger than {POST_BODY_MAX} bytes.", as_json)
        self._reader.deadline = time.monotonic() + POST_BODY_SECONDS
        try:
            data = self.rfile.read(n) if n else b""
        except socket.timeout:
            return self._refuse(408, f"The request body did not arrive within "
                                     f"{POST_BODY_SECONDS} s.", as_json)
        finally:
            self._reader.deadline = None
        if len(data) != n:
            return self._refuse(400, "Request body shorter than its Content-Length.", as_json)
        return data

    def _form(self):
        return {k: v[0] for k, v in urllib.parse.parse_qs(self._body.decode("utf-8", "replace")).items()}

    # -- identity ------------------------------------------------------------------
    # Contract with oauth2-proxy . The proxy image is pinned in
    # helm/artifacts/values.yaml (`image: quay.io/oauth2-proxy/oauth2-proxy:v7.15.6`) and the artifacts
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
    # The proxy also runs with --set-authorization-header=true, so the 202 carries
    # `Authorization: Bearer <id_token>`: its `name` claim becomes the DISPLAY name plugins show
    # (display_name_from_auth_headers). It never feeds identity or an ACL decision, and the
    # public route to the proxy's /auth endpoint is blocked (the gate reaches it in-cluster).
    def _authenticate(self):
        """Ask oauth2-proxy about the visitor's cookie. Returns (email, groups, status).
        status: None = authenticated, 401 = no session, 403 = a session whose identity the gate
        refuses (refused_identity: email None, every caller answers 403), 500 = proxy
        unreachable or unexpected answer (fail closed). Only headers from THIS response are
        trusted; incoming X-Auth-Request-* are ignored. See the contract comment above."""
        self._display_name = None
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
        if refused_identity(email):
            LOG.warning("identity refused (guest account) user=%s", email.lower())
            return None, [], 403
        # display name for the plugin authz answer (never identity; see the helper)
        self._display_name = display_name_from_auth_headers(hdrs, email.lower())
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

    def _no_artifact_page(self, path):
        # a key with no artifact root (acl_key_for is None): no ACL, so no owner to ask. The
        # answer depends on the shape of the path only, never on what exists.
        return self._page("Access required", (
            f"<p>You do not have access to <code>{html.escape(path, quote=True)}</code>.</p>"
            f"<p>This address is not inside a published artifact, so there is no owner to "
            f"ask for access.</p><p class=muted>artifact-gate</p>"))

    def _pub_denied_page(self, path):
        # a pub/ key a signed-in visitor may not open (missing, or a stray ACL that does not
        # list them): the same page either way, and no request form, since pub/ takes no
        # access requests (the gate never writes a pub/ ACL)
        return self._page("Access required", (
            f"<p>You do not have access to <code>{html.escape(path, quote=True)}</code>.</p>"
            f"<p>This is a public (<code>pub/</code>) address: access to it cannot be "
            f"requested.</p><p class=muted>artifact-gate</p>"))

    def _refused_page(self):
        # the same page for every key and endpoint: it depends on the identity only
        return self._page("Access refused", "<p>This account cannot open artifacts here.</p>"
                                            "<p class=muted>artifact-gate</p>")

    # -- forwardAuth ---------------------------------------------------------------
    def _authz_for(self, uri):
        """Shared by /_gate/auth and the request flow. Returns (verdict, artifact_key, acl).
        verdict: allow | deny | not_found | bad_path | unauth_401 | refused | unauth_500"""
        target = split_forwarded_uri(uri)
        if target is None:
            # a URI the decision and the signature could read differently: never served
            return "bad_path", uri, None
        path = target[0]
        key = key_from_path(path)
        if key is None:
            return "bad_path", path, None
        if _bad_key(key):
            # dir listings, ACLs, gate state, plugin storage, traversal: never served
            return "bad_path", path, None
        email, groups, status = self._authenticate()
        if status == 401:
            return "unauth_401", key, None
        if status == 403:
            return "refused", key, None
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
        if verdict == "refused":
            return self._send(403, self._refused_page())
        if verdict == "unauth_500":
            return self._send(500, b"identity backend error", "text/plain")
        if verdict == "bad_path":
            return self._send(404, self._page("Not found", "<p>Nothing here.</p>"))
        if acl_key_for(key) is None:
            return self._send(403, self._no_artifact_page(split_forwarded_uri(uri)[0]))
        if key.startswith(PUB_PREFIXES):
            return self._send(403, self._pub_denied_page(split_forwarded_uri(uri)[0]))
        # deny AND missing artifact answer identically (no existence leak)
        return self._send(403, self._deny_page(split_forwarded_uri(uri)[0]))

    # -- anonymous pub/ decision -------------------------------------------------------
    def _handle_pub_auth(self, method, uri):
        """GET /_gate/pub-auth: the anonymous pub/ decision (pub_auth_decision), forwardAuth
        target of the gate-pub-auth middleware. Allow: 200 with the signed upstream read, like
        /_gate/auth. Everything else: one uniform answer, the same status, headers and body for
        a missing key, a key whose pub root has an ACL, a listing, an .acl.json, a key outside
        pub/, a malformed path, a write and a client S3 header, GET and HEAD alike, and never
        a redirect to a login."""
        allowed, key, reason = pub_auth_decision(method, uri, MINIO, int(time.time()),
                                                 header_names=list(self.headers.keys()))
        if allowed:
            host = (self.headers.get("X-Forwarded-Host") or self.headers.get("Host")
                    or PUBLIC_HOST).split(",")[0].strip()
            sig = upstream_auth_headers(method, host, uri, READ_ACCESS_KEY, READ_SECRET_KEY)
            if sig is not None:
                LOG.info("pub-auth key=%s allowed=True reason=%s", key, reason)
                return self._send(200, b"ok", "text/plain", extra=sig)
            reason = "not signable"     # unreachable: the decision refuses what this refuses
        LOG.info("pub-auth uri=%s allowed=False reason=%s", (uri or "")[:300], reason)
        return self._send(404, self._page("Not found", "<p>Nothing here.</p>"))

    # -- plugin authorization API (docs/plugins.md) ------------------------------------
    def _handle_plugin_authz(self, method):
        """POST /_gate/plugin/authz — the plugin authorization API (docs/plugins.md §1). Body:
        JSON {"artifact": "/<bucket>/<key>"} (default bucket: /artifacts/<key>) or form-encoded
        `artifact=`. Answers
        {allowed, reason, user:{id,name,anonymous}, artifact:{key,expires,ttl}} through the one
        and only decide(). Anonymous visitors are allowed only for pub/ keys that pass
        pub_key_refused (the anonymous edge's character list) and only while
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
        try:
            path = urllib.parse.urlsplit(artifact).path
        except ValueError:
            path = ""                     # client text urlsplit cannot read: not a bucket path
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
        if status == 403:
            # refused identity (refused_identity): the uniform deny, for every key
            ans = {"allowed": False, "reason": DENIED_REASON,
                   "user": {"id": None, "name": None, "anonymous": False},
                   "artifact": {"key": key, "expires": None, "ttl": None}}
            LOG.info("plugin-authz refused identity key=%s allowed=False reason=%s",
                     key, DENIED_REASON)
            return self._send(200, json.dumps(ans), "application/json")
        if status == 401:
            # anonymous: only pub/ keys, only while anonymous pub access is enabled at all, and
            # never a key the anonymous edge refuses on its characters (pub_key_refused): the
            # plugin answer must not say "allowed" for a spelling /_gate/pub-auth would refuse
            if not (ANONYMOUS_PUB_ENABLED and key.startswith(PUB_PREFIXES)
                    and not pub_key_refused(key)):
                ans = {"allowed": False, "reason": "unauthenticated",
                       "user": {"id": None, "name": "anonymous", "anonymous": True},
                       "artifact": {"key": key, "expires": None, "ttl": None}}
                LOG.info("plugin-authz anonymous key=%s allowed=False reason=unauthenticated", key)
                return self._send(200, json.dumps(ans), "application/json")
            email, groups = "", []
        acl, err = read_acl(MINIO, key, now=int(time.time()))
        malformed = err == ACL_MALFORMED
        if malformed:
            # The ACL object exists but is not JSON. Decided like any other unusable ACL
            # (decide() -> bad-acl: nobody is allowed), so a stranger gets the uniform `denied`
            # and cannot tell a broken ACL file from one that does not list them. The cause
            # goes to the log only.
            LOG.error("plugin-authz acl-error key=%s err=%s — decided as an unusable ACL (deny)",
                      key, err)
            acl, err = ACL_MALFORMED, None
        if err:
            # the store could not be read (an outage): the same for every key, so it reveals
            # nothing about one artifact
            LOG.error("plugin-authz acl read failed for %s: %s — denying (fail closed)", key, err)
            ans = {"allowed": False, "reason": "acl-error",
                   "user": {"id": email or None,
                            "name": (getattr(self, "_display_name", None) or email) if email
                            else "anonymous",
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
        ans, detail = plugin_authz_decision_detail(
            email, groups, key, acl, int(time.time()), head_status, tags, last_modified,
            name=getattr(self, "_display_name", None) if email else None)
        if malformed:
            detail = f"acl-error ({ACL_MALFORMED})"
        LOG.info("plugin-authz user=%s key=%s allowed=%s reason=%s detail=%s",
                 email or "-", key, ans["allowed"], ans["reason"], detail)
        return self._send(200, json.dumps(ans), "application/json")

    # -- request access --------------------------------------------------------------
    def _handle_request_access(self):
        form = self._form()
        artifact = form.get("artifact") or ""
        try:
            path = urllib.parse.urlsplit(artifact).path
        except ValueError:
            # client text urlsplit cannot read (`//[x`): not a path inside an artifact
            LOG.warning("request-access refused: the artifact value is not a path")
            return self._send(400, self._page("Bad request",
                                              "<p>This address is not inside a published "
                                              "artifact.</p>"))
        key = key_from_path(path)
        if key is None:
            return self._send(400, self._page("Bad request", "<p>Missing artifact.</p>"))
        if _bad_key(key) or acl_key_for(key) is None:
            # a path the gate never serves (dot segments, ACLs, state, listings) or one with no
            # artifact root: nothing to request and no owner to ask. Refused on its shape alone,
            # before any identity call or store read, like forwardAuth's bad_path.
            LOG.warning("request-access refused path=%s (never served or no artifact root)", path)
            return self._send(400, self._page("Bad request",
                                              "<p>This address is not inside a published "
                                              "artifact.</p>"))
        if key.startswith(PUB_PREFIXES):
            # pub/ is anonymous-readable by design: no access to request, no owner to ask, and
            # the gate never writes a pub/ ACL (grant_access refuses it). Refused on the path
            # alone, before any identity call or store read.
            LOG.warning("request-access refused path=%s (pub/ takes no access requests)", path)
            return self._send(400, self._page("Bad request",
                                              "<p>This is a public (<code>pub/</code>) address: "
                                              "access to it cannot be requested.</p>"))
        email, groups, status = self._authenticate()
        if status == 401:
            return self._send(401, self._page("Session expired",
                                              "<p>Go back and sign in again, then request access.</p>"))
        if status == 403:
            return self._send(403, self._refused_page())
        if status == 500:
            return self._send(500, self._page("Error", "<p>Identity backend error.</p>"))
        self._email, self._groups = email, groups
        if not check_csrf(form.get("csrf", ""), _KEY, email, path, int(time.time())):
            LOG.warning("csrf rejected user=%s artifact=%s", email, path)
            return self._send(403, self._page("Bad request",
                                              "<p>Stale form. Go back, reload the page and try again.</p>"))
        # The limits count the artifact by its decoded key (canonical_artifact_path), whatever
        # spelling the form carried. Both are checked before the store is read, so the answer
        # stays the same whether or not the artifact exists.
        now = int(time.time())
        canon = canonical_artifact_path(path)
        if not RATE_LIMITER.allow(email, path, now):
            LOG.warning("rate limit user=%s artifact=%s (no notification sent)", email, canon)
            return self._send(429, self._page("Too many requests",
                                              "<p>You already asked for this artifact recently. "
                                              "Please wait before asking again.</p>"))
        if not REQUESTER_LIMITER.allow(email, None, now):
            LOG.warning("rate limit user=%s: %d access requests in %d s across artifacts "
                        "(no notification sent)", email, REQUESTER_LIMITER.max_n,
                        REQUESTER_LIMITER.window)
            return self._send(429, self._page("Too many requests",
                                              "<p>You have sent many access requests recently. "
                                              "Please wait before asking again.</p>"))
        # Same response whether or not the artifact exists / has an owner (no existence leak);
        # the request is only recorded when it can actually be answered.
        acl, err = read_acl(MINIO, key, now=now)
        exists = MINIO.head(key) == 200
        owner = (acl or {}).get("owner") if isinstance(acl, dict) else None
        if err:
            # Distinguishable line for log grepping : the HTTP answer stays
            # the uniform 200 above (deliberate — telling "ACL unreadable" apart from "no owner"
            # would be an existence leak), but ops must be able to tell this case apart in logs.
            LOG.error("request-access acl-error key=%s err=%s", key, err)
        if exists and owner:
            rid = REQUESTS.create(email, path, owner, now)
            # Per-owner cap: an owner is sent at most REQUESTS.max_pending open requests at a
            # time; above it the request is still recorded (and logged) but nothing is sent.
            try:
                admitted = REQUESTS.reserve_owner_slot(owner, rid, now)
                held = f"the owner already has {REQUESTS.max_pending} open requests"
            except ConnectionError as e:
                admitted, held = False, f"the owner's open requests could not be written: {e}"
            if not admitted:
                LOG.warning("request-access id=%s requester=%s artifact=%s owner=%s held: %s "
                            "(recorded, no notification sent)", rid, email, canon, owner, held)
                return self._request_sent()
            approve = f"https://{PUBLIC_HOST}/_gate/approve?token=" + \
                urllib.parse.quote(make_action_token(rid, "approve", _KEY, now))
            deny = f"https://{PUBLIC_HOST}/_gate/deny?token=" + \
                urllib.parse.quote(make_action_token(rid, "deny", _KEY, now))
            text = (f":lock: *Access requested*\n"
                    f"Requester: `{email}`\nRequested file: `{canon}`\n"
                    f"Approving gives access to the whole artifact `{artifact_root_path(canon)}`: "
                    f"every file in it, not only this one.\n"
                    f"[Approve]({approve}) · [Deny]({deny})\n"
                    f"Links expire in {TOKEN_TTL // 86400} days and work once, only for you.")
            ok, detail = NOTIFIER.send(owner, text)
            if not ok:
                # never sent: it does not hold one of the owner's open-request places
                try:
                    REQUESTS.release_owner_slot(owner, rid, now)
                except ConnectionError as e:
                    LOG.error("request-access id=%s: owner's open requests not updated: %s", rid, e)
            LOG.info("request-access id=%s requester=%s artifact=%s owner=%s notify_ok=%s detail=%s",
                     rid, email, canon, owner, ok, detail)
        else:
            LOG.info("request-access ignored (missing artifact or owner) requester=%s artifact=%s",
                     email, canon)
        return self._request_sent()

    def _request_sent(self):
        # one answer for a request that was sent, held at the owner's cap, or not recorded
        # (missing artifact or owner): telling them apart would leak what exists
        return self._send(200, self._page("Request sent",
                                          "<p>Your request has been received. You will get a "
                                          "message when the owner decides.</p>"))

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
        if status == 403:
            return self._send(403, self._refused_page())
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
        root = artifact_root_path(rec["artifact"]) or rec["artifact"]
        root_html = html.escape(root, quote=True)
        requester = html.escape(rec["requester"])
        if not via_post:
            scope = (f"<p>Approving gives <b>{requester}</b> access to the whole artifact "
                     f"<code>{root_html}</code>: every file in it, not only this one.</p>"
                     if action == "approve" else "")
            return self._send(200, self._page(f"Confirm: {action} access?", (
                f"<p><b>{requester}</b> asked for <code>{art}</code>.</p>{scope}"
                f"<p>Clicking the button below ({action}) is final: the link works once.</p>"
                f"<form method=POST action=https://{PUBLIC_HOST}/_gate/{action}>"
                f"<input type=hidden name=token value=\"{html.escape(token, quote=True)}\">"
                f"<button type=submit>Confirm {action}</button></form>")))
        # POST: perform. An approval grants first and records the decision second. The grant
        # is idempotent (a requester already listed is not written again), so a cut reply on
        # the request's record, or a gate stopped between the two writes, leaves at worst a
        # pending request whose access is already granted (the same link closes it), never a
        # request recorded as approved with nothing granted.
        note = ""
        if action == "approve":
            try:
                ok, note = grant_access(MINIO, rec["artifact"], rec["requester"])
            except Exception as e:  # noqa: BLE001 - defensive
                # Any failure grant_access does not report itself is still a failed grant: the
                # same answer as below, never a dropped connection. The log gets the class
                # name only (no text, no traceback: either could carry request or store data).
                ok, note = False, f"unexpected {type(e).__name__}"
            if not ok:
                # Never "approved" for a grant that did not happen: the requester is not told
                # anything, the request is still pending (it was not marked, so the same link
                # can be used again) and the owner's page says what happened. The cause stays
                # in the log.
                unknown = grant_outcome_unknown(note)
                LOG.error("approve %s: ACL write failed: %s (requester=%s artifact=%s "
                          "request still pending, requester not notified, access list %s)",
                          rec["id"], note, rec["requester"], rec["artifact"],
                          "may or may not have been updated" if unknown else "unchanged")
                if unknown:
                    # The store may have applied the write (its reply was lost or was a 5xx,
                    # and a re-read did not settle it): never "nothing was changed" here. A
                    # retry of the same link finishes the approval and never adds anyone twice;
                    # Deny writes no ACL, so it would not take back an access already added.
                    return self._send(503, self._page("Access not confirmed", (
                        f"<p>It is not known whether <b>{requester}</b> was given access to the "
                        f"artifact <code>{root_html}</code>: the store did not confirm the "
                        f"update, so its access list may or may not have been updated. They "
                        f"were not notified.</p>"
                        "<p>Use the same link again to finish: it reads the access list "
                        "again and never adds anyone twice.</p>"
                        "<p>Deny does not remove access that was already added: to take it "
                        "back, publish the artifact's access list again without them.</p>")))
                return self._send(503, self._page("Access not granted", (
                    f"<p><b>{requester}</b> was <b>not</b> given access to the artifact "
                    f"<code>{root_html}</code>: its access list could not be updated. "
                    f"Nothing was changed and they were not notified.</p>"
                    "<p>The request is still open: the same link can be used again.</p>")))
        # Record the decision. Single-use: only a still-pending request transitions
        # (last-writer-wins).
        try:
            updated = REQUESTS.mark(rec["id"], action, int(time.time()))
        except ConnectionError as e:
            if action == "deny":
                LOG.error("deny %s: the decision could not be recorded: %s (requester=%s "
                          "artifact=%s, requester not notified)", rec["id"], e,
                          rec["requester"], rec["artifact"])
                return self._send(503, self._page("Decision not confirmed", (
                    f"<p>The store did not confirm that the request of <b>{requester}</b> "
                    f"is denied. They were not notified.</p>"
                    "<p>Use the same link again: it denies the request if it is still "
                    "open.</p>")))
            # The access is granted, and that is the outcome: the requester is told. The record
            # may still say pending; then the same link closes it (the grant finds the
            # requester listed and writes nothing).
            LOG.error("approve %s: access granted, but the decision could not be recorded: %s "
                      "(requester=%s artifact=%s)", rec["id"], e, rec["requester"],
                      rec["artifact"])
            updated = {"status": action}
        if updated is None or updated["status"] != action:
            current = (REQUESTS.get(rec["id"]) or {}).get("status")
            if action == "approve" and current == "deny":
                # Approve and Deny of one request at the same time: this approval granted the
                # access, the Deny recorded the decision. Say both; Deny writes no ACL.
                LOG.warning("approve %s: access granted (%s), but a deny was recorded at the "
                            "same time (requester=%s artifact=%s, not notified of the approval)",
                            rec["id"], note, rec["requester"], rec["artifact"])
                return self._send(409, self._page("Decided twice", (
                    f"<p><b>{requester}</b> was given access to the whole artifact "
                    f"<code>{root_html}</code> by this approval, but a Deny of the same request "
                    f"was recorded at the same time. They were not told about the approval.</p>"
                    "<p>Deny does not remove access that was already added: to take it back, "
                    "publish the artifact's access list again without them.</p>")))
            return self._send(410, self._page("Already decided", "<p>Another decision won the race.</p>"))
        self._release_owner_slot(rec)
        if action == "approve":
            msg = (f"Your access request for `{rec['artifact']}` was approved: you can now open "
                   f"the whole artifact `{root}`.")
            done = (f"<p><b>{requester}</b> can now open the whole artifact "
                    f"<code>{root_html}</code>. They were notified.</p>")
        else:
            msg = f"Your access request for `{rec['artifact']}` was denied."
            done = f"<p>{requester} was notified.</p>"
        ok, detail = NOTIFIER.send(rec["requester"], msg)
        LOG.info("action=%s id=%s by=%s requester=%s artifact=%s acl_note=%s notify_ok=%s detail=%s",
                 action, rec["id"], email, rec["requester"], rec["artifact"], note, ok, detail)
        return self._send(200, self._page(
            "Request approved" if action == "approve" else "Request denied", done))

    def _release_owner_slot(self, rec):
        """A decided request no longer holds one of its owner's open-request places."""
        try:
            REQUESTS.release_owner_slot(rec.get("owner"), rec["id"], int(time.time()))
        except ConnectionError as e:
            LOG.error("request %s decided, owner's open requests not updated: %s", rec["id"], e)

    # -- routing ---------------------------------------------------------------------
    def do_GET(self):  # noqa: N802
        self._route("GET")

    def do_HEAD(self):  # noqa: N802
        self._route("HEAD")

    def do_POST(self):  # noqa: N802
        self._route("POST")

    def do_PUT(self):  # noqa: N802
        # Never served, so the body is never read: with one, the connection closes after the 405
        # (an unread byte would otherwise start the next request line on a reused connection).
        self._body, self._drop_body = b"", self._has_body()
        self._send(405, self._page("Method not allowed", "<p>Writes go through the publisher path.</p>"))

    do_DELETE = do_PUT
    do_PATCH = do_PUT
    do_OPTIONS = do_PUT

    def _route(self, method):
        self._body, self._drop_body = b"", False
        try:
            path = urllib.parse.urlsplit(self.path).path
        except ValueError:
            # a request target urlsplit cannot read (`http://[x/`): nothing is routed for it,
            # and its body (if any) is not read
            return self._refuse(400, "Bad request target.")
        # Which listener this request arrived on (see module docstring). A server without an
        # explicit gate_mode is treated as PUBLIC: fail-closed for the decision endpoint.
        mode = getattr(self.server, "gate_mode", "public")
        # Request body (see POST_BODY_MAX): read only for a POST endpoint of this listener.
        if method == "POST" and path in _POST_PATHS.get(mode, ()):
            body = self._read_post_body(as_json=(path == "/_gate/plugin/authz"))
            if body is None:
                return None
            self._body = body
        elif self._has_body():
            if method in ("GET", "HEAD"):
                return self._refuse(400, "A request body is not accepted here.")
            # a POST anywhere else: answered below (404/405) without reading the body, then closed
            self._drop_body = True
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
        if path == "/_gate/pub-auth":
            # The anonymous pub/ decision (gate-pub-auth forwardAuth target). Decision listener
            # only, exactly like /_gate/auth: on the public listener it 404s.
            if mode != "auth":
                return self._send(404, self._page("Not found", "<p>Nothing here.</p>"))
            return self._handle_pub_auth(self.headers.get("X-Forwarded-Method", method),
                                         self.headers.get("X-Forwarded-Uri", self.path))
        if path == "/_gate/plugin/authz":
            # Plugin authorization API (docs/plugins.md): internal listener only, exactly like
            # /_gate/auth. The public IngressRoute never points at 8081, and a request that
            # somehow arrives on the public listener 404s (fail-closed).
            if mode != "auth":
                return self._send(404, self._page("Not found", "<p>Nothing here.</p>"))
            return self._handle_plugin_authz(method)
        if mode == "auth":
            # the decision listener serves nothing but its decision endpoints (+ healthz): no
            # public endpoints
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
# acl_key -> (fetched_at, acl, err), least recently used first. Bounded: an entry lives at most
# ACL_CACHE_TTL seconds and the cache holds at most ACL_CACHE_MAX entries (oldest use evicted).
_acl_cache = OrderedDict()
_acl_lock = threading.Lock()


def _acl_cache_get(acl_key, now):
    with _acl_lock:
        hit = _acl_cache.get(acl_key)
        if hit is None:
            return None
        if now - hit[0] < ACL_CACHE_TTL:
            _acl_cache.move_to_end(acl_key)
            return hit
        del _acl_cache[acl_key]          # stale: never served again
        return None


def _acl_cache_put(acl_key, entry, now):
    with _acl_lock:
        _acl_cache[acl_key] = entry
        _acl_cache.move_to_end(acl_key)
        while _acl_cache:                # stale entries at the old end go first
            first = next(iter(_acl_cache.values()))
            if now - first[0] < ACL_CACHE_TTL:
                break
            _acl_cache.popitem(last=False)
        while len(_acl_cache) > ACL_CACHE_MAX:
            _acl_cache.popitem(last=False)


# read_acl's error for an ACL object that exists but is not valid JSON (an operator error):
# forwardAuth and plugin authz answer it like any other deny, never with a distinct reason.
ACL_MALFORMED = "malformed JSON"


def read_acl(minio, key, now, bypass_cache=False):
    """Return (acl|None, error|None) for the ACL that governs `key` (acl_key_for). acl=None
    with no error means that object does not exist, or the key has no ACL at all (no artifact
    root): then nothing is read and decide() denies. An object that is not JSON, or whose JSON
    is `null`, is (None, ACL_MALFORMED)."""
    acl_key = acl_key_for(key)
    if acl_key is None:
        return None, None
    if not bypass_cache:
        hit = _acl_cache_get(acl_key, now)
        if hit is not None:
            return hit[1], hit[2]
    err = None
    acl = None
    try:
        status, body = minio.get(acl_key)
        if status == 200:
            try:
                acl = json.loads(body)
            except ValueError:
                err = ACL_MALFORMED
            if acl is None and err is None:
                # an object that exists and says `null` is not "no ACL": refuse it like any
                # other unusable ACL (it would otherwise open a pub/ root it was meant to close)
                err = ACL_MALFORMED
        elif status != 404:
            err = f"HTTP {status}"
    except ConnectionError as e:
        err = str(e)
    if not bypass_cache:
        _acl_cache_put(acl_key, (now, acl, err), now)
    return acl, err


# Per-ACL-key locks serialising grant_access inside the process (ThreadingHTTPServer: two owners
# approving two requests for the same artifact at the same time). Writers outside the process
# (a publisher re-publishing the ACL, another gate replica) are covered by the conditional PUT
# (If-Match) in grant_access, not by this lock. The dict grows one entry per artifact root with
# an approved grant — bounded by the number of published artifacts (no eviction by design: a
# lock with waiters must not be dropped).
_grant_locks = {}
_grant_locks_guard = threading.Lock()


def _grant_lock(acl_key):
    with _grant_locks_guard:
        lock = _grant_locks.get(acl_key)
        if lock is None:
            lock = _grant_locks[acl_key] = threading.Lock()
        return lock


def read_acl_for_write(minio, acl_key):
    """(acl, etag, err) of one ACL object, read uncached for a conditional write. err is None
    only when the object exists, is a JSON object and came with an ETag (no ETag: no
    conditional write is possible, so the caller must not write)."""
    try:
        status, body, etag = minio.get_with_etag(acl_key)
    except ConnectionError as e:
        return None, None, str(e)
    if status == 404:
        return None, None, "missing"
    if status != 200:
        return None, None, f"HTTP {status}"
    try:
        acl = json.loads(body)
    except ValueError:
        return None, None, ACL_MALFORMED
    if not isinstance(acl, dict):
        return None, None, "not a JSON object"
    if not etag:
        return None, None, "no ETag"
    return acl, etag, None


# A write that loses the race (412) is redone once on a fresh read; a second loss gives up.
GRANT_ATTEMPTS = 2

# grant_access notes after which the access list may or may not have been updated: the reply to
# the write was lost ("put failed: ...") or was a server error ("put HTTP 5xx": a store may
# fail after applying the write), and one re-read did not show the requester listed; or
# something unexpected was raised inside the grant ("unexpected <Class>", see _handle_action).
# Every other failed grant is known to have changed nothing: it stopped before the write, or
# the store refused the write with a 4xx status (412, 403, ...).
_GRANT_OUTCOME_UNKNOWN = ("put failed:", "unexpected ", "put HTTP 5")


def grant_outcome_unknown(note):
    """True when a failed grant may or may not have updated the access list."""
    return isinstance(note, str) and note.startswith(_GRANT_OUTCOME_UNKNOWN)


def _confirm_unknown_write(minio, acl_key, requester, failure, cause):
    """After an ACL write the store may or may not have applied (its reply was lost, or it was
    a server error; `failure` is the note for it, "put failed: ..." or "put HTTP 5xx"): one
    fresh read. (True, note) when the requester is listed now, so the grant happened (`cause`
    names what made the outcome unknown); else (False, "<failure>; ...") saying what the read
    found, and the outcome stays unknown."""
    acl, _etag, err = read_acl_for_write(minio, acl_key)
    if err is not None:
        return False, f"{failure}; the confirming read failed too: {err}"
    users = acl.get("users")
    if isinstance(users, list) and requester.lower() in [u.lower() for u in users
                                                         if isinstance(u, str)]:
        return True, f"added (confirmed by a re-read after {cause})"
    return False, f"{failure}; not listed on a re-read"


def grant_access(minio, artifact_path, requester):
    """Add `requester` to the ACL users of `artifact_path`. (ok, note).

    Writes only the ACL that governs the path (acl_key_for: the artifact root for u/ and g/,
    whatever the file's depth) and only when it already exists: an approval never creates an
    ACL object, and never writes one under pub/ (refused before any read). The write is a read-modify-write that cannot lose another writer's change:
      - serialised per ACL key inside the process (_grant_lock);
      - conditional against every other writer: the ACL is read with its ETag and written with
        If-Match, so the store refuses it (412) if the object changed in between; then it is
        read again, the requester added again and written once more; a second 412 gives up
        with (False, "put HTTP 412") and leaves the other writer's ACL as it is;
      - everything else in the ACL (owner, groups, expires, unknown fields) is written back as
        read, and the ACL keeps its tags (ttl, which drives its expiry): they are read before
        the write and sent with it; if they cannot be read, nothing is written;
      - a write whose reply is lost, or that the store answers with a 5xx (it may have applied
        it either way), is checked with one fresh read: the requester listed is a grant;
        anything else keeps the failure's note ("put failed: ..." or "put HTTP 5xx") and the
        outcome stays unknown (grant_outcome_unknown)."""
    key = key_from_path(artifact_path)
    if key is None or _bad_key(key):
        # a path the gate would never serve (dot segments, an ACL, gate state, a listing) never
        # gets an ACL written for it, whatever root acl_key_for would derive
        return False, "bad artifact path"
    if key.startswith(PUB_PREFIXES):
        # pub/ takes no access requests: the gate never writes a pub/ ACL (the S3 policy of its
        # user refuses it too), whatever ACL may exist there
        return False, "pub/ takes no access grants"
    acl_key = acl_key_for(key)
    if acl_key is None:
        return False, "no artifact root"
    added = "added"
    with _grant_lock(acl_key):
        for _attempt in range(GRANT_ATTEMPTS):
            acl, etag, err = read_acl_for_write(minio, acl_key)    # write path: never the cache
            if err:
                return False, f"acl unreadable: {err}"
            users = acl.get("users") or []
            if not isinstance(users, list):
                return False, "acl unreadable: users is not a list"
            if requester.lower() in [u.lower() for u in users if isinstance(u, str)]:
                return True, "already listed"
            tags, terr = minio.get_tags_checked(acl_key)
            if terr:
                return False, f"acl tags unreadable: {terr}"
            acl["users"] = users + [requester]
            try:
                status = minio.put(acl_key, json.dumps(acl, indent=2).encode(), "application/json",
                                   if_match=etag,
                                   tagging=urllib.parse.urlencode(sorted(tags.items())) or None)
            except ConnectionError as e:
                ok, note = _confirm_unknown_write(minio, acl_key, requester, f"put failed: {e}",
                                                  "a lost reply")
                if not ok:
                    return False, note
                status, added = 200, note
                break
            if 500 <= status <= 599:
                # a server error: the store may have applied the write before failing
                ok, note = _confirm_unknown_write(minio, acl_key, requester, f"put HTTP {status}",
                                                  f"HTTP {status}")
                if not ok:
                    return False, note
                status, added = 200, note
                break
            if status != 412:
                break
        if status not in (200, 204):
            return False, f"put HTTP {status}"
    with _acl_lock:
        _acl_cache.pop(acl_key, None)
    return True, added


# --------------------------------------------------------------------------------------------
MINIO = MinioClient(MINIO_ENDPOINT, MINIO_ACCESS_KEY, MINIO_SECRET_KEY, BUCKET)
STATE = MinioStateStore(MINIO)
RATE_LIMITER = RateLimiter(STATE)
REQUESTER_LIMITER = RateLimiter(STATE, REQUESTER_RATE_LIMIT_MAX, RATE_LIMIT_WINDOW, per_requester=True)
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
             "requester_rate=%d/%ds owner_pending=%d token_ttl=%ds slack=%s anonymous_pub=%s "
             "plugin_prefix=%s",
             PUBLIC_HOST, BUCKET, OAUTH2_AUTH_URL, PUB_PREFIXES,
             RATE_LIMIT_MAX, RATE_LIMIT_WINDOW, REQUESTER_RATE_LIMIT_MAX, RATE_LIMIT_WINDOW,
             OWNER_PENDING_MAX, TOKEN_TTL, bool(SLACK_BOT_TOKEN),
             ANONYMOUS_PUB_ENABLED, PLUGIN_PREFIX)
    # Two listeners (see module docstring): the decision endpoint lives ONLY on the auth one.
    public_server, auth_server = _build_servers()
    threading.Thread(target=auth_server.serve_forever, daemon=True).start()
    LOG.info("listening: public=%d (request-access) forwardAuth=%d (decision endpoint)",
             LISTEN_PORT, AUTH_LISTEN_PORT)
    public_server.serve_forever()


if __name__ == "__main__":
    main()
