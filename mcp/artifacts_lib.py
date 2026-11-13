"""artifacts_lib.py — stdlib-only S3/MinIO client + key helpers for the artifacts MCP.

Deliberately dependency-free (no boto3/minio): the MCP server runs on laptops and
containers where installing an SDK is friction. SigV4 signing is implemented here with
hmac/hashlib only. Configuration is environment-driven; nothing here hardcodes a host.

Env:
  ARTIFACTS_ENDPOINT     S3 endpoint, e.g. https://artifacts-write.example.com
                         or http://127.0.0.1:9000 (default https://artifacts-write.example.com)
  ARTIFACTS_BUCKET       bucket name (default "artifacts")
  ARTIFACTS_REGION       signing region (default "us-east-1")
  ARTIFACTS_ACCESS_KEY / ARTIFACTS_SECRET_KEY   publisher credentials (required)
  ARTIFACTS_READ_BASE    base of the read (gate) host in delivered links
                         (default https://artifacts.example.com)
  ARTIFACTS_PLUGINS      enabled plugins "name=/prefix/;name2=/prefix2/" (docs/plugins.md §8.5)
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import os
import re
import urllib.request
import urllib.parse
import uuid
import xml.etree.ElementTree as ET

MAX_BYTES = 10 * 1024 * 1024
MAX_TTL_DAYS = 3650
# Object keys: one safe charset per segment (letters, digits, _ . = - and / separators).
_SAFE_PART = re.compile(r"[^A-Za-z0-9_.=-]+")
# Prefixes the publisher must never touch: gate state and plugin storage.
FORBIDDEN_PREFIXES = ("_gate/", "_plugins/")


def env(name: str, default: str = "") -> str:
    return os.environ.get(name) or default


def safe_object_name(name: str) -> str:
    """Safe S3 object name: no paths, useful ASCII, no '..'."""
    clean = os.path.basename(str(name))
    clean = _SAFE_PART.sub("_", clean).strip("._-")
    return clean or "artifact"


def validate_key(key: str) -> str:
    """Reject traversal and forbidden prefixes; return the cleaned key."""
    clean = str(key).strip().lstrip("/")
    if clean.startswith(f"{env('ARTIFACTS_BUCKET', 'artifacts')}/"):
        clean = clean[len(clean.split('/', 1)[0]) + 1:]
    if not clean or ".." in clean or "\\" in clean or "//" in clean:
        raise ValueError("invalid artifact key")
    for seg in clean.split("/"):
        if seg in (".", ".."):
            raise ValueError("invalid artifact key")
    for pref in FORBIDDEN_PREFIXES:
        if clean == pref.rstrip("/") or clean.startswith(pref):
            raise ValueError(f"key under {pref} is not manageable here")
    if clean.endswith(".acl.json"):
        raise ValueError("ACL files are managed by the publisher, not deleted directly")
    return clean


def key_for_html(title: str, public: bool, when: datetime.datetime | None = None) -> str:
    """pub/ = anonymous while the host is not publicly exposed; else a gated key."""
    when = when or datetime.datetime.now(datetime.timezone.utc)
    stamp = when.strftime("%Y%m%d")
    stem = safe_object_name(title)[:60] or "artifact"
    if public:
        return f"pub/{stem}-{uuid.uuid4().hex[:8]}.html"
    # Gated artifacts get a directory of their own: the gate ACL lives in the
    # object's directory, so a shared date directory would let one publish
    # overwrite another's ACL.
    return f"u/{stem}-{uuid.uuid4().hex[:8]}/index.html"


def plugin_links(read_base: str, key: str) -> list[dict]:
    """One link per enabled plugin (docs/plugins.md §8.5).

    Like every delivered link, the URL carries the bucket as its first path
    segment (MinIO path-style), with the plugin prefix in front of it — same
    shape the CLI prints: <read_base>/_<plugin>/<bucket>/<key>.
    """
    read_base = read_base.rstrip("/")
    bucket = env("ARTIFACTS_BUCKET", "artifacts")
    out = []
    for pair in env("ARTIFACTS_PLUGINS").split(";"):
        pair = pair.strip()
        if not pair or "=" not in pair:
            continue
        name, prefix = pair.split("=", 1)
        if not (prefix.startswith("/") and prefix.endswith("/")):
            continue
        out.append({"name": name.strip(), "url": f"{read_base}{prefix}{bucket}/{key}"})
    return out


def acl_for(owner: str, users: list[str], groups: list[str], ttl_days: int) -> str:
    """Gate ACL JSON (gate/gate.py decide() format), expiring with the objects."""
    import json
    expires = (datetime.date.today() + datetime.timedelta(days=ttl_days)).isoformat()
    return json.dumps({
        "owner": (owner or "").lower(),
        "users": sorted({u.lower() for u in users if u}),
        "groups": sorted({g for g in groups if g}),
        "expires": expires,
    })


class S3Client:
    """Minimal SigV4 client: put/get/head/delete/list + put ACL. stdlib only."""

    def __init__(self, endpoint: str | None = None, access_key: str | None = None,
                 secret_key: str | None = None, bucket: str | None = None,
                 region: str | None = None):
        self.endpoint = (endpoint or env("ARTIFACTS_ENDPOINT",
                                         "https://artifacts-write.example.com")).rstrip("/")
        self.scheme, _, self.hostport = self.endpoint.partition("://")
        self.access_key = access_key if access_key is not None else env("ARTIFACTS_ACCESS_KEY")
        self.secret_key = secret_key if secret_key is not None else env("ARTIFACTS_SECRET_KEY")
        self.bucket = bucket or env("ARTIFACTS_BUCKET", "artifacts")
        self.region = region or env("ARTIFACTS_REGION", "us-east-1")
        if not (self.access_key and self.secret_key):
            raise RuntimeError("ARTIFACTS_ACCESS_KEY / ARTIFACTS_SECRET_KEY are required")

    # ---- signing -----------------------------------------------------------------------
    @staticmethod
    def _sha(b: bytes) -> str:
        return hashlib.sha256(b).hexdigest()

    @staticmethod
    def _hmac(key: bytes, msg: bytes) -> bytes:
        return hmac.new(key, msg, hashlib.sha256).digest()

    def _signed_request(self, method: str, key: str, data: bytes = b"",
                       extra_headers: dict[str, str] | None = None, query: str = ""):
        amzdate = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        datestamp = amzdate[:8]
        uri = "/" + urllib.parse.quote(f"{self.bucket}/{key}", safe="/") if key \
            else "/" + urllib.parse.quote(self.bucket, safe="/")
        payload_hash = self._sha(data)
        headers = {
            "host": self.hostport,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amzdate,
        }
        headers.update({k.lower(): v for k, v in (extra_headers or {}).items()})
        signed = sorted(headers)
        canonical_headers = "".join(f"{h}:{headers[h].strip()}\n" for h in signed)
        signed_headers = ";".join(signed)
        canonical_uri = uri if not query else uri  # query is signed below
        canonical_query = query
        canonical = "\n".join([method, canonical_uri, canonical_query,
                               canonical_headers, signed_headers, payload_hash])
        scope = f"{datestamp}/{self.region}/s3/aws4_request"
        string_to_sign = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope, self._sha(canonical.encode())])
        k = self._hmac(f"AWS4{self.secret_key}".encode(), datestamp.encode())
        k = self._hmac(k, self.region.encode())
        k = self._hmac(k, b"s3")
        k = self._hmac(k, b"aws4_request")
        signature = hmac.new(k, string_to_sign.encode(), hashlib.sha256).hexdigest()
        headers["Authorization"] = (
            f"AWS4-HMAC-SHA256 Credential={self.access_key}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}")
        url = f"{self.scheme}://{self.hostport}{uri}"
        if query:
            url += "?" + query
        return urllib.request.Request(url, data=data if data or method in ("PUT", "POST") else None,
                                      headers=headers, method=method)

    def _call(self, method: str, key: str, data: bytes = b"",
              extra_headers: dict[str, str] | None = None, query: str = ""):
        req = self._signed_request(method, key, data, extra_headers, query)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read(), dict(resp.headers)

    # ---- operations --------------------------------------------------------------------
    def put(self, key: str, data: bytes, content_type: str, ttl_days: int,
            metadata: dict[str, str] | None = None) -> None:
        headers = {"content-type": content_type, "x-amz-tagging": f"ttl={ttl_days}",
                   "cache-control": "no-cache"}
        for k, v in (metadata or {}).items():
            headers[f"x-amz-meta-{k}"] = v
        self._call("PUT", key, data, headers)

    def put_acl(self, dir_key: str, acl_json: str) -> None:
        """Write <dir>/.acl.json: the gate's ACL for the artifact rooted at dir_key (u/<run>,
        g/<slug>/<run>), which governs every file under it at any depth."""
        self._call("PUT", f"{dir_key}/.acl.json", acl_json.encode(),
                   {"content-type": "application/json", "cache-control": "no-cache"})

    def head(self, key: str) -> int:
        try:
            status, _, _ = self._call("HEAD", key)
            return status
        except urllib.error.HTTPError as e:  # noqa: PERF203
            return e.code

    def get(self, key: str) -> bytes:
        return self._call("GET", key)[1]

    def delete(self, key: str) -> int:
        return self._call("DELETE", key)[0]

    def list(self, prefix: str = "", max_keys: int = 100) -> list[dict]:
        q = urllib.parse.urlencode({"list-type": "2", "prefix": prefix, "max-keys": str(max_keys)})
        _, body, _ = self._call("GET", "", query=q)
        ns = "{http://s3.amazonaws.com/doc/2006-03-01/}"
        root = ET.fromstring(body)
        out = []
        for c in root.iter(f"{ns}Contents"):
            out.append({
                "key": (c.findtext(f"{ns}Key") or ""),
                "size": int(c.findtext(f"{ns}Size") or 0),
                "last_modified": c.findtext(f"{ns}LastModified") or "",
            })
        return out
