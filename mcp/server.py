#!/usr/bin/env python3
"""artifacts MCP server — publish/list/delete artifacts from an agent session.

stdio MCP server (mcp SDK). Config is environment-driven (see artifacts_lib.py); no
hostnames or credentials are hardcoded. Every publish prints the artifact link plus one
link per enabled plugin (docs/plugins.md §8.5).

Run: python3 server.py   (expose to a client with the `mcp` SDK / claude_desktop_config)
"""
from __future__ import annotations

import datetime
import os
import sys

from mcp.server.fastmcp import FastMCP

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from artifacts_lib import (  # noqa: E402
    MAX_BYTES, MAX_TTL_DAYS, S3Client, acl_for, env, key_for_html,
    plugin_links, safe_object_name, validate_key,
)

mcp = FastMCP("artifacts")


def _client() -> S3Client:
    return S3Client()


def _read_base() -> str:
    return env("ARTIFACTS_READ_BASE", "https://artifacts.example.com").rstrip("/")


def _check_ttl(days: int) -> int:
    days = int(days)
    if not 1 <= days <= MAX_TTL_DAYS:
        raise ValueError(f"ttl_days must be between 1 and {MAX_TTL_DAYS}")
    return days


def _stamp_metadata() -> dict[str, str]:
    return {
        "publisher": safe_object_name(env("ARTIFACTS_PUBLISHER", os.environ.get("USER", "unknown"))),
        "published-at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    }


def _publish(data: bytes, key: str, content_type: str, ttl: int,
             public: bool, users: list[str] | None, groups: list[str] | None,
             owner: str | None) -> dict:
    if not data.strip():
        raise ValueError("empty content")
    if len(data) > MAX_BYTES:
        raise ValueError(f"{len(data)} bytes; maximum {MAX_BYTES}")
    ttl = _check_ttl(ttl)
    if public and (users or groups):
        raise ValueError("public artifacts live under pub/ and take no ACL; drop users/groups")
    c = _client()
    if not public:
        # ACL first: a gated object without its ACL is a 403 for everyone in the gap.
        c.put_acl(key.rsplit("/", 1)[0] if "/" in key else "",
                  acl_for(owner or env("ARTIFACTS_OWNER", ""), users or [], groups or [], ttl))
    c.put(key, data, content_type, ttl, _stamp_metadata())
    read_base = _read_base()
    bucket = env("ARTIFACTS_BUCKET", "artifacts")
    return {
        "url": f"{read_base}/{bucket}/{key}",
        "key": key,
        "public": public,
        "ttl_days": ttl,
        "expires_on": (datetime.date.today() + datetime.timedelta(days=ttl)).isoformat(),
        "size_bytes": len(data),
        "plugins": plugin_links(read_base, key),
    }


@mcp.tool()
def publish_html(html: str, title: str, ttl_days: int = 7, public: bool = False,
                 users: str = "", groups: str = "") -> dict:
    """Publish an HTML page as an artifact.

    public=True puts it under pub/ (anonymous read while the host is not publicly
    exposed). Otherwise an ACL is written first: `users` (comma-separated emails/UPNs)
    and `groups` (comma-separated group ids) may open it; `owner` (env
    ARTIFACTS_OWNER) is notified on access requests. Returns the artifact link plus one
    link per enabled plugin.
    """
    key = key_for_html(title, public)
    return _publish(html.encode("utf-8"), key, "text/html; charset=utf-8", ttl_days,
                    public, [u for u in users.split(",") if u.strip()],
                    [g for g in groups.split(",") if g.strip()], None)


@mcp.tool()
def publish_file(path: str, ttl_days: int = 7, public: bool = False,
                 users: str = "", groups: str = "") -> dict:
    """Publish a local file as an artifact (same ACL rules as publish_html).

    The served name is the sanitized basename plus a short uuid so two publishes of the
    same file never overwrite each other.
    """
    import mimetypes
    with open(path, "rb") as fh:
        data = fh.read()
    base = safe_object_name(os.path.basename(path))
    ext = os.path.splitext(base)[1]
    stem = os.path.splitext(base)[0]
    import uuid
    served = f"{stem}-{uuid.uuid4().hex[:8]}{ext}" if ext else f"{base}-{uuid.uuid4().hex[:8]}"
    ct = mimetypes.guess_type(base)[0] or "application/octet-stream"
    if public:
        key = f"pub/{served}"
    else:
        # own directory per publish — the gate ACL lives in the object's directory
        key = f"u/{os.path.splitext(served)[0]}/{served}"
    return _publish(data, key, ct, ttl_days, public,
                    [u for u in users.split(",") if u.strip()],
                    [g for g in groups.split(",") if g.strip()], None)


@mcp.tool()
def list_artifacts(prefix: str = "", max_keys: int = 100) -> list[dict]:
    """List objects in the artifacts bucket (key, size, last_modified).

    Gate state (_gate/) and plugin storage (_plugins/) are listed only if you ask for
    those prefixes explicitly; they are not deletable from here.
    """
    return _client().list(prefix=prefix, max_keys=int(max_keys))


@mcp.tool()
def delete_artifact(key: str) -> dict:
    """Delete one artifact by key. Refuses _gate/, _plugins/ prefixes and .acl.json keys."""
    clean = validate_key(key)
    status = _client().delete(clean)
    return {"key": clean, "deleted": status in (200, 204), "http_status": status}


if __name__ == "__main__":
    mcp.run()
