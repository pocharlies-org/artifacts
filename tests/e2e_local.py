#!/usr/bin/env python3
"""End-to-end test of the gate HTTP layer against a fake MinIO and a fake oauth2-proxy, with no
cluster ( Covers: forwardAuth allow/deny/404/405, CSRF-bound request-access, rate limit,
GET-never-mutates approval, owner-only approval, single-use token, ACL grant on approve, and the
two-listener split : the gate runs with a PUBLIC listener (request-access)
and an AUTH listener (forwardAuth decision), so the tests run two gate servers and hit each
endpoint on its own listener.

Run:  python3 -I -m unittest discover -s tests -p 'e2e_*.py' -v
"""

import importlib.util
import base64
import hashlib
import io
import json
import logging
import os
import re
import socket
import threading
import time
import tracemalloc
import unittest
from unittest import mock
import urllib.error
import urllib.parse
import urllib.request
from http import client as http_client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ------------------------------------------------------------------ fake MinIO (path style) ----
# S3 write semantics the gate relies on: every object version has an ETag (sent on GET and
# HEAD), a PUT with If-Match answers 412 unless the object is still that version, and a PUT
# replaces the object's tag set (x-amz-tagging; none sent: untagged).
OBJECTS = {}
TAGS = {}          # key -> {tag: value}, served on GET <key>?tagging (ILM ttl)
OBJECTS_LOCK = threading.Lock()
LAST_MODIFIED = "Wed, 21 Oct 2026 07:28:00 GMT"
# key -> [callable, ...]: each GET of that key pops one and runs it after the answer's version
# is taken and before it is sent, i.e. another writer changes the object between that read
# and the reader's next request.
AFTER_GET = {}
PUTS = []          # (key, If-Match, x-amz-tagging, status) of every PUT
# (method, key) -> n: the next n answers to that request are cut short (Content-Length promises
# more than is sent, then the connection closes: the client gets http.client.IncompleteRead).
# method is "GET", "GET?tagging" or "PUT"; a cut PUT is still applied, as a store may do.
TRUNCATE = {}
# (method, key) -> [action, ...]: each such request pops the next action, before TRUNCATE is
# looked at. "ok" answers normally; "drop" closes the connection without any answer (a PUT is
# then NOT applied: the client cannot tell it from a reply lost after the write); "cut" is
# TRUNCATE's cut reply (a PUT is applied). method is "GET" or "PUT".
PLAN = {}


def etag_of(body):
    return '"%s"' % hashlib.md5(body).hexdigest()


class MinioHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _key(self):
        path = urllib.parse.urlsplit(self.path).path
        return urllib.parse.unquote(path[len("/artifacts/"):])

    def _plan(self, method, key):
        with OBJECTS_LOCK:
            steps = PLAN.get((method, key))
            return steps.pop(0) if steps else "ok"

    def _drop(self):
        self.close_connection = True          # no status line at all: RemoteDisconnected

    def _cut(self, method, key):
        with OBJECTS_LOCK:
            n = TRUNCATE.get((method, key), 0)
            if n:
                TRUNCATE[(method, key)] = n - 1
        return bool(n)

    def _reply_cut(self, status, body, headers=None):
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body) + 16))
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_GET(self):
        if "tagging" in urllib.parse.urlsplit(self.path).query:
            key = self._key()
            with OBJECTS_LOCK:
                tags = TAGS.get(key)
                exists = key in OBJECTS
            if not exists:
                return self._reply(404, b"NoSuchKey")
            xml = ("<Tagging><TagSet>"
                   + "".join(f"<Tag><Key>{k}</Key><Value>{v}</Value></Tag>"
                             for k, v in (tags or {}).items())
                   + "</TagSet></Tagging>")
            if self._cut("GET?tagging", key):
                return self._reply_cut(200, xml.encode())
            return self._reply(200, xml.encode())
        key = self._key()
        step = self._plan("GET", key)
        if step == "drop":
            return self._drop()
        with OBJECTS_LOCK:
            body = OBJECTS.get(key)
            hooks = AFTER_GET.get(key)
            hook = hooks.pop(0) if hooks else None
        if hook is not None:
            hook()
        if body is None:
            return self._reply(404, b"NoSuchKey")
        if step == "cut" or self._cut("GET", key):
            return self._reply_cut(200, body, {"ETag": etag_of(body)})
        self._reply(200, body, {"ETag": etag_of(body)})

    def do_HEAD(self):
        with OBJECTS_LOCK:
            body = OBJECTS.get(self._key())
        self.send_response(200 if body is not None else 404)
        if body is not None:
            self.send_header("Last-Modified", LAST_MODIFIED)
            self.send_header("ETag", etag_of(body))
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_PUT(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n)
        key = self._key()
        step = self._plan("PUT", key)
        if step == "drop":
            return self._drop()
        if_match, tagging = self.headers.get("If-Match"), self.headers.get("x-amz-tagging")
        with OBJECTS_LOCK:
            current = OBJECTS.get(key)
            if if_match is not None and (current is None or etag_of(current) != if_match):
                status = 412
            else:
                status = 200
                OBJECTS[key] = body
                if tagging:
                    TAGS[key] = dict(urllib.parse.parse_qsl(tagging))
                else:
                    TAGS.pop(key, None)
            PUTS.append((key, if_match, tagging, status))
        if step == "cut" or self._cut("PUT", key):
            return self._reply_cut(status, b"")
        self._reply(status, b"" if status == 200 else b"PreconditionFailed")

    def _reply(self, status, body, headers=None):
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# ------------------------------------------------------------- fake oauth2-proxy /auth ---------
# (email, groups[, send_email_header]) — send_email defaults True; False makes the fake proxy
# answer 202 with ONLY X-Auth-Request-Preferred-Username, the misconfiguration the gate must fail
# closed on (identity comes from X-Auth-Request-Email ONLY).
# Display names: the real proxy (--set-authorization-header) returns the session's id_token in
# the Authorization header of its 202; the gate reads only its `name` claim, for display.
NAMES = {"alice": "Alice Example", "bob": "Bob Example"}


def _fake_id_token(email, name):
    b = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
    return f"{b({'alg': 'none'})}.{b({'email': email, 'name': name})}.sig"


USERS = {"alice": ("alice@example.com", ""),            # no groups claim (overage-ish)
         "bob": ("bob@example.com", "11111111-2222-4333-8444-555555555555"),
         "owner": ("owner@example.com", ""),
         "prefonly": ("prefonly@example.com", "", False)}


class ProxyHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if not self.path.startswith("/oauth2-artifacts/auth"):
            self.send_error(404)
            return
        sid = dict(p.split("=", 1) for p in (self.headers.get("Cookie") or "").split("; ") if "=" in p)
        name = sid.get("sid", "")
        bearer = self.headers.get("Authorization") or ""
        if not name and bearer.startswith("Bearer "):
            name = bearer[len("Bearer "):]   # scripted checks present an id_token, no cookie
        u = USERS.get(name)
        if not u:
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(202)
        if len(u) > 2 and not u[2]:
            self.send_header("X-Auth-Request-Preferred-Username", u[0])
        else:
            self.send_header("X-Auth-Request-Email", u[0])
        if u[1]:
            self.send_header("X-Auth-Request-Groups", u[1])
        if name in NAMES:
            self.send_header("Authorization", f"Bearer {_fake_id_token(u[0], NAMES[name])}")
        self.send_header("Content-Length", "0")
        self.end_headers()


def serve(handler, mode=None):
    s = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    if mode is not None:
        s.gate_mode = mode   # "public" | "auth" — mirrors gate.main()
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


def http(url, method="GET", data=None, headers=None, cookie=None):
    body = data.encode() if isinstance(data, str) else data
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)


class E2ETest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.minio = serve(MinioHandler)
        cls.proxy = serve(ProxyHandler)
        mport = cls.minio.server_address[1]
        pport = cls.proxy.server_address[1]
        # env BEFORE importing the gate module (it reads config at import time)
        os.environ.update({
            "MINIO_ENDPOINT": f"http://127.0.0.1:{mport}",
            "MINIO_ACCESS_KEY": "gate", "MINIO_SECRET_KEY": "gate-secret",
            "GATE_READ_ACCESS_KEY": "reader", "GATE_READ_SECRET_KEY": "reader-secret",
            "OAUTH2_AUTH_URL": f"http://127.0.0.1:{pport}/oauth2-artifacts/auth",
            "HMAC_KEY_B64": "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s=",  # 32 bytes, test-only fixture key
            "SLACK_BOT_TOKEN": "",  # -> LogNotifier (no external calls)
            "PUBLIC_HOST": "artifacts.test.invalid",
            "GATE_RATE_LIMIT_MAX": "2", "GATE_RATE_LIMIT_WINDOW_SECONDS": "3600",
        })
        spec = importlib.util.spec_from_file_location("gate_e2e", os.path.join(ROOT, "gate", "gate.py"))
        cls.gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.gate)
        cls.gate._acl_cache.clear()
        # Two listeners, like gate.main(): public = request-access surface (the port the public
        # IngressRoute points at), auth = forwardAuth decision endpoint only (Warning 2).
        cls.gate_public = serve(cls.gate.GateHandler, "public")
        cls.base = f"http://127.0.0.1:{cls.gate_public.server_address[1]}"
        cls.gate_auth = serve(cls.gate.GateHandler, "auth")
        cls.auth_base = f"http://127.0.0.1:{cls.gate_auth.server_address[1]}"

    def setUp(self):
        global OBJECTS
        with OBJECTS_LOCK:
            OBJECTS.clear()
            TAGS.clear()
            AFTER_GET.clear()
            PUTS.clear()
            TRUNCATE.clear()
            PLAN.clear()
        self.gate._acl_cache.clear()
        # pub artifact without ACL; private artifact with ACL (owner + bob's group); ACL for it
        OBJECTS["pub/free/index.html"] = b"<h1>free</h1>"
        OBJECTS["u/secret/report.html"] = b"<h1>secret</h1>"
        OBJECTS["u/secret/.acl.json"] = json.dumps({
            "owner": "owner@example.com", "users": ["alice@example.com"],
            "groups": ["11111111-2222-4333-8444-555555555555"], "expires": None}).encode()

    # -- forwardAuth ---------------------------------------------------------------
    def auth(self, uri, sid, method="GET"):
        # traefik's forwardAuth targets the DECISION listener (auth_base), never the public one.
        return http(self.auth_base + "/_gate/auth",
                    headers={"X-Forwarded-Method": method, "X-Forwarded-Uri": uri},
                    cookie=f"sid={sid}" if sid else None)

    def test_pub_no_acl_any_signed_in(self):
        st, _, _ = self.auth("/artifacts/pub/free/index.html", "alice")
        self.assertEqual(st, 200)

    def test_allowed_but_missing_object_gets_deny_page_not_minio_404(self):
        # Regression (found live): decide() allows pub/ objects without an ACL BEFORE
        # checking existence, so a nonexistent pub/ object passed forwardAuth and the client saw
        # MinIO's NoSuchKey XML — an existence leak. On allow the gate must HEAD the object and
        # answer the deny page when it is not there (same page as "not allowed").
        for uri in ("/artifacts/pub/free/does-not-exist.html",        # pub, no ACL, allowed-first
                    "/artifacts/u/secret/does-not-exist.html"):     # ACL allows alice, object absent
            st, body, _ = self.auth(uri, "alice")
            self.assertEqual(st, 403, uri)
            self.assertIn("Access required", body, uri)

    def _auth_h(self, uri, sid, host="artifacts.test.invalid", method="GET"):
        return http(self.auth_base + "/_gate/auth",
                    headers={"X-Forwarded-Method": method, "X-Forwarded-Uri": uri,
                             "X-Forwarded-Host": host},
                    cookie=f"sid={sid}" if sid else None)

    def test_allow_signs_the_upstream_read(self):
        # MinIO has no anonymous read outside pub/: on ALLOW the gate returns SigV4 headers the
        # proxy copies onto the upstream request. They must bind method, Host and path.
        uri = "/artifacts/u/secret/report.html"
        for method in ("GET", "HEAD"):
            st, _, h = self._auth_h(uri, "alice", host="reports.example.org", method=method)
            self.assertEqual(st, 200)
            auth = h.get("Authorization", "")
            # finding 4: the dedicated read-signing user, never the gate (ACL/state) user
            self.assertTrue(auth.startswith("AWS4-HMAC-SHA256 Credential=reader/"), auth)
            self.assertNotIn("Credential=gate/", auth)
            self.assertIn("SignedHeaders=host;x-amz-content-sha256;x-amz-date", auth)
            want = self.gate.sigv4_headers(method, "reports.example.org", uri, [], None, b"",
                                           "reader", "reader-secret", amzdate=h["X-Amz-Date"])
            self.assertEqual(auth, want["Authorization"])
            self.assertEqual(h["X-Amz-Content-Sha256"], want["x-amz-content-sha256"])

    def test_deny_and_401_carry_no_signature(self):
        USERS["carol3"] = ("carol3@example.com", "aaaa")
        for sid, code in (("carol3", 403), (None, 401)):
            st, _, h = self._auth_h("/artifacts/u/secret/report.html", sid)
            self.assertEqual(st, code)
            self.assertNotIn("Authorization", h)
            self.assertNotIn("X-Amz-Date", h)

    def test_s3_subresource_or_override_query_refused(self):
        for q in ("response-content-type=text/html", "Response-Content-Disposition=x",
                  "tagging", "versionId=abc", "X-Amz-Expires=60"):
            st, _, h = self._auth_h("/artifacts/u/secret/report.html?" + q, "alice")
            self.assertEqual(st, 404, q)
            self.assertNotIn("Authorization", h, q)

    def test_query_allow_list_every_query_refused(self):
        # finding 1: ?lambdaArn= used to reach MinIO's GetObjectLambdaHandler signed by the
        # gate. The allow-list is empty: every query form answers the same 404, unsigned, for an
        # allowed reader (alice) on GET and HEAD.
        for q in ("lambdaArn=arn:minio:s3-object-lambda::x:webhook", "acl", "ACL", "%61cl",
                  "acl%00", "%20acl", "acl&acl", "v=1&v=2", "acl;x=1", ";", "", "v=2&tab="):
            for method in ("GET", "HEAD"):
                st, _, h = self._auth_h("/artifacts/u/secret/report.html?" + q, "alice",
                                        method=method)
                self.assertEqual(st, 404, (q, method))
                self.assertNotIn("Authorization", h, q)
                self.assertNotIn("X-Amz-Date", h, q)
        # the same read without a query is still allowed and signed
        st, _, h = self._auth_h("/artifacts/u/secret/report.html", "alice")
        self.assertEqual(st, 200)
        self.assertIn("Authorization", h)

    def test_client_s3_headers_refused_before_signing(self):
        # finding 5: x-amz-*/x-minio-* from the visitor are refused (400) before identity or
        # signing, for allowed readers too, and nothing is signed.
        for hdr, val in (("X-Amz-Server-Side-Encryption-Customer-Algorithm", "AES256"),
                         ("X-Amz-Checksum-Mode", "ENABLED"), ("x-amz-date", "20260101T000000Z"),
                         ("X-Minio-Extract", "true"), ("X-MINIO-Source-Proxy-Request", "true")):
            st, body, h = http(self.auth_base + "/_gate/auth",
                               headers={"X-Forwarded-Method": "GET",
                                        "X-Forwarded-Uri": "/artifacts/u/secret/report.html",
                                        hdr: val},
                               cookie="sid=alice")
            self.assertEqual(st, 400, hdr)
            self.assertNotIn("Authorization", h, hdr)
            self.assertNotIn("X-Amz-Date", h, hdr)
        # anonymous with the header: refused the same way (before the identity call)
        st, _, _ = http(self.auth_base + "/_gate/auth",
                        headers={"X-Forwarded-Method": "GET",
                                 "X-Forwarded-Uri": "/artifacts/u/secret/report.html",
                                 "X-Amz-Checksum-Mode": "ENABLED"})
        self.assertEqual(st, 400)

    def test_anonymous_gets_401(self):
        st, _, _ = self.auth("/artifacts/pub/free/index.html", None)
        self.assertEqual(st, 401)

    def test_private_acl_user_allowed(self):
        st, _, _ = self.auth("/artifacts/u/secret/report.html", "alice")
        self.assertEqual(st, 200)

    def test_private_acl_group_member_allowed(self):
        st, _, _ = self.auth("/artifacts/u/secret/report.html", "bob")
        self.assertEqual(st, 200)

    def test_private_acl_non_member_denied_with_page(self):
        # owner user has no groups claim -> group-only ACL denies (overage rule), but owner is
        # listed? owner@ is not in users; use a user not in the ACL at all:
        USERS["carol"] = ("carol@example.com", "aaaa")
        st, body, _ = self.auth("/artifacts/u/secret/report.html", "carol")
        self.assertEqual(st, 403)
        self.assertIn("Request access", body)
        self.assertIn("u/secret/report.html", body)

    def test_missing_artifact_same_403_page_as_denied(self):
        USERS["carol2"] = ("carol2@example.com", "aaaa")
        st1, b1, _ = self.auth("/artifacts/u/secret/report.html", "carol2")
        st2, b2, _ = self.auth("/artifacts/u/secret/does-not-exist.html", "carol2")
        self.assertEqual((st1, st2), (403, 403))
        # identical shape: both pages only echo the path the visitor asked for (no new info) and
        # both offer Request access; nothing distinguishes "missing" from "not allowed".
        self.assertIn("Request access", b2)
        self.assertIn("does-not-exist", b2)  # the requested path itself is shown (not a leak)

    def test_acl_file_never_served(self):
        st, _, _ = self.auth("/artifacts/u/secret/.acl.json", "alice")
        self.assertEqual(st, 404)

    def test_state_prefix_never_served(self):
        st, _, _ = self.auth("/artifacts/_gate/req/deadbeef.json", "alice")
        self.assertEqual(st, 404)

    def test_dir_listing_path_404(self):
        st, _, _ = self.auth("/artifacts/pub/free/", "alice")
        self.assertEqual(st, 404)

    def test_non_get_head_405(self):
        st, _, _ = self.auth("/artifacts/pub/free/index.html", "alice", method="DELETE")
        self.assertEqual(st, 405)

    def test_direct_write_on_artifacts_path_405(self):
        st, _, _ = http(self.base + "/artifacts/pub/free/index.html", method="PUT", data=b"x",
                        cookie="sid=alice")
        self.assertEqual(st, 405)

    def test_spoofed_x_auth_request_headers_ignored(self):
        # client sends its own X-Auth-Request-Email; gate must ask oauth2-proxy (no cookie -> 401)
        st, _, _ = http(self.auth_base + "/_gate/auth",
                        headers={"X-Forwarded-Method": "GET",
                                 "X-Forwarded-Uri": "/artifacts/u/secret/report.html",
                                 "X-Auth-Request-Email": "alice@example.com"})
        self.assertEqual(st, 401)

    # -- listener split  ------------------------------------
    def test_auth_endpoint_not_served_on_public_listener(self):
        # The public route (8080) can never drive the decision: even a well-formed forwardAuth
        # request with a valid session 404s on the public listener, so a misrouted IngressRoute
        # cannot reach /_gate/auth through the public surface.
        st, _, _ = http(self.base + "/_gate/auth",
                        headers={"X-Forwarded-Method": "GET",
                                 "X-Forwarded-Uri": "/artifacts/u/secret/report.html"},
                        cookie="sid=alice")
        self.assertEqual(st, 404)

    def test_public_endpoints_not_served_on_auth_listener(self):
        # The decision listener serves ONLY /_gate/auth: the public request-access surface
        # (request/approve/deny) is not reachable there.
        st, _, _ = http(self.auth_base + "/_gate/request", method="POST",
                       data=urllib.parse.urlencode({"csrf": "x", "artifact": "/artifacts/a"}),
                       headers={"Content-Type": "application/x-www-form-urlencoded"},
                       cookie="sid=alice")
        self.assertEqual(st, 404)
        st, _, _ = http(self.auth_base + "/_gate/approve?token=whatever", cookie="sid=owner")
        self.assertEqual(st, 404)
        st, _, _ = http(self.auth_base + "/_gate/deny", method="POST",
                       data=urllib.parse.urlencode({"token": "whatever"}),
                       headers={"Content-Type": "application/x-www-form-urlencoded"},
                       cookie="sid=owner")
        self.assertEqual(st, 404)

    def test_proxy_202_without_email_fails_closed(self):
        # Warning 1: a 202 carrying only X-Auth-Request-Preferred-Username is NOT an identity —
        # the gate fails closed with 500, it never logs the visitor in.
        st, _, _ = self.auth("/artifacts/pub/free/index.html", "prefonly")
        self.assertEqual(st, 500)

    # -- request access + approval flow --------------------------------------------
    def test_full_request_approve_flow(self):
        USERS["dave"] = ("dave@example.com", "aaaa")
        # 1) dave hits the deny page and extracts the CSRF token
        st, page, _ = self.auth("/artifacts/u/secret/report.html", "dave")
        self.assertEqual(st, 403)
        csrf = re.search(r'name=csrf value="([^"]+)"', page).group(1)
        # 2) dave requests access
        st, page, _ = http(self.base + "/_gate/request", method="POST",
                           data=urllib.parse.urlencode({"csrf": csrf,
                                                        "artifact": "/artifacts/u/secret/report.html"}),
                           headers={"Content-Type": "application/x-www-form-urlencoded"},
                           cookie="sid=dave")
        self.assertEqual(st, 200)
        self.assertIn("Request sent", page)
        # 3) the request landed in state with owner + pending
        with OBJECTS_LOCK:
            req_keys = [k for k in OBJECTS if k.startswith("_gate/req/")]
        self.assertEqual(len(req_keys), 1)
        rec = json.loads(OBJECTS[req_keys[0]])
        self.assertEqual(rec["status"], "pending")
        self.assertEqual(rec["requester"], "dave@example.com")
        # 4) owner opens the GET link -> confirmation page, state unchanged (GET never mutates)
        token = self.gate.make_action_token(rec["id"], "approve", self.gate._KEY, 1_800_000_000)
        url = self.base + "/_gate/approve?token=" + urllib.parse.quote(token, safe="")
        st, page, _ = http(url, cookie="sid=owner")
        self.assertEqual(st, 200)
        self.assertIn("Confirm", page)
        with OBJECTS_LOCK:
            self.assertEqual(json.loads(OBJECTS[req_keys[0]])["status"], "pending")
        # 5) a non-owner cannot act: alice (listed user) gets 403
        st, _, _ = http(url, method="POST", data=urllib.parse.urlencode({"token": token}),
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        cookie="sid=alice")
        self.assertEqual(st, 403)
        # 6) owner POSTs -> approved, ACL updated
        st, page, _ = http(url, method="POST", data=urllib.parse.urlencode({"token": token}),
                           headers={"Content-Type": "application/x-www-form-urlencoded"},
                           cookie="sid=owner")
        self.assertEqual(st, 200)
        with OBJECTS_LOCK:
            self.assertEqual(json.loads(OBJECTS[req_keys[0]])["status"], "approve")
            acl = json.loads(OBJECTS["u/secret/.acl.json"])
        self.assertIn("dave@example.com", acl["users"])
        # 7) token is now single-use: replay fails
        st, body, _ = http(url, method="POST", data=urllib.parse.urlencode({"token": token}),
                           headers={"Content-Type": "application/x-www-form-urlencoded"},
                           cookie="sid=owner")
        self.assertEqual(st, 410)
        self.assertIn("already <b>approved</b>", body,
                      "replay page must read 'already approved', not the raw action verb")
        # 8) dave can now read (forwardAuth allows)
        st, _, _ = self.auth("/artifacts/u/secret/report.html", "dave")
        self.assertEqual(st, 200)

    def test_deny_flow_leaves_acl_untouched(self):
        USERS["erin"] = ("erin@example.com", "aaaa")
        st, page, _ = self.auth("/artifacts/u/secret/report.html", "erin")
        csrf = re.search(r'name=csrf value="([^"]+)"', page).group(1)
        st, _, _ = http(self.base + "/_gate/request", method="POST",
                       data=urllib.parse.urlencode({"csrf": csrf,
                                                    "artifact": "/artifacts/u/secret/report.html"}),
                       headers={"Content-Type": "application/x-www-form-urlencoded"},
                       cookie="sid=erin")
        with OBJECTS_LOCK:
            rec = json.loads(OBJECTS[next(k for k in OBJECTS if k.startswith("_gate/req/"))])
        acl_before = OBJECTS["u/secret/.acl.json"]
        token = self.gate.make_action_token(rec["id"], "deny", self.gate._KEY, 1_800_000_000)
        st, _, _ = http(self.base + "/_gate/deny", method="POST",
                        data=urllib.parse.urlencode({"token": token}),
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        cookie="sid=owner")
        self.assertEqual(st, 200)
        with OBJECTS_LOCK:
            self.assertEqual(OBJECTS["u/secret/.acl.json"], acl_before)
            self.assertEqual(json.loads(OBJECTS[f"_gate/req/{rec['id']}.json"])["status"], "deny")

    def _pending_request(self, requester):
        rid = self.gate.REQUESTS.create(requester, "/artifacts/u/secret/report.html",
                                        "owner@example.com", 1_800_000_000)
        return rid

    def _post_action(self, endpoint, token):
        return http(self.base + f"/_gate/{endpoint}", method="POST",
                    data=urllib.parse.urlencode({"token": token}),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    cookie="sid=owner")

    def test_deny_token_cannot_approve(self):
        # finding 3: the token's `act` binds the endpoint. A deny token POSTed (or opened) on
        # /_gate/approve is refused with 410: no state change, no ACL grant.
        rid = self._pending_request("frank@example.com")
        acl_before = OBJECTS["u/secret/.acl.json"]
        token = self.gate.make_action_token(rid, "deny", self.gate._KEY, 1_800_000_000)
        st, body, _ = self._post_action("approve", token)
        self.assertEqual(st, 410)
        self.assertIn("Link invalid", body)
        st, _, _ = http(self.base + "/_gate/approve?token=" + urllib.parse.quote(token, safe=""),
                        cookie="sid=owner")
        self.assertEqual(st, 410)
        with OBJECTS_LOCK:
            self.assertEqual(json.loads(OBJECTS[f"_gate/req/{rid}.json"])["status"], "pending")
            self.assertEqual(OBJECTS["u/secret/.acl.json"], acl_before)
        # the right endpoint still works with the same token
        st, _, _ = self._post_action("deny", token)
        self.assertEqual(st, 200)
        with OBJECTS_LOCK:
            self.assertEqual(json.loads(OBJECTS[f"_gate/req/{rid}.json"])["status"], "deny")
            self.assertEqual(OBJECTS["u/secret/.acl.json"], acl_before)

    def test_approve_token_cannot_deny(self):
        # finding 3, other direction: an approve token on /_gate/deny is refused (410)
        rid = self._pending_request("grace@example.com")
        token = self.gate.make_action_token(rid, "approve", self.gate._KEY, 1_800_000_000)
        st, _, _ = self._post_action("deny", token)
        self.assertEqual(st, 410)
        st, _, _ = http(self.base + "/_gate/deny?token=" + urllib.parse.quote(token, safe=""),
                        cookie="sid=owner")
        self.assertEqual(st, 410)
        with OBJECTS_LOCK:
            self.assertEqual(json.loads(OBJECTS[f"_gate/req/{rid}.json"])["status"], "pending")
        st, _, _ = self._post_action("approve", token)
        self.assertEqual(st, 200)
        with OBJECTS_LOCK:
            self.assertEqual(json.loads(OBJECTS[f"_gate/req/{rid}.json"])["status"], "approve")
            self.assertIn("grace@example.com",
                          json.loads(OBJECTS["u/secret/.acl.json"])["users"])

    # -- the approval's ACL write: conditional (If-Match), keeps the ttl tag, never a false
    #    "approved" -------------------------------------------------------------------
    def record_notifications(self):
        sent = []

        class Recorder:
            def send(self, email, text):
                sent.append((email, text))
                return True, "ok"
        patch = mock.patch.object(self.gate, "NOTIFIER", Recorder())
        patch.start()
        self.addCleanup(patch.stop)
        return sent

    @staticmethod
    def other_writer_adds(user):
        def write():                          # runs under OBJECTS_LOCK: a plain overwrite
            acl = json.loads(OBJECTS["u/secret/.acl.json"])
            acl["users"].append(user)
            OBJECTS["u/secret/.acl.json"] = json.dumps(acl).encode()
        return write

    def _approve(self, requester):
        rid = self._pending_request(requester)
        token = self.gate.make_action_token(rid, "approve", self.gate._KEY, int(time.time()))
        return rid, token

    def test_approval_race_first_put_412_retry_keeps_both_writers(self):
        sent = self.record_notifications()
        rid, token = self._approve("ivan@example.com")
        with OBJECTS_LOCK:
            AFTER_GET["u/secret/.acl.json"] = [self.other_writer_adds("other@example.com")]
        st, page, _ = self._post_action("approve", token)
        self.assertEqual(st, 200, page)
        acl_puts = [(st_, bool(im)) for k, im, _t, st_ in PUTS if k == "u/secret/.acl.json"]
        self.assertEqual(acl_puts, [(412, True), (200, True)])     # conditional both times
        acl = json.loads(OBJECTS["u/secret/.acl.json"])
        self.assertEqual(acl["users"], ["alice@example.com", "other@example.com", "ivan@example.com"])
        self.assertEqual((acl["owner"], acl["groups"]),
                         ("owner@example.com", ["11111111-2222-4333-8444-555555555555"]))
        self.assertEqual(len(sent), 1)
        self.assertIn("approved", sent[0][1])

    def test_approval_that_loses_twice_is_never_reported_approved(self):
        sent = self.record_notifications()
        log = self.capture_log()
        rid, token = self._approve("judy@example.com")
        with OBJECTS_LOCK:
            AFTER_GET["u/secret/.acl.json"] = [self.other_writer_adds("o1@example.com"),
                                               self.other_writer_adds("o2@example.com")]
        st, page, _ = self._post_action("approve", token)
        self.assertEqual(st, 503)
        self.assertIn("Access not granted", page)
        self.assertNotIn("Request approved", page)
        self.assertEqual(sent, [])                                # the requester is told nothing
        self.assertIn("ACL write failed: put HTTP 412", log.getvalue())
        acl = json.loads(OBJECTS["u/secret/.acl.json"])           # the other writer's ACL, as written
        self.assertEqual(acl["users"], ["alice@example.com", "o1@example.com", "o2@example.com"])
        with OBJECTS_LOCK:
            self.assertEqual(json.loads(OBJECTS[f"_gate/req/{rid}.json"])["status"], "pending")
        # re-decidable: the same link works once the write can go through
        st, page, _ = self._post_action("approve", token)
        self.assertEqual(st, 200, page)
        self.assertIn("judy@example.com", json.loads(OBJECTS["u/secret/.acl.json"])["users"])
        self.assertEqual(len(sent), 1)
        self.assertIn("approved", sent[0][1])

    def test_approval_without_a_readable_acl_is_never_reported_approved(self):
        sent = self.record_notifications()
        log = self.capture_log()
        rid, token = self._approve("kim@example.com")
        with OBJECTS_LOCK:
            del OBJECTS["u/secret/.acl.json"]
        st, page, _ = self._post_action("approve", token)
        self.assertEqual(st, 503)
        self.assertIn("Access not granted", page)
        self.assertEqual(sent, [])
        self.assertIn("ACL write failed: acl unreadable: missing", log.getvalue())
        self.assertNotIn("u/secret/.acl.json", OBJECTS)            # never created
        with OBJECTS_LOCK:
            self.assertEqual(json.loads(OBJECTS[f"_gate/req/{rid}.json"])["status"], "pending")

    def test_approval_keeps_the_acl_ttl_tag(self):
        with OBJECTS_LOCK:
            TAGS["u/secret/.acl.json"] = {"ttl": "7"}
        rid, token = self._approve("lena@example.com")
        st, _, _ = self._post_action("approve", token)
        self.assertEqual(st, 200)
        self.assertIn("lena@example.com", json.loads(OBJECTS["u/secret/.acl.json"])["users"])
        self.assertEqual(TAGS.get("u/secret/.acl.json"), {"ttl": "7"})
        self.assertEqual([t for k, _im, t, _st in PUTS if k == "u/secret/.acl.json"], ["ttl=7"])

    # a store reply cut short (http.client.IncompleteRead, not an OSError) on any request of the
    # grant, or any other unexpected exception, is a failed grant like the others: 503, request
    # back to pending, no message, one clean log line; the same link works once the store does
    def _approval_with_a_cut_store_reply(self, method):
        sent = self.record_notifications()
        log = self.capture_log()
        acl_key = "u/secret/.acl.json"
        with OBJECTS_LOCK:
            TAGS[acl_key] = {"ttl": "7"}
            TRUNCATE[(method, acl_key)] = 1
        rid, token = self._approve("sam@example.com")
        st, page, _ = self._post_action("approve", token)
        self.assertEqual(st, 503, page)
        self.assertIn("Access not granted", page)
        self.assertEqual(sent, [])
        with OBJECTS_LOCK:
            self.assertEqual(TRUNCATE[(method, acl_key)], 0)        # the cut reply was sent
            self.assertEqual(json.loads(OBJECTS[f"_gate/req/{rid}.json"])["status"], "pending")
        lines = [ln for ln in log.getvalue().splitlines() if "ACL write failed" in ln]
        self.assertEqual(len(lines), 1, lines)
        self.assertIn(": IncompleteRead (requester=sam@example.com", lines[0])
        for leak in ("more expected", "bytes read", "alice@example.com", '"users"'):
            self.assertNotIn(leak, lines[0])
        st, page, _ = self._post_action("approve", token)      # the store answers in full again
        self.assertEqual(st, 200, page)
        acl = json.loads(OBJECTS[acl_key])
        self.assertEqual(acl["users"].count("sam@example.com"), 1)
        self.assertEqual(TAGS[acl_key], {"ttl": "7"})
        self.assertEqual(len(sent), 1)
        self.assertIn("approved", sent[0][1])
        return lines[0]

    def test_cut_reply_on_the_acl_read_is_a_failed_grant(self):
        line = self._approval_with_a_cut_store_reply("GET")
        self.assertIn("acl unreadable: minio GET u/secret/.acl.json: IncompleteRead", line)

    def test_cut_reply_on_the_tag_read_is_a_failed_grant(self):
        line = self._approval_with_a_cut_store_reply("GET?tagging")
        self.assertIn("acl tags unreadable: minio GET u/secret/.acl.json: IncompleteRead", line)

    def test_cut_reply_on_an_applied_acl_write_is_confirmed_by_a_re_read(self):
        # the store applied the write but its reply was cut: one fresh read finds the requester
        # listed, so the first click already approves, with one write and one message
        sent = self.record_notifications()
        log = self.capture_log()
        acl_key = "u/secret/.acl.json"
        with OBJECTS_LOCK:
            TAGS[acl_key] = {"ttl": "7"}
            TRUNCATE[("PUT", acl_key)] = 1
        rid, token = self._approve("sam@example.com")
        st, page, _ = self._post_action("approve", token)
        self.assertEqual(st, 200, page)
        self.assertIn("<title>Request approved</title>", page)
        with OBJECTS_LOCK:
            self.assertEqual(TRUNCATE[("PUT", acl_key)], 0)        # the cut reply was sent
            self.assertEqual(json.loads(OBJECTS[f"_gate/req/{rid}.json"])["status"], "approve")
            self.assertEqual([s for k, _im, _t, s in PUTS if k == acl_key], [200])
            self.assertEqual(json.loads(OBJECTS[acl_key])["users"].count("sam@example.com"), 1)
            self.assertEqual(TAGS[acl_key], {"ttl": "7"})
        self.assertEqual(len(sent), 1)
        self.assertIn("approved", sent[0][1])
        self.assertIn("acl_note=added (confirmed by a re-read after a lost reply)", log.getvalue())
        self.assertNotIn("ACL write failed", log.getvalue())

    # a write whose outcome is unknown (its reply lost, and the re-read does not show the
    # requester) says so: never "Nothing was changed"; the same link finishes it, and Deny is
    # not a way back
    def _assert_unknown_outcome_page(self, page, reopened=True):
        self.assertIn("<title>Access not confirmed</title>", page)
        self.assertIn("may or may not have been updated", page)
        self.assertIn("Deny does not remove access that was already added", page)
        if reopened:
            self.assertIn("Use the same link again", page)
        self.assertNotIn("Nothing was changed", page)
        self.assertNotIn("Request approved", page)

    def test_lost_reply_on_a_write_the_store_did_not_apply_is_an_unknown_outcome(self):
        sent = self.record_notifications()
        log = self.capture_log()
        acl_key = "u/secret/.acl.json"
        with OBJECTS_LOCK:
            PLAN[("PUT", acl_key)] = ["drop"]
        rid, token = self._approve("uma@example.com")
        st, page, _ = self._post_action("approve", token)
        self.assertEqual(st, 503, page)
        self._assert_unknown_outcome_page(page)
        self.assertEqual(sent, [])
        with OBJECTS_LOCK:
            self.assertEqual(json.loads(OBJECTS[f"_gate/req/{rid}.json"])["status"], "pending")
            self.assertNotIn("uma@example.com", json.loads(OBJECTS[acl_key])["users"])
        lines = [ln for ln in log.getvalue().splitlines() if "ACL write failed" in ln]
        self.assertEqual(len(lines), 1, lines)
        self.assertIn("ACL write failed: put failed: minio PUT u/secret/.acl.json:", lines[0])
        self.assertIn("; not listed on a re-read (requester=uma@example.com", lines[0])
        self.assertIn("access list may or may not have been updated)", lines[0])
        st, page, _ = self._post_action("approve", token)          # the store answers again
        self.assertEqual(st, 200, page)
        self.assertIn("uma@example.com", json.loads(OBJECTS[acl_key])["users"])
        self.assertEqual(len(sent), 1)

    def test_lost_reply_and_a_failed_re_read_is_an_unknown_outcome(self):
        # the write was applied, its reply was cut, and the confirming read fails too: the
        # requester already has access, so the page must not say nothing changed; a retry of
        # the same link finds them listed and writes nothing more
        sent = self.record_notifications()
        log = self.capture_log()
        acl_key = "u/secret/.acl.json"
        with OBJECTS_LOCK:
            PLAN[("PUT", acl_key)] = ["cut"]
            PLAN[("GET", acl_key)] = ["ok", "drop"]
        rid, token = self._approve("vic@example.com")
        st, page, _ = self._post_action("approve", token)
        self.assertEqual(st, 503, page)
        self._assert_unknown_outcome_page(page)
        self.assertEqual(sent, [])
        with OBJECTS_LOCK:
            self.assertIn("vic@example.com", json.loads(OBJECTS[acl_key])["users"])
            self.assertEqual(json.loads(OBJECTS[f"_gate/req/{rid}.json"])["status"], "pending")
        self.assertIn("; the confirming read failed too: minio GET u/secret/.acl.json:",
                      log.getvalue())
        self.assertIn("access list may or may not have been updated)", log.getvalue())
        st, page, _ = self._post_action("approve", token)
        self.assertEqual(st, 200, page)
        with OBJECTS_LOCK:
            self.assertEqual([s for k, _im, _t, s in PUTS if k == acl_key], [200])   # one write
            self.assertEqual(json.loads(OBJECTS[acl_key])["users"].count("vic@example.com"), 1)
        self.assertEqual(len(sent), 1)
        self.assertIn("acl_note=already listed", log.getvalue())

    def test_only_a_known_refusal_says_nothing_was_changed(self):
        # a write refused with a status code changed nothing and says so; a lost reply never does
        acl_key = "u/secret/.acl.json"
        self.record_notifications()
        _rid, token = self._approve("walt@example.com")
        with OBJECTS_LOCK:
            AFTER_GET[acl_key] = [self.other_writer_adds("o1@example.com"),
                                  self.other_writer_adds("o2@example.com")]
        st, page, _ = self._post_action("approve", token)
        self.assertEqual(st, 503, page)
        self.assertIn("<title>Access not granted</title>", page)
        self.assertIn("Nothing was changed", page)
        self.assertNotIn("may or may not", page)
        _rid, token = self._approve("xena@example.com")
        with OBJECTS_LOCK:
            PLAN[("PUT", acl_key)] = ["drop"]
        st, page, _ = self._post_action("approve", token)
        self.assertEqual(st, 503, page)
        self._assert_unknown_outcome_page(page)

    def test_unexpected_exception_in_the_grant_is_a_failed_grant(self):
        sent = self.record_notifications()
        log = self.capture_log()
        rid, token = self._approve("tess@example.com")
        secretish = "Authorization: AWS4-HMAC-SHA256 Credential=leak-marker"
        with mock.patch.object(self.gate, "grant_access", side_effect=RuntimeError(secretish)):
            st, page, _ = self._post_action("approve", token)
        self.assertEqual(st, 503, page)
        self._assert_unknown_outcome_page(page)       # raised anywhere: maybe after the write
        self.assertEqual(sent, [])
        with OBJECTS_LOCK:
            self.assertEqual(json.loads(OBJECTS[f"_gate/req/{rid}.json"])["status"], "pending")
        out = log.getvalue()
        self.assertNotIn("leak-marker", out)
        self.assertNotIn("Traceback", out)
        lines = [ln for ln in out.splitlines() if "ACL write failed" in ln]
        self.assertEqual(len(lines), 1, lines)
        self.assertIn("ACL write failed: unexpected RuntimeError (requester=tess@example.com", lines[0])
        st, page, _ = self._post_action("approve", token)
        self.assertEqual(st, 200, page)
        self.assertIn("tess@example.com", json.loads(OBJECTS["u/secret/.acl.json"])["users"])
        self.assertEqual(len(sent), 1)

    def test_deny_message_unchanged(self):
        sent = self.record_notifications()
        rid = self._pending_request("mike@example.com")
        token = self.gate.make_action_token(rid, "deny", self.gate._KEY, int(time.time()))
        st, page, _ = self._post_action("deny", token)
        self.assertEqual(st, 200)
        self.assertIn("<title>Request denied</title>", page)
        self.assertEqual(len(sent), 1)
        self.assertIn("denied", sent[0][1])
        self.assertNotIn("approved", sent[0][1])
        self.assertEqual([k for k, *_x in PUTS if k.endswith(".acl.json")], [])

    # -- an approval grants the whole artifact: every message says so --------------------
    def test_owner_dm_names_the_whole_artifact(self):
        sent = self.record_notifications()
        USERS["nina"] = ("nina@example.com", "aaaa")
        uri = "/artifacts/u/secret/assets/app.css"
        with OBJECTS_LOCK:
            OBJECTS["u/secret/assets/app.css"] = b"body{}"
        st, page, _ = self.auth(uri, "nina")
        csrf = re.search(r'name=csrf value="([^"]+)"', page).group(1)
        st, _, _ = http(self.base + "/_gate/request", method="POST",
                        data=urllib.parse.urlencode({"csrf": csrf, "artifact": uri}),
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        cookie="sid=nina")
        self.assertEqual(st, 200)
        self.assertEqual([to for to, _ in sent], ["owner@example.com"])
        text = sent[0][1]
        self.assertIn("Requested file: `/artifacts/u/secret/assets/app.css`", text)
        self.assertIn("Approving gives access to the whole artifact `/artifacts/u/secret/`", text)

    def test_confirm_and_result_pages_name_the_whole_artifact(self):
        sent = self.record_notifications()
        rid = self.gate.REQUESTS.create("olga@example.com", "/artifacts/u/secret/assets/app.css",
                                        "owner@example.com", int(time.time()))
        approve = self.gate.make_action_token(rid, "approve", self.gate._KEY, int(time.time()))
        st, page, _ = http(self.base + "/_gate/approve?token=" + urllib.parse.quote(approve, safe=""),
                           cookie="sid=owner")
        self.assertEqual(st, 200)
        self.assertIn("asked for <code>/artifacts/u/secret/assets/app.css</code>", page)
        self.assertIn("access to the whole artifact <code>/artifacts/u/secret/</code>", page)
        deny = self.gate.make_action_token(rid, "deny", self.gate._KEY, int(time.time()))
        st, page, _ = http(self.base + "/_gate/deny?token=" + urllib.parse.quote(deny, safe=""),
                           cookie="sid=owner")
        self.assertEqual(st, 200)
        self.assertNotIn("whole artifact", page)
        st, page, _ = self._post_action("approve", approve)
        self.assertEqual(st, 200)
        self.assertIn("<title>Request approved</title>", page)
        self.assertIn("can now open the whole artifact <code>/artifacts/u/secret/</code>", page)
        self.assertEqual(sent, [("olga@example.com",
                                 "Your access request for `/artifacts/u/secret/assets/app.css` was "
                                 "approved: you can now open the whole artifact `/artifacts/u/secret/`.")])

    def test_key_without_artifact_root_promises_no_owner(self):
        acl = json.dumps({"owner": "alice@example.com", "users": []}).encode()
        with OBJECTS_LOCK:
            OBJECTS["u/.acl.json"] = acl
            OBJECTS["u/loose.html"] = b"x"
        USERS["pete"] = ("pete@example.com", "aaaa")
        for uri in ("/artifacts/u/loose.html", "/artifacts/u/ghost.html", "/artifacts/acl/run.json"):
            st, body, _ = self.auth(uri, "pete")
            self.assertEqual(st, 403, uri)
            self.assertIn("Access required", body)
            self.assertIn("no owner to ask", body)
            self.assertNotIn("Request access", body)
            self.assertNotIn("name=csrf", body)
        st, body, _ = self.auth("/artifacts/u/secret/report.html", "pete")   # a real artifact: the form
        self.assertEqual(st, 403)
        self.assertIn("Request access", body)

    def test_request_access_refuses_paths_the_gate_never_serves(self):
        # even with a valid CSRF token for that exact path (the gate never issues one: no deny
        # page is rendered for these), nothing is recorded, nobody is notified
        sent = self.record_notifications()
        acl = json.dumps({"owner": "owner@example.com", "users": []}).encode()
        with OBJECTS_LOCK:
            OBJECTS["u/secret/../other/x.html"] = b"x"     # the literal key, as a store could hold it
            OBJECTS["u/other/.acl.json"] = acl
            OBJECTS["u/.acl.json"] = acl
            OBJECTS["u/loose.html"] = b"x"
        USERS["quin"] = ("quin@example.com", "aaaa")
        for path in ("/artifacts/u/secret/../other/x.html", "/artifacts/u/secret/%2e%2e/other/x.html",
                     "/artifacts/u/secret/.acl.json", "/artifacts/u/secret/",
                     "/artifacts/u/loose.html", "/artifacts/acl/run.json"):
            csrf = self.gate.make_csrf("quin@example.com", path, self.gate._KEY, int(time.time()))
            st, body, _ = http(self.base + "/_gate/request", method="POST",
                               data=urllib.parse.urlencode({"csrf": csrf, "artifact": path}),
                               headers={"Content-Type": "application/x-www-form-urlencoded"},
                               cookie="sid=quin")
            self.assertEqual(st, 400, path)
            self.assertIn("not inside a published artifact", body)
        with OBJECTS_LOCK:
            self.assertEqual([k for k in OBJECTS if k.startswith("_gate/req/")], [])
        self.assertEqual(sent, [])

    def test_pub_takes_no_access_request(self):
        # pub/ is anonymous-readable by design: a signed-in visitor denied a pub/ key (missing,
        # or a stray ACL that does not list them) gets the same page with no request form; the
        # request POST is refused on its path, and an approval of an older pending pub/ request
        # writes nothing
        sent = self.record_notifications()
        USERS["hank"] = ("hank@example.com", "aaaa")
        acl = json.dumps({"owner": "owner@example.com", "users": ["alice@example.com"]}).encode()
        with OBJECTS_LOCK:
            OBJECTS["pub/closed/index.html"] = b"x"
            OBJECTS["pub/closed/.acl.json"] = acl
        pages = []
        for uri in ("/artifacts/pub/closed/index.html", "/artifacts/pub/free/ghost.html"):
            st, body, _ = self.auth(uri, "hank")
            self.assertEqual(st, 403, uri)
            self.assertIn("Access required", body, uri)
            self.assertIn("cannot be requested", body, uri)
            self.assertNotIn("Request access", body, uri)
            self.assertNotIn("name=csrf", body, uri)
            pages.append(body.replace(uri, "<uri>"))
        self.assertEqual(pages[0], pages[1])                 # missing and closed: one page
        for path in ("/artifacts/pub/closed/index.html", "/artifacts/pub/free/index.html"):
            csrf = self.gate.make_csrf("hank@example.com", path, self.gate._KEY, int(time.time()))
            st, body, _ = http(self.base + "/_gate/request", method="POST",
                               data=urllib.parse.urlencode({"csrf": csrf, "artifact": path}),
                               headers={"Content-Type": "application/x-www-form-urlencoded"},
                               cookie="sid=hank")
            self.assertEqual(st, 400, path)
            self.assertIn("cannot be requested", body)
        with OBJECTS_LOCK:
            self.assertEqual([k for k in OBJECTS if k.startswith("_gate/req/")], [])
        self.assertEqual(sent, [])
        # a pub/ request recorded before this rule: the approval is refused, nothing written
        rid = self.gate.REQUESTS.create("hank@example.com", "/artifacts/pub/closed/index.html",
                                        "owner@example.com", 1_800_000_000)
        token = self.gate.make_action_token(rid, "approve", self.gate._KEY, int(time.time()))
        st, page, _ = self._post_action("approve", token)
        self.assertEqual(st, 503, page)
        self.assertIn("Access not granted", page)
        self.assertIn("Nothing was changed", page)
        with OBJECTS_LOCK:
            self.assertEqual(OBJECTS["pub/closed/.acl.json"], acl)
            self.assertEqual([k for k, *_x in PUTS if k.endswith(".acl.json")], [])
        self.assertEqual(sent, [])

    def test_request_access_missing_artifact_uniform_response_no_state(self):
        USERS["frank"] = ("frank@example.com", "aaaa")
        st, page, _ = self.auth("/artifacts/u/secret/ghost.html", "frank")
        csrf = re.search(r'name=csrf value="([^"]+)"', page).group(1)
        st, page2, _ = http(self.base + "/_gate/request", method="POST",
                            data=urllib.parse.urlencode({"csrf": csrf,
                                                         "artifact": "/artifacts/u/secret/ghost.html"}),
                           headers={"Content-Type": "application/x-www-form-urlencoded"},
                           cookie="sid=frank")
        self.assertEqual(st, 200)
        self.assertIn("Request sent", page2)            # same page as the real request
        with OBJECTS_LOCK:
            self.assertEqual([k for k in OBJECTS if k.startswith("_gate/req/")], [])  # nothing recorded

    def test_request_access_rate_limited(self):
        USERS["gina"] = ("gina@example.com", "aaaa")
        for i in range(2):                                # GATE_RATE_LIMIT_MAX=2
            st, page, _ = self.auth("/artifacts/u/secret/report.html", "gina")
            csrf = re.search(r'name=csrf value="([^"]+)"', page).group(1)
            st, _, _ = http(self.base + "/_gate/request", method="POST",
                            data=urllib.parse.urlencode({"csrf": csrf,
                                                         "artifact": "/artifacts/u/secret/report.html"}),
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                            cookie="sid=gina")
            self.assertEqual(st, 200, f"request {i}")
        st, page, _ = self.auth("/artifacts/u/secret/report.html", "gina")
        csrf = re.search(r'name=csrf value="([^"]+)"', page).group(1)
        st, page, _ = http(self.base + "/_gate/request", method="POST",
                           data=urllib.parse.urlencode({"csrf": csrf,
                                                        "artifact": "/artifacts/u/secret/report.html"}),
                           headers={"Content-Type": "application/x-www-form-urlencoded"},
                           cookie="sid=gina")
        self.assertEqual(st, 429)
        self.assertIn("Too many requests", page)

    def test_csrf_rejected_on_foreign_or_stale_token(self):
        USERS["hank"] = ("hank@example.com", "aaaa")
        st, page, _ = self.auth("/artifacts/u/secret/report.html", "hank")
        csrf = re.search(r'name=csrf value="([^"]+)"', page).group(1)
        # hank replays his token but claims another artifact
        st, _, _ = http(self.base + "/_gate/request", method="POST",
                        data=urllib.parse.urlencode({"csrf": csrf,
                                                     "artifact": "/artifacts/u/secret/other.html"}),
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        cookie="sid=hank")
        self.assertEqual(st, 403)
        # bob steals hank's token
        st, _, _ = http(self.base + "/_gate/request", method="POST",
                        data=urllib.parse.urlencode({"csrf": csrf,
                                                     "artifact": "/artifacts/u/secret/report.html"}),
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        cookie="sid=bob")
        self.assertEqual(st, 403)

    def test_healthz(self):
        st, body, _ = http(self.base + "/_gate/healthz")
        self.assertEqual((st, body), (200, "ok"))

    def test_gate_pages_have_csp_and_no_store(self):
        USERS["ivy"] = ("ivy@example.com", "aaaa")
        st, _, hdrs = self.auth("/artifacts/u/secret/report.html", "ivy")
        self.assertEqual(st, 403)
        self.assertIn("default-src 'none'", hdrs.get("Content-Security-Policy", ""))
        self.assertEqual(hdrs.get("Cache-Control"), "no-store")

    def test_expired_acl_denies(self):
        OBJECTS["u/secret/.acl.json"] = json.dumps(
            {"owner": "owner@example.com", "users": ["alice@example.com"],
             "expires": "2020-01-01"}).encode()
        self.gate._acl_cache.clear()
        st, _, _ = self.auth("/artifacts/u/secret/report.html", "alice")
        self.assertEqual(st, 403)


    def test_keepalive_connection_stays_in_sync_after_405(self):
        # Regression (found live): the gate's 405 path answered without reading the
        # request body. Traefik reuses backend keep-alive connections and BaseHTTPRequestHandler
        # does not drain bodies, so the leftover body byte became the first byte of the NEXT
        # request line on that connection (in the cluster: method 'xPOST' -> 501). A body the
        # gate does not read now closes the connection after the answer (Connection: close), so
        # the next request starts on a fresh connection and still gets its real 405, never a 501
        # from a corrupted request line.
        hostport = self.base.split("//", 1)[1]
        conn = http_client.HTTPConnection(hostport, timeout=10)
        self.addCleanup(conn.close)
        conn.request("PUT", "/artifacts/x.txt", body="x")
        r = conn.getresponse()
        self.assertEqual(r.status, 405)
        self.assertEqual(r.getheader("Connection"), "close")
        r.read()
        conn.request("POST", "/artifacts/x.txt", body="y")
        r = conn.getresponse()
        self.assertEqual(r.status, 405,
                         "second request on the reused connection was corrupted by an unread body")
        r.read()


    # -- plugin authorization API (docs/plugins.md) -----------------------------------
    def plugin_authz(self, artifact, sid=None, flag=None, method="POST", ctype="application/json",
                     bearer=None):
        saved = self.gate.ANONYMOUS_PUB_ENABLED
        if flag is not None:
            self.gate.ANONYMOUS_PUB_ENABLED = flag
        self.addCleanup(setattr, self.gate, "ANONYMOUS_PUB_ENABLED", saved)
        hdrs = {"Content-Type": ctype}
        if bearer:
            hdrs["Authorization"] = f"Bearer {bearer}"
        st, body, _ = http(self.auth_base + "/_gate/plugin/authz", method=method,
                           data=json.dumps({"artifact": artifact}), headers=hdrs,
                           cookie=f"sid={sid}" if sid else None)
        try:
            return st, json.loads(body)
        except ValueError:
            return st, body

    def test_plugin_authz_allow_user(self):
        st, ans = self.plugin_authz("/artifacts/u/secret/report.html", sid="alice")
        self.assertEqual(st, 200)
        self.assertTrue(ans["allowed"], ans)
        self.assertEqual(ans["user"]["id"], "alice@example.com")
        self.assertEqual(ans["user"]["name"], "Alice Example")   # id_token `name` claim
        self.assertFalse(ans["user"]["anonymous"])
        self.assertEqual(ans["artifact"]["key"], "u/secret/report.html")

    def test_plugin_authz_name_falls_back_to_email(self):
        st, ans = self.plugin_authz("/artifacts/u/secret/report.html", sid="owner")
        self.assertEqual((st, ans["allowed"]), (200, True))
        self.assertEqual(ans["user"]["name"], "owner@example.com")   # no id_token from the proxy

    def test_plugin_authz_expired_not_leaked_to_strangers(self):
        OBJECTS["u/secret/.acl.json"] = json.dumps(
            {"owner": "owner@example.com", "users": ["alice@example.com"],
             "expires": "2020-01-01"}).encode()
        self.gate._acl_cache.clear()
        # bob is in no listed group: same answer as for a live artifact he is not on
        st, ans = self.plugin_authz("/artifacts/u/secret/report.html", sid="bob")
        self.assertEqual((st, ans["allowed"], ans["reason"]), (200, False, "denied"))
        self.assertEqual((ans["artifact"]["expires"], ans["artifact"]["ttl"]), (None, None))

    def test_plugin_authz_allow_group_member(self):
        st, ans = self.plugin_authz("/artifacts/u/secret/report.html", sid="bob")
        self.assertEqual((st, ans["allowed"]), (200, True))
        self.assertEqual(ans["reason"], "group")

    def test_plugin_authz_bearer_token_accepted(self):
        # the gate forwards the visitor's Authorization bearer to oauth2-proxy (fake proxy maps
        # Bearer <sid> to the same user): identity still comes from the proxy's response only.
        st, ans = self.plugin_authz("/artifacts/u/secret/report.html", bearer="alice")
        self.assertEqual((st, ans["allowed"]), (200, True))
        self.assertEqual(ans["user"]["id"], "alice@example.com")

    def test_plugin_authz_deny_no_acl_outside_pub(self):
        st, ans = self.plugin_authz("/artifacts/u/noteam/x.html", sid="alice")
        self.assertEqual(st, 200)
        self.assertFalse(ans["allowed"])
        self.assertEqual(ans["reason"], "denied")

    def test_plugin_authz_stranger_cannot_tell_acl_from_no_acl(self):
        # a stranger gets one answer for a directory without an ACL and for an ACL that does not
        # list them; the gate's log keeps the detailed reason
        USERS["stranger"] = ("stranger@example.com", "99999999-2222-4333-8444-555555555555")
        OBJECTS["u/noacl/report.html"] = b"x"
        log = self.capture_log()
        _, no_acl = self.plugin_authz("/artifacts/u/noacl/report.html", sid="stranger")
        _, listed_not_me = self.plugin_authz("/artifacts/u/secret/report.html", sid="stranger")
        _, missing = self.plugin_authz("/artifacts/u/secret/ghost.html", sid="stranger")
        for ans in (no_acl, listed_not_me, missing):
            self.assertEqual((ans["allowed"], ans["reason"]), (False, "denied"), ans)
            self.assertEqual((ans["artifact"]["expires"], ans["artifact"]["ttl"]), (None, None))
        lines = [ln for ln in log.getvalue().splitlines() if "plugin-authz user=stranger@" in ln]
        self.assertEqual(len(lines), 3, lines)
        self.assertIn("reason=denied detail=no-acl: deny by default", lines[0])
        self.assertIn("reason=denied detail=not-listed", lines[1])

    def test_malformed_acl_is_the_uniform_deny_for_a_stranger(self):
        # an ACL file that is not JSON must not tell a stranger "this artifact has a broken ACL"
        USERS["rita"] = ("rita@example.com", "99999999-2222-4333-8444-555555555555")
        uri = "/artifacts/u/secret/report.html"
        _, listed_not_me = self.plugin_authz(uri, sid="rita")
        st, page_valid, _ = self.auth(uri, "rita")
        self.assertEqual(st, 403)
        with OBJECTS_LOCK:
            OBJECTS["u/secret/.acl.json"] = b'{"owner": "owner@example.com", "users": [broken'
        self.gate._acl_cache.clear()
        log = self.capture_log()
        st, broken = self.plugin_authz(uri, sid="rita")
        self.assertEqual(st, 200)
        self.assertEqual(broken, listed_not_me)
        self.assertEqual((broken["allowed"], broken["reason"]), (False, "denied"))
        self.assertIn("detail=acl-error (malformed JSON)", log.getvalue())
        # nobody is let in by an ACL that cannot be read, the owner included: same answer shape
        _, owner = self.plugin_authz(uri, sid="owner")
        self.assertEqual((owner["allowed"], owner["reason"]), (False, "denied"))
        # forwardAuth already answered it with the same deny page as any other refusal
        st, page_broken, h = self.auth(uri, "rita")
        self.assertEqual(st, 403)
        self.assertNotIn("Authorization", h)
        strip = lambda p: re.sub(r'name=csrf value="[^"]+"', "", p)
        self.assertEqual(strip(page_broken), strip(page_valid))

    def test_plugin_authz_store_outage_is_still_acl_error(self):
        # unreadable store (the same for every key): reported as acl-error, fail closed
        with mock.patch.object(self.gate.MINIO, "get", side_effect=ConnectionError("down")):
            st, ans = self.plugin_authz("/artifacts/u/secret/report.html", sid="alice")
        self.assertEqual((st, ans["allowed"], ans["reason"]), (200, False, "acl-error"))

    def test_plugin_authz_deny_expired(self):
        OBJECTS["u/secret/.acl.json"] = json.dumps(
            {"owner": "owner@example.com", "users": ["alice@example.com"],
             "expires": "2020-01-01"}).encode()
        self.gate._acl_cache.clear()
        st, ans = self.plugin_authz("/artifacts/u/secret/report.html", sid="alice")
        self.assertEqual((st, ans["allowed"]), (200, False))
        self.assertEqual(ans["reason"], "expired")

    def test_plugin_authz_expiry_from_acl(self):
        OBJECTS["u/secret/.acl.json"] = json.dumps(
            {"owner": "owner@example.com", "users": ["alice@example.com"],
             "expires": "2030-01-02"}).encode()
        self.gate._acl_cache.clear()
        st, ans = self.plugin_authz("/artifacts/u/secret/report.html", sid="alice")
        self.assertTrue(ans["allowed"])
        self.assertTrue(ans["artifact"]["expires"].startswith("2030-01-02"))

    def test_plugin_authz_expiry_from_ttl_tag(self):
        # no ACL expires: ttl tag + Last-Modified compose the ILM expiry (docs/plugins.md §4)
        TAGS["u/secret/report.html"] = {"ttl": "7"}
        st, ans = self.plugin_authz("/artifacts/u/secret/report.html", sid="alice")
        self.assertTrue(ans["allowed"])
        self.assertEqual(ans["artifact"]["ttl"], 7)
        from datetime import datetime, timezone
        from email.utils import parsedate_to_datetime
        lm = parsedate_to_datetime(LAST_MODIFIED).timestamp()
        self.assertEqual(ans["artifact"]["expires"],
                         datetime.fromtimestamp(lm + 7 * 86400, timezone.utc).isoformat())

    def test_plugin_authz_anonymous_pub_flag_on(self):
        st, ans = self.plugin_authz("/artifacts/pub/free/index.html", flag=True)
        self.assertEqual(st, 200)
        self.assertTrue(ans["allowed"], ans)
        self.assertTrue(ans["user"]["anonymous"])

    def test_plugin_authz_anonymous_pub_flag_off(self):
        st, ans = self.plugin_authz("/artifacts/pub/free/index.html", flag=False)
        self.assertEqual(st, 200)
        self.assertFalse(ans["allowed"])
        self.assertEqual(ans["reason"], "unauthenticated")

    def test_plugin_authz_anonymous_outside_pub_denied_even_flag_on(self):
        st, ans = self.plugin_authz("/artifacts/u/secret/report.html", flag=True)
        self.assertEqual(st, 200)
        self.assertFalse(ans["allowed"])
        self.assertEqual(ans["reason"], "unauthenticated")

    def test_plugin_authz_pub_signed_in_allowed(self):
        st, ans = self.plugin_authz("/artifacts/pub/free/index.html", sid="alice")
        self.assertEqual((st, ans["allowed"]), (200, True))

    def test_plugin_authz_traversal_400(self):
        for art in ("/artifacts/pub/../u/secret/report.html",
                    "/artifacts/u/secret/../../etc/passwd"):
            st, ans = self.plugin_authz(art, sid="alice")
            self.assertEqual(st, 400, art)

    def test_plugin_authz_plugins_prefix_400(self):
        # the core never serves plugin storage, not even to plugins themselves
        st, _ = self.plugin_authz("/artifacts/_plugins/canvas/x.bin", sid="alice")
        self.assertEqual(st, 400)
        st, _ = self.plugin_authz("/artifacts/_plugins/canvas/x.bin")
        self.assertEqual(st, 400)

    def test_plugin_authz_state_prefix_400(self):
        st, _ = self.plugin_authz("/artifacts/_gate/req/x.json", sid="alice")
        self.assertEqual(st, 400)

    def test_plugin_authz_acl_file_400(self):
        st, _ = self.plugin_authz("/artifacts/u/secret/.acl.json", sid="alice")
        self.assertEqual(st, 400)

    def test_plugin_authz_bad_artifact_400(self):
        st, _ = self.plugin_authz("/elsewhere/x.html", sid="alice")
        self.assertEqual(st, 400)
        st, _ = self.plugin_authz("not-a-path", sid="alice")
        self.assertEqual(st, 400)

    def test_plugin_authz_not_on_public_listener(self):
        # fail-closed listener split: the public listener 404s the decision endpoints
        st, _, _ = http(self.base + "/_gate/plugin/authz", method="POST",
                     data=json.dumps({"artifact": "/artifacts/u/secret/report.html"}),
                     headers={"Content-Type": "application/json"}, cookie="sid=alice")
        self.assertEqual(st, 404)

    def test_plugin_authz_get_not_allowed(self):
        st, body, _ = http(self.auth_base + "/_gate/plugin/authz", cookie="sid=alice")
        self.assertEqual(st, 405)
        self.assertEqual(json.loads(body), {"error": "POST required"})
        # a GET carrying a body is refused before routing (a GET takes no body)
        st, _ = self.plugin_authz("/artifacts/u/secret/report.html", sid="alice", method="GET")
        self.assertEqual(st, 400)

    def test_plugin_authz_proxy_error_fails_closed(self):
        st, _ = self.plugin_authz("/artifacts/pub/free/index.html", sid="prefonly", flag=True)
        self.assertEqual(st, 500)

    def test_plugin_authz_allowed_but_object_missing(self):
        st, ans = self.plugin_authz("/artifacts/u/secret/ghost.html", sid="alice")
        self.assertEqual((st, ans["allowed"]), (200, False))
        self.assertEqual(ans["reason"], "object-missing")

    # -- hardening: request bodies, forwarded URI, logs, page headers -----------------
    def capture_log(self):
        buf = io.StringIO()
        handler = logging.StreamHandler(buf)
        handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        lg = logging.getLogger("artifact-gate")
        lg.addHandler(handler)
        self.addCleanup(lg.removeHandler, handler)
        self.addCleanup(lg.setLevel, lg.level)
        lg.setLevel(logging.INFO)
        return buf

    @staticmethod
    def raw(port, data, timeout=5.0):
        """Send raw bytes; return (status, {header: value}, socket). status None = no answer."""
        sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        sock.sendall(data)
        buf = b""
        try:
            while b"\r\n\r\n" not in buf:
                got = sock.recv(65536)
                if not got:
                    break
                buf += got
        except OSError:
            pass
        if not buf.startswith(b"HTTP/1.1 "):
            return None, {}, sock
        head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
        hdrs = {k.lower(): v for k, _, v in (ln.partition(": ") for ln in head[1:])}
        return int(head[0].split()[1]), hdrs, sock

    def port_of(self, server):
        return server.server_address[1]

    def test_post_endpoint_refuses_chunked_body(self):
        pub, dec = self.port_of(self.gate_public), self.port_of(self.gate_auth)
        for port, path in ((pub, "/_gate/request"), (pub, "/_gate/approve"), (pub, "/_gate/deny"),
                           (dec, "/_gate/plugin/authz")):
            for te in ("chunked", "gzip, chunked", "identity"):
                st, h, sock = self.raw(port, (
                    f"POST {path} HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: {te}\r\n"
                    "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
                    "5\r\ncsrf=\r\n0\r\n\r\n").encode())
                sock.close()
                self.assertEqual((st, h.get("connection")), (411, "close"), (path, te))
        # Content-Length together with Transfer-Encoding: refused the same way, never guessed
        st, h, sock = self.raw(pub, b"POST /_gate/request HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n"
                                    b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
        sock.close()
        self.assertEqual(st, 411)

    def test_chunked_body_is_never_read_into_memory(self):
        # F1: a chunk-size line of -1 used to read the connection to its end into memory
        # (7d00000: 125 MB claimed and allocated). The refusal comes before any body byte is read.
        for size_line in (b"-1", b"7d00000"):
            tracemalloc.start()
            try:
                tracemalloc.reset_peak()
                base = tracemalloc.get_traced_memory()[0]
                st, h, sock = self.raw(self.port_of(self.gate_public),
                                       b"POST /_gate/request HTTP/1.1\r\nHost: x\r\n"
                                       b"Transfer-Encoding: chunked\r\n\r\n" + size_line + b"\r\n",
                                       timeout=3)
                piece, sent = b"\0" * 65536, 0
                try:
                    for _ in range(128):             # 8 MiB more, if the gate still reads
                        sock.sendall(piece)
                        sent += len(piece)
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass                              # the gate closed the connection: refused
                time.sleep(0.3)
                peak = tracemalloc.get_traced_memory()[1] - base
            finally:
                tracemalloc.stop()
                sock.close()
            self.assertLess(peak, 2 * 1024 * 1024, (size_line, peak, sent))
            self.assertEqual(st, 411, size_line)

    def test_post_endpoint_refuses_missing_bad_or_large_length(self):
        pub, dec = self.port_of(self.gate_public), self.port_of(self.gate_auth)
        cases = [
            (b"", 411),                                              # no length at all
            (b"Content-Length: -1\r\n", 400),
            (b"Content-Length: +5\r\n", 400),
            (b"Content-Length: 5x\r\n", 400),
            (b"Content-Length: 1, 1\r\n", 400),
            (b"Content-Length: 1\r\nContent-Length: 1\r\n", 400),
            (b"Content-Length: 99999999999\r\n", 400),
            (b"Content-Length: 16385\r\n", 413),                     # POST_BODY_MAX + 1
            (b"Content-Length: 314572800\r\n", 413),                 # 300 MB declared, 0 sent
        ]
        for port, path in ((pub, "/_gate/request"), (dec, "/_gate/plugin/authz")):
            for hdr, want in cases:
                st, h, sock = self.raw(port, b"POST " + path.encode() + b" HTTP/1.1\r\nHost: x\r\n"
                                       + hdr + b"\r\n", timeout=3)
                sock.close()
                self.assertEqual((st, h.get("connection")), (want, "close"), (path, hdr))
                if path.endswith("authz"):
                    self.assertEqual(h.get("content-type"), "application/json")
        self.assertEqual(self.gate.POST_BODY_MAX, 16 * 1024)

    def test_post_endpoint_body_read_exactly_and_connection_reused(self):
        # an accepted body (at the limit) is read in full: the next request on the same
        # connection is parsed from the right byte
        hostport = self.base.split("//", 1)[1]
        conn = http_client.HTTPConnection(hostport, timeout=10)
        self.addCleanup(conn.close)
        prefix = "artifact=/artifacts/u/secret/report.html&csrf="
        body = prefix + "x" * (16 * 1024 - len(prefix))     # exactly POST_BODY_MAX bytes
        conn.request("POST", "/_gate/request", body=body,
                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        r = conn.getresponse()
        r.read()
        self.assertEqual(r.status, 401)                     # read, parsed, no session
        sock = conn.sock
        conn.request("GET", "/_gate/healthz")
        r = conn.getresponse()
        self.assertEqual((r.status, r.read()), (200, b"ok"))
        self.assertIs(conn.sock, sock, "the connection was not reused")

    def test_body_on_a_method_that_takes_none_is_refused(self):
        pub, dec = self.port_of(self.gate_public), self.port_of(self.gate_auth)
        fwd = (b"X-Forwarded-Method: GET\r\nX-Forwarded-Uri: /artifacts/pub/free/index.html\r\n"
               b"Cookie: sid=alice\r\n")
        for method in (b"GET", b"HEAD"):
            for body in (b"Content-Length: 5\r\n\r\nhello", b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"):
                st, h, sock = self.raw(dec, method + b" /_gate/auth HTTP/1.1\r\nHost: x\r\n" + fwd + body)
                sock.close()
                self.assertEqual((st, h.get("connection")), (400, "close"), (method, body))
                self.assertNotIn("authorization", h)
        # Content-Length: 0 is no body: the same forwardAuth is answered as usual
        st, h, sock = self.raw(dec, b"GET /_gate/auth HTTP/1.1\r\nHost: x\r\n" + fwd
                               + b"Content-Length: 0\r\n\r\n")
        sock.close()
        self.assertEqual(st, 200)
        # writes are never served: 405 as before, and with a body the connection closes unread
        for method in (b"PUT", b"DELETE", b"PATCH", b"OPTIONS", b"POST"):
            st, h, sock = self.raw(pub, method + b" /artifacts/x.txt HTTP/1.1\r\nHost: x\r\n"
                                   b"Transfer-Encoding: chunked\r\n\r\n-1\r\n")
            sock.close()
            self.assertEqual((st, h.get("connection")), (405, "close"), method)
            st, h, sock = self.raw(pub, method + b" /artifacts/x.txt HTTP/1.1\r\nHost: x\r\n"
                                   b"Content-Length: 314572800\r\n\r\n")
            sock.close()
            self.assertEqual((st, h.get("connection")), (405, "close"), method)
        st, h, sock = self.raw(pub, b"PUT /artifacts/x.txt HTTP/1.1\r\nHost: x\r\n\r\n")
        sock.close()
        self.assertEqual((st, h.get("connection")), (405, None))   # no body: keep-alive

    def test_stalled_body_times_out(self):
        # a client that stops sending holds the connection for GateHandler.timeout at most
        self.assertEqual(self.gate.GateHandler.timeout, 30)

        class Quick(self.gate.GateHandler):
            timeout = 1

        srv = serve(Quick, "public")
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        sock = socket.create_connection(("127.0.0.1", srv.server_address[1]), timeout=5)
        self.addCleanup(sock.close)
        sock.sendall(b"POST /_gate/request HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\ncsrf=")
        t0 = time.monotonic()
        try:
            got = sock.recv(1024)
        except socket.timeout:
            got = None
        self.assertEqual(got, b"", "the gate kept waiting for the rest of the body")
        self.assertLess(time.monotonic() - t0, 4)

    def test_forwarded_uri_read_two_ways_is_refused(self):
        # L1: "#frag" was decided as pub/free/index.html and signed as ".../index.html#frag";
        # "//host/..." and "http://host/..." put a host into one reading of the path
        for uri in ("/artifacts/pub/free/index.html#frag", "/artifacts/u/secret/report.html#x",
                    "//evil.example/artifacts/pub/free/index.html",
                    "http://evil.example/artifacts/pub/free/index.html",
                    "/artifacts/pub/free/in dex.html", "/artifacts/pub/free/index.html\x7f"):
            st, body, h = self._auth_h(uri, "alice")
            self.assertEqual(st, 404, uri)
            self.assertIn("Nothing here", body, uri)
            self.assertNotIn("Authorization", h, uri)
        st, _, h = self._auth_h("/artifacts/pub/free/index.html", "alice")
        self.assertEqual(st, 200)
        self.assertIn("Authorization", h)

    def test_action_token_never_in_the_log(self):
        log = self.capture_log()
        token = self.gate.make_action_token("ab" * 16, "approve", self.gate._KEY, int(time.time()))
        st, _, _ = http(self.base + "/_gate/approve?token=" + urllib.parse.quote(token, safe=""),
                        cookie="sid=owner")
        self.assertEqual(st, 410)                            # no such request: still logged
        st, _, sock = self.raw(self.port_of(self.gate_public),
                               f"GET /_gate/deny?token={token} extra HTTP/1.1\r\n\r\n".encode())
        sock.close()
        self.assertEqual(st, 400)          # "Bad request syntax (<request line>)", logged too
        out = log.getvalue()
        self.assertIn('"GET /_gate/approve?<redacted> HTTP/1.1" 410', out)
        self.assertIn("token=<redacted>", out)
        self.assertNotIn(token, out)
        self.assertNotIn(token.split(".")[1], out)

    def test_client_values_cannot_forge_log_lines(self):
        log = self.capture_log()
        forged = "INFO action=approve id=deadbeef by=owner@example.com"
        self._auth_h("/artifacts/u/secret/x%0A" + urllib.parse.quote(forged), "alice")
        self._auth_h("/artifacts/u/secret/report.html?x=%0A" + urllib.parse.quote(forged), "alice")
        # urlsplit drops \n from the form value; other line breaks of str.splitlines() remain.
        # Two log lines carry the form's path: the CSRF refusal (a path inside an artifact, u/x/)
        # and the shape refusal before it (a path with no artifact root, u/x<sep>...)
        for sep in ("\x0b", "\x1e", "\x85", "\u2028"):
            for prefix in ("/artifacts/u/x/", "/artifacts/u/x"):
                http(self.base + "/_gate/request", method="POST",
                     data=urllib.parse.urlencode({"csrf": "bad", "artifact": prefix + sep + forged}),
                     headers={"Content-Type": "application/x-www-form-urlencoded"}, cookie="sid=alice")
        lines = log.getvalue().splitlines()
        self.assertFalse([ln for ln in lines if ln.startswith(forged)], lines)
        self.assertTrue([ln for ln in lines if "key=u/secret/x\\x0aINFO action" in ln], lines)
        self.assertEqual(len([ln for ln in lines if "csrf rejected" in ln and "u/x/\\" in ln]), 4,
                         lines)
        self.assertEqual(len([ln for ln in lines
                              if "request-access refused" in ln and "u/x\\" in ln]), 4, lines)

    def test_gate_pages_cannot_be_framed(self):
        USERS["fran"] = ("fran@example.com", "aaaa")
        answers = [self.auth("/artifacts/u/secret/report.html", "fran"),          # 403 deny page
                   self.auth("/artifacts/u/secret/.acl.json", "fran"),            # 404
                   http(self.base + "/artifacts/x", method="DELETE"),                # 405
                   http(self.base + "/_gate/approve?token=x"),                       # 410
                   http(self.base + "/_gate/healthz")]                               # 200
        st, _ = self.plugin_authz("/artifacts/u/secret/report.html", sid="fran")
        self.assertEqual(st, 200)
        for st, _, h in answers:
            self.assertIn("frame-ancestors 'none'", h.get("Content-Security-Policy", ""), st)
            self.assertIn("default-src 'none'", h.get("Content-Security-Policy", ""), st)
            self.assertEqual(h.get("X-Frame-Options"), "DENY", st)
            self.assertEqual(h.get("Server"), "artifact-gate/1.0", st)  # no Python version

    # -- ACL at the artifact root, keys without one, _mcp/, refused identities ----------
    def test_subfolder_files_answer_to_the_root_acl(self):
        # a zip with subfolders is one artifact: every depth opens for who the root ACL lists
        # and closes for everyone when they are removed from it
        with OBJECTS_LOCK:
            OBJECTS["u/secret/assets/css/app.css"] = b"body{}"
            OBJECTS["g/team-a/run1/index.html"] = b"<h1>g</h1>"
            OBJECTS["g/team-a/run1/a/b/c.js"] = b"1"
            OBJECTS["g/team-a/run1/.acl.json"] = json.dumps(
                {"owner": "owner@example.com", "groups": ["11111111-2222-4333-8444-555555555555"]}).encode()
        for uri, sid in (("/artifacts/u/secret/assets/css/app.css", "alice"),
                         ("/artifacts/u/secret/assets/css/app.css", "bob"),
                         ("/artifacts/g/team-a/run1/index.html", "bob"),
                         ("/artifacts/g/team-a/run1/a/b/c.js", "bob")):
            st, _, h = self._auth_h(uri, sid)
            self.assertEqual(st, 200, (uri, sid))
            self.assertIn("Authorization", h)
            st, ans = self.plugin_authz(uri, sid=sid)
            self.assertEqual((st, ans["allowed"]), (200, True), (uri, sid))
        USERS["carol4"] = ("carol4@example.com", "aaaa")
        st, body, _ = self.auth("/artifacts/u/secret/assets/css/app.css", "carol4")
        self.assertEqual(st, 403)
        self.assertIn("Request access", body)
        with OBJECTS_LOCK:
            OBJECTS["u/secret/.acl.json"] = json.dumps(
                {"owner": "owner@example.com", "users": [], "groups": []}).encode()
        self.gate._acl_cache.clear()                     # the 15 s cache, not the rule
        for uri in ("/artifacts/u/secret/report.html", "/artifacts/u/secret/assets/css/app.css"):
            st, _, _ = self.auth(uri, "alice")
            self.assertEqual(st, 403, uri)

    def test_stray_nested_acl_never_consulted_or_served(self):
        USERS["mallory"] = ("mallory@example.com", "aaaa")
        with OBJECTS_LOCK:
            OBJECTS["u/secret/sub/x.html"] = b"x"
            OBJECTS["u/secret/sub/.acl.json"] = json.dumps(
                {"owner": "mallory@example.com", "users": ["mallory@example.com"]}).encode()
        st, _, h = self._auth_h("/artifacts/u/secret/sub/x.html", "mallory")
        self.assertEqual(st, 403)
        self.assertNotIn("Authorization", h)
        _, ans = self.plugin_authz("/artifacts/u/secret/sub/x.html", sid="mallory")
        self.assertEqual((ans["allowed"], ans["reason"]), (False, "denied"))
        st, _, _ = self.auth("/artifacts/u/secret/sub/x.html", "alice")   # listed at the root
        self.assertEqual(st, 200)
        for sid in ("mallory", "alice"):
            st, body, _ = self.auth("/artifacts/u/secret/sub/.acl.json", sid)
            self.assertEqual(st, 404, sid)
            self.assertIn("Nothing here", body)
            st, _ = self.plugin_authz("/artifacts/u/secret/sub/.acl.json", sid=sid)
            self.assertEqual(st, 400, sid)

    def test_stray_pub_root_acl_closes_every_depth(self):
        # a stray ACL at a pub root (no publisher writes one) narrows the whole run for signed-in
        # visitors and closes it to anonymous ones, at every depth; a deeper one is never read
        USERS["carol"] = ("carol@example.com", "aaaa")
        with OBJECTS_LOCK:
            OBJECTS["pub/free/sub/x.html"] = b"x"
            OBJECTS["pub/free/.acl.json"] = json.dumps(
                {"owner": "owner@example.com", "users": ["alice@example.com"]}).encode()
            OBJECTS["pub/free/sub/.acl.json"] = json.dumps(
                {"owner": "carol@example.com", "users": ["carol@example.com"]}).encode()
        for uri in ("/artifacts/pub/free/index.html", "/artifacts/pub/free/sub/x.html"):
            st, _, h = self._auth_h(uri, "carol")
            self.assertEqual(st, 403, uri)
            self.assertNotIn("Authorization", h, uri)
            st, _, h = self._auth_h(uri, "alice")
            self.assertEqual(st, 200, uri)
            self.assertIn("Authorization", h, uri)
            _, ans = self.plugin_authz(uri, flag=True)                      # anonymous
            self.assertEqual((ans["allowed"], ans["reason"]), (False, "denied"), uri)
            _, ans = self.plugin_authz(uri, sid="carol")
            self.assertEqual((ans["allowed"], ans["reason"]), (False, "denied"), uri)

    # -- the anonymous pub/ decision: GET /_gate/pub-auth (decision listener) ------------
    def pub_auth(self, uri, method="GET", headers=None, cookie=None, flag=True, port=None):
        saved = self.gate.ANONYMOUS_PUB_ENABLED
        self.gate.ANONYMOUS_PUB_ENABLED = flag
        self.addCleanup(setattr, self.gate, "ANONYMOUS_PUB_ENABLED", saved)
        base = self.auth_base if port is None else f"http://127.0.0.1:{port}"
        h = {"X-Forwarded-Method": method, "X-Forwarded-Uri": uri,
             "X-Forwarded-Host": "artifacts.test.invalid"}
        h.update(headers or {})
        return http(base + "/_gate/pub-auth", headers=h, cookie=cookie)

    @staticmethod
    def _shape(st, body, h):
        # status, headers and body of an answer, Date aside (it moves with the clock)
        return st, body, tuple(sorted((k.lower(), v) for k, v in h.items() if k.lower() != "date"))

    def test_pub_auth_allows_an_existing_pub_key_without_acl_and_signs_it(self):
        uri = "/artifacts/pub/free/index.html"
        for method in ("GET", "HEAD"):
            st, body, h = self.pub_auth(uri, method)          # no cookie: anonymous
            self.assertEqual((st, body), (200, "ok"), method)
            want = self.gate.upstream_auth_headers(method, "artifacts.test.invalid", uri,
                                                   "reader", "reader-secret",
                                                   amzdate=h["X-Amz-Date"])
            self.assertEqual(h["Authorization"], want["Authorization"], method)
            self.assertIn("Credential=reader/", h["Authorization"])
        # a single-file pub artifact (the MCP's layout) too
        with OBJECTS_LOCK:
            OBJECTS["pub/mcp-report-0123abcd.html"] = b"<h1>mcp</h1>"
        self.assertEqual(self.pub_auth("/artifacts/pub/mcp-report-0123abcd.html")[0], 200)
        # /_gate/auth stays the signed-in decision: never 200 without a session (C27)
        saved = self.gate.ANONYMOUS_PUB_ENABLED
        self.gate.ANONYMOUS_PUB_ENABLED = True
        self.addCleanup(setattr, self.gate, "ANONYMOUS_PUB_ENABLED", saved)
        for method in ("GET", "HEAD"):
            st, _, h = self.auth(uri, None, method=method)
            self.assertEqual(st, 401, method)
            self.assertNotIn("Authorization", h)

    def test_pub_auth_one_uniform_answer_for_everything_it_refuses(self):
        # C28: the same status, headers and body for a missing key, a key whose pub root has an
        # ACL, a listing, an .acl.json, _gate/, _mcp/, a malformed path, a query, a write and a
        # client S3 header; GET and HEAD alike; no login redirect, nothing from the store
        self.assertEqual(self.pub_auth("/artifacts/pub/free/index.html")[0], 200)   # control
        with OBJECTS_LOCK:
            OBJECTS["pub/closed/index.html"] = b"x"
            OBJECTS["pub/closed/.acl.json"] = json.dumps(
                {"owner": "owner@example.com", "users": ["alice@example.com"]}).encode()
        cases = [("/artifacts/pub/free/ghost.html", {}), ("/artifacts/pub/closed/index.html", {}),
                 ("/artifacts/pub/free/", {}), ("/artifacts/pub/free/.acl.json", {}),
                 ("/artifacts/pub/closed/.acl.json", {}), ("/artifacts/_gate/req/x.json", {}),
                 ("/artifacts/_mcp/x.json", {}), ("/artifacts/pub/free/index.html#x", {}),
                 ("/artifacts/pub/free/index.html?x=1", {}), ("//evil/artifacts/pub/free/x", {}),
                 ("/artifacts/u/secret/report.html", {}),
                 ("/artifacts/pub/free/index.html", {"X-Amz-Checksum-Mode": "ENABLED"})]
        shapes = set()
        for uri, extra in cases:
            for method in ("GET", "HEAD"):
                st, body, h = self.pub_auth(uri, method, headers=extra)
                self.assertEqual(st, 404, (uri, method))
                self.assertNotIn("Location", h)
                self.assertNotIn("Authorization", h)
                self.assertTrue(h["Content-Type"].startswith("text/html"), uri)
                self.assertNotIn("NoSuchKey", body)
                self.assertNotIn("<?xml", body)
                shapes.add(self._shape(st, body, h))
        for method in ("PUT", "DELETE", "POST"):
            shapes.add(self._shape(*self.pub_auth("/artifacts/pub/free/index.html", method)))
        self.assertEqual(len(shapes), 1, shapes)

    def test_pub_auth_never_lets_a_c29_spelling_through(self):
        # canaries in u/, g/, acl/ and _gate/ without an ACL; each probe spelling is refused
        # before the store is read, and never carries a signature
        self.assertEqual(self.pub_auth("/artifacts/pub/free/index.html")[0], 200)   # control
        with OBJECTS_LOCK:
            for k in ("u/canary/c.html", "g/team-a/canary/c.html", "acl/canary.html",
                      "_gate/canary.json"):
                OBJECTS[k] = b"CANARY"
        for t in ("u/canary/c.html", "g/team-a/canary/c.html", "acl/canary.html",
                  "_gate/canary.json"):
            for s in ("pub/../{}", "pub/%2e%2e/{}", "pub/%252e%252e/{}", "pub//../{}",
                      "pub/x;/../{}", "pub/free/..%2f..%2f{}", "pub/free/%5c..%5c{}"):
                uri = "/artifacts/" + s.format(t)
                st, body, h = self.pub_auth(uri)
                self.assertEqual(st, 404, uri)
                self.assertNotIn("CANARY", body)
                self.assertNotIn("Authorization", h, uri)

    def test_pub_auth_ignores_sessions_and_spoofed_targets(self):
        # a session changes nothing (no identity is asked), and a forwarded URI aimed at u/ or
        # g/ gets the uniform answer even from a visitor the ACL lists
        self.assertEqual(self.pub_auth("/artifacts/pub/free/index.html", cookie="sid=alice")[0],
                         200)
        with OBJECTS_LOCK:
            OBJECTS["g/team-a/run1/index.html"] = b"g"
            OBJECTS["pub/closed/index.html"] = b"x"
            OBJECTS["pub/closed/.acl.json"] = json.dumps(
                {"owner": "alice@example.com", "users": ["alice@example.com"]}).encode()
        for uri in ("/artifacts/u/secret/report.html", "/artifacts/g/team-a/run1/index.html",
                    "/artifacts/pub/closed/index.html"):
            for cookie in (None, "sid=alice", "sid=owner"):
                st, body, h = self.pub_auth(uri, cookie=cookie)
                self.assertEqual(st, 404, (uri, cookie))
                self.assertNotIn("Authorization", h)
                self.assertIn("Nothing here", body)

    def test_pub_auth_only_on_the_decision_listener_and_only_when_enabled(self):
        uri = "/artifacts/pub/free/index.html"
        self.assertEqual(self.pub_auth(uri)[0], 200)                           # control
        st, _, h = self.pub_auth(uri, port=self.port_of(self.gate_public))
        self.assertEqual(st, 404)
        self.assertNotIn("Authorization", h)
        st, _, h = self.pub_auth(uri, flag=False)
        self.assertEqual(st, 404)
        self.assertNotIn("Authorization", h)

    def test_pub_signed_in_reason_says_anonymous_read_by_design(self):
        st, ans = self.plugin_authz("/artifacts/pub/free/index.html", sid="alice")
        self.assertEqual((st, ans["allowed"], ans["reason"]),
                         (200, True, "pub: no ACL (anonymous read by design)"))

    def test_null_acl_at_a_pub_root_fails_closed(self):
        # a pub/ root ACL whose body is the JSON literal `null` is an unusable ACL, not "no ACL":
        # the anonymous decision, the plugin's anonymous answer and the signed-in decision all
        # refuse, as for any other malformed ACL
        self.assertEqual(self.pub_auth("/artifacts/pub/free/index.html")[0], 200)   # control
        for body in (b"null", b" null "):
            self.gate._acl_cache.clear()
            with OBJECTS_LOCK:
                OBJECTS["pub/free/.acl.json"] = body
            st, page, h = self.pub_auth("/artifacts/pub/free/index.html")
            self.assertEqual(st, 404, body)
            self.assertIn("Nothing here", page)
            self.assertNotIn("Authorization", h)
            _, ans = self.plugin_authz("/artifacts/pub/free/index.html", flag=True)    # anonymous
            self.assertEqual((ans["allowed"], ans["reason"]), (False, "denied"), body)
            _, ans = self.plugin_authz("/artifacts/pub/free/index.html", sid="alice")
            self.assertEqual((ans["allowed"], ans["reason"]), (False, "denied"), body)
            st, _, h = self._auth_h("/artifacts/pub/free/index.html", "alice")       # signed in
            self.assertEqual(st, 403, body)
            self.assertNotIn("Authorization", h)

    def test_keys_without_artifact_root_denied(self):
        # an ACL where the old per-directory lookup would find one lets nobody in
        acl = json.dumps({"owner": "alice@example.com", "users": ["alice@example.com"]}).encode()
        keys = ["u/x.html", "g/team-a/x.html", "acl/run.json", "other/run/x.html", "x.html"]
        with OBJECTS_LOCK:
            for d in ("u/", "g/team-a/", "acl/", "other/run/", ""):
                OBJECTS[d + ".acl.json"] = acl
            for k in keys:
                OBJECTS[k] = b"x"
        for k in keys:
            st, body, h = self._auth_h("/artifacts/" + k, "alice")
            self.assertEqual(st, 403, k)
            self.assertIn("Access required", body, k)
            self.assertNotIn("Authorization", h, k)
            st, ans = self.plugin_authz("/artifacts/" + k, sid="alice")
            self.assertEqual((st, ans["allowed"], ans["reason"]), (200, False, "denied"), k)

    def test_mcp_prefix_is_bad_path(self):
        with OBJECTS_LOCK:
            OBJECTS["_mcp/sessions/x.json"] = b"{}"
            OBJECTS["_mcp/sessions/.acl.json"] = json.dumps({"owner": "alice@example.com"}).encode()
        for sid in ("alice", None):
            st, body, h = self._auth_h("/artifacts/_mcp/sessions/x.json", sid)
            self.assertEqual(st, 404, sid)
            self.assertIn("Nothing here", body)
            self.assertNotIn("Authorization", h)
        st, _ = self.plugin_authz("/artifacts/_mcp/sessions/x.json", sid="alice")
        self.assertEqual(st, 400)

    def test_approval_for_a_nested_file_writes_only_the_root_acl(self):
        USERS["dora"] = ("dora@example.com", "aaaa")
        with OBJECTS_LOCK:
            OBJECTS["u/secret/assets/app.css"] = b"body{}"
        uri = "/artifacts/u/secret/assets/app.css"
        st, page, _ = self.auth(uri, "dora")
        self.assertEqual(st, 403)
        csrf = re.search(r'name=csrf value="([^"]+)"', page).group(1)
        st, page, _ = http(self.base + "/_gate/request", method="POST",
                           data=urllib.parse.urlencode({"csrf": csrf, "artifact": uri}),
                           headers={"Content-Type": "application/x-www-form-urlencoded"},
                           cookie="sid=dora")
        self.assertEqual(st, 200)
        with OBJECTS_LOCK:
            req_keys = [k for k in OBJECTS if k.startswith("_gate/req/")]
            acls_before = sorted(k for k in OBJECTS if k.endswith(".acl.json"))
        self.assertEqual(len(req_keys), 1)              # the root ACL's owner is asked
        rec = json.loads(OBJECTS[req_keys[0]])
        self.assertEqual((rec["owner"], rec["artifact"]), ("owner@example.com", uri))
        token = self.gate.make_action_token(rec["id"], "approve", self.gate._KEY, int(time.time()))
        st, _, _ = self._post_action("approve", token)
        self.assertEqual(st, 200)
        with OBJECTS_LOCK:
            acls_after = sorted(k for k in OBJECTS if k.endswith(".acl.json"))
            root = json.loads(OBJECTS["u/secret/.acl.json"])
        self.assertEqual(acls_after, acls_before)       # no ACL object created
        self.assertEqual(acls_after, ["u/secret/.acl.json"])
        self.assertIn("dora@example.com", root["users"])
        for u in (uri, "/artifacts/u/secret/report.html"):
            st, _, _ = self.auth(u, "dora")
            self.assertEqual(st, 200, u)

    def test_guest_identity_refused_on_every_endpoint(self):
        guest = "guest_example.org#EXT#@tenant.example"
        USERS["guest"] = (guest, "11111111-2222-4333-8444-555555555555")
        with OBJECTS_LOCK:
            acl = json.loads(OBJECTS["u/secret/.acl.json"])
            acl["users"].append(guest.lower())          # listed, and in the listed group
            OBJECTS["u/secret/.acl.json"] = json.dumps(acl).encode()
        log = self.capture_log()
        for uri in ("/artifacts/u/secret/report.html", "/artifacts/pub/free/index.html"):
            st, body, h = self._auth_h(uri, "guest")
            self.assertEqual(st, 403, uri)
            self.assertIn("Access refused", body)
            self.assertNotIn("Request access", body)
            self.assertNotIn("Authorization", h)
            st, ans = self.plugin_authz(uri, sid="guest", flag=True)
            self.assertEqual((st, ans["allowed"], ans["reason"], ans["user"]["id"]),
                             (200, False, "denied", None), uri)
        st, body, _ = http(self.base + "/_gate/request", method="POST",
                           data=urllib.parse.urlencode({"csrf": "x",
                                                        "artifact": "/artifacts/u/secret/report.html"}),
                           headers={"Content-Type": "application/x-www-form-urlencoded"},
                           cookie="sid=guest")
        self.assertEqual(st, 403)
        self.assertIn("Access refused", body)
        rid = self._pending_request("dave@example.com")
        token = self.gate.make_action_token(rid, "approve", self.gate._KEY, int(time.time()))
        st, body, _ = http(self.base + "/_gate/approve?token=" + urllib.parse.quote(token, safe=""),
                           cookie="sid=guest")
        self.assertEqual(st, 403)
        self.assertIn("Access refused", body)
        st, _, _ = http(self.base + "/_gate/approve", method="POST",
                        data=urllib.parse.urlencode({"token": token}),
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        cookie="sid=guest")
        self.assertEqual(st, 403)
        with OBJECTS_LOCK:
            self.assertEqual(json.loads(OBJECTS[f"_gate/req/{rid}.json"])["status"], "pending")
        self.assertIn("identity refused (guest account)", log.getvalue())


if __name__ == "__main__":
    unittest.main()
