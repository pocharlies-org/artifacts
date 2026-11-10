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
import json
import os
import re
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http import client as http_client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ------------------------------------------------------------------ fake MinIO (path style) ----
OBJECTS = {}
TAGS = {}          # key -> {tag: value}, served on GET <key>?tagging (ILM ttl)
OBJECTS_LOCK = threading.Lock()
LAST_MODIFIED = "Wed, 21 Oct 2026 07:28:00 GMT"


class MinioHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _key(self):
        path = urllib.parse.urlsplit(self.path).path
        return urllib.parse.unquote(path[len("/artifacts/"):])

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
            return self._reply(200, xml.encode())
        with OBJECTS_LOCK:
            body = OBJECTS.get(self._key())
        if body is None:
            return self._reply(404, b"NoSuchKey")
        self._reply(200, body)

    def do_HEAD(self):
        with OBJECTS_LOCK:
            exists = self._key() in OBJECTS
        self.send_response(200 if exists else 404)
        if exists:
            self.send_header("Last-Modified", LAST_MODIFIED)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_PUT(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n)
        with OBJECTS_LOCK:
            OBJECTS[self._key()] = body
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _reply(self, status, body):
        self.send_response(status)
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
        self.gate._acl_cache.clear()
        # pub artifact without ACL; private artifact with ACL (owner + bob's group); ACL for it
        OBJECTS["pub/free/index.html"] = b"<h1>free</h1>"
        OBJECTS["team/secret/report.html"] = b"<h1>secret</h1>"
        OBJECTS["team/secret/.acl.json"] = json.dumps({
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
                    "/artifacts/team/secret/does-not-exist.html"):     # ACL allows alice, object absent
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
        uri = "/artifacts/team/secret/report.html"
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
            st, _, h = self._auth_h("/artifacts/team/secret/report.html", sid)
            self.assertEqual(st, code)
            self.assertNotIn("Authorization", h)
            self.assertNotIn("X-Amz-Date", h)

    def test_s3_subresource_or_override_query_refused(self):
        for q in ("response-content-type=text/html", "Response-Content-Disposition=x",
                  "tagging", "versionId=abc", "X-Amz-Expires=60"):
            st, _, h = self._auth_h("/artifacts/team/secret/report.html?" + q, "alice")
            self.assertEqual(st, 404, q)
            self.assertNotIn("Authorization", h, q)

    def test_query_allow_list_every_query_refused(self):
        # finding 1: ?lambdaArn= used to reach MinIO's GetObjectLambdaHandler signed by the
        # gate. The allow-list is empty: every query form answers the same 404, unsigned, for an
        # allowed reader (alice) on GET and HEAD.
        for q in ("lambdaArn=arn:minio:s3-object-lambda::x:webhook", "acl", "ACL", "%61cl",
                  "acl%00", "%20acl", "acl&acl", "v=1&v=2", "acl;x=1", ";", "", "v=2&tab="):
            for method in ("GET", "HEAD"):
                st, _, h = self._auth_h("/artifacts/team/secret/report.html?" + q, "alice",
                                        method=method)
                self.assertEqual(st, 404, (q, method))
                self.assertNotIn("Authorization", h, q)
                self.assertNotIn("X-Amz-Date", h, q)
        # the same read without a query is still allowed and signed
        st, _, h = self._auth_h("/artifacts/team/secret/report.html", "alice")
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
                                        "X-Forwarded-Uri": "/artifacts/team/secret/report.html",
                                        hdr: val},
                               cookie="sid=alice")
            self.assertEqual(st, 400, hdr)
            self.assertNotIn("Authorization", h, hdr)
            self.assertNotIn("X-Amz-Date", h, hdr)
        # anonymous with the header: refused the same way (before the identity call)
        st, _, _ = http(self.auth_base + "/_gate/auth",
                        headers={"X-Forwarded-Method": "GET",
                                 "X-Forwarded-Uri": "/artifacts/team/secret/report.html",
                                 "X-Amz-Checksum-Mode": "ENABLED"})
        self.assertEqual(st, 400)

    def test_anonymous_gets_401(self):
        st, _, _ = self.auth("/artifacts/pub/free/index.html", None)
        self.assertEqual(st, 401)

    def test_private_acl_user_allowed(self):
        st, _, _ = self.auth("/artifacts/team/secret/report.html", "alice")
        self.assertEqual(st, 200)

    def test_private_acl_group_member_allowed(self):
        st, _, _ = self.auth("/artifacts/team/secret/report.html", "bob")
        self.assertEqual(st, 200)

    def test_private_acl_non_member_denied_with_page(self):
        # owner user has no groups claim -> group-only ACL denies (overage rule), but owner is
        # listed? owner@ is not in users; use a user not in the ACL at all:
        USERS["carol"] = ("carol@example.com", "aaaa")
        st, body, _ = self.auth("/artifacts/team/secret/report.html", "carol")
        self.assertEqual(st, 403)
        self.assertIn("Request access", body)
        self.assertIn("team/secret/report.html", body)

    def test_missing_artifact_same_403_page_as_denied(self):
        USERS["carol2"] = ("carol2@example.com", "aaaa")
        st1, b1, _ = self.auth("/artifacts/team/secret/report.html", "carol2")
        st2, b2, _ = self.auth("/artifacts/team/secret/does-not-exist.html", "carol2")
        self.assertEqual((st1, st2), (403, 403))
        # identical shape: both pages only echo the path the visitor asked for (no new info) and
        # both offer Request access; nothing distinguishes "missing" from "not allowed".
        self.assertIn("Request access", b2)
        self.assertIn("does-not-exist", b2)  # the requested path itself is shown (not a leak)

    def test_acl_file_never_served(self):
        st, _, _ = self.auth("/artifacts/team/secret/.acl.json", "alice")
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
                                 "X-Forwarded-Uri": "/artifacts/team/secret/report.html",
                                 "X-Auth-Request-Email": "alice@example.com"})
        self.assertEqual(st, 401)

    # -- listener split  ------------------------------------
    def test_auth_endpoint_not_served_on_public_listener(self):
        # The public route (8080) can never drive the decision: even a well-formed forwardAuth
        # request with a valid session 404s on the public listener, so a misrouted IngressRoute
        # cannot reach /_gate/auth through the public surface.
        st, _, _ = http(self.base + "/_gate/auth",
                        headers={"X-Forwarded-Method": "GET",
                                 "X-Forwarded-Uri": "/artifacts/team/secret/report.html"},
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
        st, page, _ = self.auth("/artifacts/team/secret/report.html", "dave")
        self.assertEqual(st, 403)
        csrf = re.search(r'name=csrf value="([^"]+)"', page).group(1)
        # 2) dave requests access
        st, page, _ = http(self.base + "/_gate/request", method="POST",
                           data=urllib.parse.urlencode({"csrf": csrf,
                                                        "artifact": "/artifacts/team/secret/report.html"}),
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
            acl = json.loads(OBJECTS["team/secret/.acl.json"])
        self.assertIn("dave@example.com", acl["users"])
        # 7) token is now single-use: replay fails
        st, body, _ = http(url, method="POST", data=urllib.parse.urlencode({"token": token}),
                           headers={"Content-Type": "application/x-www-form-urlencoded"},
                           cookie="sid=owner")
        self.assertEqual(st, 410)
        self.assertIn("already <b>approved</b>", body,
                      "replay page must read 'already approved', not the raw action verb")
        # 8) dave can now read (forwardAuth allows)
        st, _, _ = self.auth("/artifacts/team/secret/report.html", "dave")
        self.assertEqual(st, 200)

    def test_deny_flow_leaves_acl_untouched(self):
        USERS["erin"] = ("erin@example.com", "aaaa")
        st, page, _ = self.auth("/artifacts/team/secret/report.html", "erin")
        csrf = re.search(r'name=csrf value="([^"]+)"', page).group(1)
        st, _, _ = http(self.base + "/_gate/request", method="POST",
                       data=urllib.parse.urlencode({"csrf": csrf,
                                                    "artifact": "/artifacts/team/secret/report.html"}),
                       headers={"Content-Type": "application/x-www-form-urlencoded"},
                       cookie="sid=erin")
        with OBJECTS_LOCK:
            rec = json.loads(OBJECTS[next(k for k in OBJECTS if k.startswith("_gate/req/"))])
        acl_before = OBJECTS["team/secret/.acl.json"]
        token = self.gate.make_action_token(rec["id"], "deny", self.gate._KEY, 1_800_000_000)
        st, _, _ = http(self.base + "/_gate/deny", method="POST",
                        data=urllib.parse.urlencode({"token": token}),
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        cookie="sid=owner")
        self.assertEqual(st, 200)
        with OBJECTS_LOCK:
            self.assertEqual(OBJECTS["team/secret/.acl.json"], acl_before)
            self.assertEqual(json.loads(OBJECTS[f"_gate/req/{rec['id']}.json"])["status"], "deny")

    def _pending_request(self, requester):
        rid = self.gate.REQUESTS.create(requester, "/artifacts/team/secret/report.html",
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
        acl_before = OBJECTS["team/secret/.acl.json"]
        token = self.gate.make_action_token(rid, "deny", self.gate._KEY, 1_800_000_000)
        st, body, _ = self._post_action("approve", token)
        self.assertEqual(st, 410)
        self.assertIn("Link invalid", body)
        st, _, _ = http(self.base + "/_gate/approve?token=" + urllib.parse.quote(token, safe=""),
                        cookie="sid=owner")
        self.assertEqual(st, 410)
        with OBJECTS_LOCK:
            self.assertEqual(json.loads(OBJECTS[f"_gate/req/{rid}.json"])["status"], "pending")
            self.assertEqual(OBJECTS["team/secret/.acl.json"], acl_before)
        # the right endpoint still works with the same token
        st, _, _ = self._post_action("deny", token)
        self.assertEqual(st, 200)
        with OBJECTS_LOCK:
            self.assertEqual(json.loads(OBJECTS[f"_gate/req/{rid}.json"])["status"], "deny")
            self.assertEqual(OBJECTS["team/secret/.acl.json"], acl_before)

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
                          json.loads(OBJECTS["team/secret/.acl.json"])["users"])

    def test_request_access_missing_artifact_uniform_response_no_state(self):
        USERS["frank"] = ("frank@example.com", "aaaa")
        st, page, _ = self.auth("/artifacts/team/secret/ghost.html", "frank")
        csrf = re.search(r'name=csrf value="([^"]+)"', page).group(1)
        st, page2, _ = http(self.base + "/_gate/request", method="POST",
                            data=urllib.parse.urlencode({"csrf": csrf,
                                                         "artifact": "/artifacts/team/secret/ghost.html"}),
                           headers={"Content-Type": "application/x-www-form-urlencoded"},
                           cookie="sid=frank")
        self.assertEqual(st, 200)
        self.assertIn("Request sent", page2)            # same page as the real request
        with OBJECTS_LOCK:
            self.assertEqual([k for k in OBJECTS if k.startswith("_gate/req/")], [])  # nothing recorded

    def test_request_access_rate_limited(self):
        USERS["gina"] = ("gina@example.com", "aaaa")
        for i in range(2):                                # GATE_RATE_LIMIT_MAX=2
            st, page, _ = self.auth("/artifacts/team/secret/report.html", "gina")
            csrf = re.search(r'name=csrf value="([^"]+)"', page).group(1)
            st, _, _ = http(self.base + "/_gate/request", method="POST",
                            data=urllib.parse.urlencode({"csrf": csrf,
                                                         "artifact": "/artifacts/team/secret/report.html"}),
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                            cookie="sid=gina")
            self.assertEqual(st, 200, f"request {i}")
        st, page, _ = self.auth("/artifacts/team/secret/report.html", "gina")
        csrf = re.search(r'name=csrf value="([^"]+)"', page).group(1)
        st, page, _ = http(self.base + "/_gate/request", method="POST",
                           data=urllib.parse.urlencode({"csrf": csrf,
                                                        "artifact": "/artifacts/team/secret/report.html"}),
                           headers={"Content-Type": "application/x-www-form-urlencoded"},
                           cookie="sid=gina")
        self.assertEqual(st, 429)
        self.assertIn("Too many requests", page)

    def test_csrf_rejected_on_foreign_or_stale_token(self):
        USERS["hank"] = ("hank@example.com", "aaaa")
        st, page, _ = self.auth("/artifacts/team/secret/report.html", "hank")
        csrf = re.search(r'name=csrf value="([^"]+)"', page).group(1)
        # hank replays his token but claims another artifact
        st, _, _ = http(self.base + "/_gate/request", method="POST",
                        data=urllib.parse.urlencode({"csrf": csrf,
                                                     "artifact": "/artifacts/team/secret/other.html"}),
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        cookie="sid=hank")
        self.assertEqual(st, 403)
        # bob steals hank's token
        st, _, _ = http(self.base + "/_gate/request", method="POST",
                        data=urllib.parse.urlencode({"csrf": csrf,
                                                     "artifact": "/artifacts/team/secret/report.html"}),
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        cookie="sid=bob")
        self.assertEqual(st, 403)

    def test_healthz(self):
        st, body, _ = http(self.base + "/_gate/healthz")
        self.assertEqual((st, body), (200, "ok"))

    def test_gate_pages_have_csp_and_no_store(self):
        USERS["ivy"] = ("ivy@example.com", "aaaa")
        st, _, hdrs = self.auth("/artifacts/team/secret/report.html", "ivy")
        self.assertEqual(st, 403)
        self.assertIn("default-src 'none'", hdrs.get("Content-Security-Policy", ""))
        self.assertEqual(hdrs.get("Cache-Control"), "no-store")

    def test_expired_acl_denies(self):
        OBJECTS["team/secret/.acl.json"] = json.dumps(
            {"owner": "owner@example.com", "users": ["alice@example.com"],
             "expires": "2020-01-01"}).encode()
        self.gate._acl_cache.clear()
        st, _, _ = self.auth("/artifacts/team/secret/report.html", "alice")
        self.assertEqual(st, 403)


    def test_keepalive_connection_stays_in_sync_after_405(self):
        # Regression (found live): the gate's 405 path answered without reading the
        # request body. Traefik reuses backend keep-alive connections and BaseHTTPRequestHandler
        # does not drain bodies, so the leftover body byte became the first byte of the NEXT
        # request line on that connection (in the cluster: method 'xPOST' -> 501). Two requests
        # on ONE connection must both get their real 405, never a 501 from a corrupted request line.
        hostport = self.base.split("//", 1)[1]
        conn = http_client.HTTPConnection(hostport, timeout=10)
        self.addCleanup(conn.close)
        conn.request("PUT", "/artifacts/x.txt", body="x")
        r = conn.getresponse()
        self.assertEqual(r.status, 405)
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
        st, ans = self.plugin_authz("/artifacts/team/secret/report.html", sid="alice")
        self.assertEqual(st, 200)
        self.assertTrue(ans["allowed"], ans)
        self.assertEqual(ans["user"]["id"], "alice@example.com")
        self.assertEqual(ans["user"]["name"], "Alice Example")   # id_token `name` claim
        self.assertFalse(ans["user"]["anonymous"])
        self.assertEqual(ans["artifact"]["key"], "team/secret/report.html")

    def test_plugin_authz_name_falls_back_to_email(self):
        st, ans = self.plugin_authz("/artifacts/team/secret/report.html", sid="owner")
        self.assertEqual((st, ans["allowed"]), (200, True))
        self.assertEqual(ans["user"]["name"], "owner@example.com")   # no id_token from the proxy

    def test_plugin_authz_expired_not_leaked_to_strangers(self):
        OBJECTS["team/secret/.acl.json"] = json.dumps(
            {"owner": "owner@example.com", "users": ["alice@example.com"],
             "expires": "2020-01-01"}).encode()
        self.gate._acl_cache.clear()
        # bob is in no listed group: same answer as for a live artifact he is not on
        st, ans = self.plugin_authz("/artifacts/team/secret/report.html", sid="bob")
        self.assertEqual((st, ans["allowed"], ans["reason"]), (200, False, "not-listed"))
        self.assertEqual((ans["artifact"]["expires"], ans["artifact"]["ttl"]), (None, None))

    def test_plugin_authz_allow_group_member(self):
        st, ans = self.plugin_authz("/artifacts/team/secret/report.html", sid="bob")
        self.assertEqual((st, ans["allowed"]), (200, True))
        self.assertEqual(ans["reason"], "group")

    def test_plugin_authz_bearer_token_accepted(self):
        # the gate forwards the visitor's Authorization bearer to oauth2-proxy (fake proxy maps
        # Bearer <sid> to the same user): identity still comes from the proxy's response only.
        st, ans = self.plugin_authz("/artifacts/team/secret/report.html", bearer="alice")
        self.assertEqual((st, ans["allowed"]), (200, True))
        self.assertEqual(ans["user"]["id"], "alice@example.com")

    def test_plugin_authz_deny_no_acl_outside_pub(self):
        st, ans = self.plugin_authz("/artifacts/team/noteam/x.html", sid="alice")
        self.assertEqual(st, 200)
        self.assertFalse(ans["allowed"])
        self.assertIn("no-acl", ans["reason"])

    def test_plugin_authz_deny_expired(self):
        OBJECTS["team/secret/.acl.json"] = json.dumps(
            {"owner": "owner@example.com", "users": ["alice@example.com"],
             "expires": "2020-01-01"}).encode()
        self.gate._acl_cache.clear()
        st, ans = self.plugin_authz("/artifacts/team/secret/report.html", sid="alice")
        self.assertEqual((st, ans["allowed"]), (200, False))
        self.assertEqual(ans["reason"], "expired")

    def test_plugin_authz_expiry_from_acl(self):
        OBJECTS["team/secret/.acl.json"] = json.dumps(
            {"owner": "owner@example.com", "users": ["alice@example.com"],
             "expires": "2030-01-02"}).encode()
        self.gate._acl_cache.clear()
        st, ans = self.plugin_authz("/artifacts/team/secret/report.html", sid="alice")
        self.assertTrue(ans["allowed"])
        self.assertTrue(ans["artifact"]["expires"].startswith("2030-01-02"))

    def test_plugin_authz_expiry_from_ttl_tag(self):
        # no ACL expires: ttl tag + Last-Modified compose the ILM expiry (docs/plugins.md §4)
        TAGS["team/secret/report.html"] = {"ttl": "7"}
        st, ans = self.plugin_authz("/artifacts/team/secret/report.html", sid="alice")
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
        st, ans = self.plugin_authz("/artifacts/team/secret/report.html", flag=True)
        self.assertEqual(st, 200)
        self.assertFalse(ans["allowed"])
        self.assertEqual(ans["reason"], "unauthenticated")

    def test_plugin_authz_pub_signed_in_allowed(self):
        st, ans = self.plugin_authz("/artifacts/pub/free/index.html", sid="alice")
        self.assertEqual((st, ans["allowed"]), (200, True))

    def test_plugin_authz_traversal_400(self):
        for art in ("/artifacts/pub/../team/secret/report.html",
                    "/artifacts/team/secret/../../etc/passwd"):
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
        st, _ = self.plugin_authz("/artifacts/team/secret/.acl.json", sid="alice")
        self.assertEqual(st, 400)

    def test_plugin_authz_bad_artifact_400(self):
        st, _ = self.plugin_authz("/elsewhere/x.html", sid="alice")
        self.assertEqual(st, 400)
        st, _ = self.plugin_authz("not-a-path", sid="alice")
        self.assertEqual(st, 400)

    def test_plugin_authz_not_on_public_listener(self):
        # fail-closed listener split: the public listener 404s the decision endpoints
        st, _, _ = http(self.base + "/_gate/plugin/authz", method="POST",
                     data=json.dumps({"artifact": "/artifacts/team/secret/report.html"}),
                     headers={"Content-Type": "application/json"}, cookie="sid=alice")
        self.assertEqual(st, 404)

    def test_plugin_authz_get_not_allowed(self):
        st, _ = self.plugin_authz("/artifacts/team/secret/report.html", sid="alice", method="GET")
        self.assertEqual(st, 405)

    def test_plugin_authz_proxy_error_fails_closed(self):
        st, _ = self.plugin_authz("/artifacts/pub/free/index.html", sid="prefonly", flag=True)
        self.assertEqual(st, 500)

    def test_plugin_authz_allowed_but_object_missing(self):
        st, ans = self.plugin_authz("/artifacts/team/secret/ghost.html", sid="alice")
        self.assertEqual((st, ans["allowed"]), (200, False))
        self.assertEqual(ans["reason"], "object-missing")


if __name__ == "__main__":
    unittest.main()
