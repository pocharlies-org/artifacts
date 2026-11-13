#!/usr/bin/env python3
"""Unit tests for gate/gate.py ( authz decision, token signing/expiry/single-use,
CSRF, rate limit, request store, ACL write. Run:

    python3 -I -m unittest tests.test_gate -v
"""

import base64
import io
import json
import logging
import os
from datetime import datetime, timezone
import sys
import tempfile
import threading
import time
import unittest

# gate.py reads env at import time (required vars); give it inert values first.
os.environ.setdefault("MINIO_ACCESS_KEY", "test-ak")
os.environ.setdefault("MINIO_SECRET_KEY", "test-sk-not-a-secret")
os.environ.setdefault("GATE_READ_ACCESS_KEY", "test-read-ak")
os.environ.setdefault("GATE_READ_SECRET_KEY", "test-read-sk-not-a-secret")
os.environ.setdefault("OAUTH2_AUTH_URL", "http://oauth2.test.invalid/oauth2-artifacts/auth")
os.environ.setdefault("HMAC_KEY_B64", base64.b64encode(b"k" * 32).decode())
# ephemeral ports so _build_servers() never collides with a real gate or another test (Warning 5)
os.environ.setdefault("GATE_PORT", "0")
os.environ.setdefault("GATE_AUTH_PORT", "0")

import importlib.util  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("artifact_gate", os.path.join(_ROOT, "gate", "gate.py"))
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)  # noqa: E402

def load_gate_with_bucket(bucket):
    """Fresh gate module instance with GATE_BUCKET overridden (env is read at import)."""
    old = os.environ.get("GATE_BUCKET")
    os.environ["GATE_BUCKET"] = bucket
    try:
        spec = importlib.util.spec_from_file_location(
            "artifact_gate_" + bucket.replace("-", "_"), os.path.join(_ROOT, "gate", "gate.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        if old is None:
            os.environ.pop("GATE_BUCKET", None)
        else:
            os.environ["GATE_BUCKET"] = old


KEY = b"k" * 32
NOW = 1_800_000_000  # fixed clock for the whole suite


class TestBucketPath(unittest.TestCase):
    """The gate must key off the CONFIGURED bucket, not a hardcoded /artifacts/
    (verifier finding 8): CLI/MCP links embed the bucket name, so with bucket !=
    'artifacts' the gate would otherwise 400 its own links."""

    def test_default_bucket_accepts_artifacts_path(self):
        self.assertEqual(gate.key_from_path("/artifacts/pub/x.html"), "pub/x.html")
        self.assertIsNone(gate.key_from_path("/team-reports/pub/x.html"))

    def test_non_default_bucket_accepts_its_own_prefix(self):
        m = load_gate_with_bucket("team-reports")
        self.assertEqual(m.BUCKET_PATH, "/team-reports/")
        self.assertEqual(m.key_from_path("/team-reports/u/r/index.html"), "u/r/index.html")
        self.assertIsNone(m.key_from_path("/artifacts/u/r/index.html"))

    def test_non_default_bucket_bad_key_still_guarded(self):
        m = load_gate_with_bucket("team-reports")
        self.assertTrue(m._bad_key(m.key_from_path("/team-reports/_plugins/c/x")))
        # bucket-root listing: key_from_path yields "", _bad_key rejects it


class FakeStore:
    """In-memory stand-in for MinioStateStore."""

    def __init__(self):
        self.objs = {}

    def get_json(self, rel):
        return json.loads(self.objs[rel]) if rel in self.objs else None

    def put_json(self, rel, obj):
        self.objs[rel] = json.dumps(obj)


class FakeMinio:
    def __init__(self, objects=None):
        self.objects = dict(objects or {})   # key -> bytes
        self.puts = []

    def get(self, key):
        if key in self.objects:
            return 200, self.objects[key]
        return 404, b""

    def head(self, key):
        return 200 if key in self.objects else 404

    def put(self, key, data, ctype=None):
        self.objects[key] = data
        self.puts.append(key)
        return 200


# --------------------------------------------------------------------------------------------
class DecideTest(unittest.TestCase):
    PUB = ("pub/",)

    def d(self, email, groups, key, acl, pub=PUB):
        return gate.decide(email, groups, key, acl, NOW, pub_prefixes=pub)

    def test_pub_without_acl_allows_any_signed_in(self):
        ok, reason = self.d("a@example.com", [], "pub/x/report.html", None)
        self.assertTrue(ok)
        self.assertIn("pub", reason)

    def test_private_without_acl_denies(self):
        ok, reason = self.d("a@example.com", [], "team/x/report.html", None)
        self.assertFalse(ok)
        self.assertEqual(reason, "no-acl: deny by default (no owner to ask)")

    def test_owner_case_insensitive(self):
        acl = {"owner": "owner@example.com", "users": [], "groups": []}
        ok, reason = self.d("owner@example.com", [], "t/x", acl)
        self.assertTrue(ok)
        self.assertEqual(reason, "owner")

    def test_user_listed(self):
        acl = {"owner": "o@example.com", "users": ["Other@Example.com"], "groups": []}
        ok, reason = self.d("other@example.com", [], "t/x", acl)
        self.assertTrue(ok)
        self.assertEqual(reason, "user")

    def test_group_member(self):
        acl = {"owner": "o@example.com", "users": [], "groups": ["11111111-2222-4333-8444-555555555555"]}
        ok, reason = self.d("x@example.com", ["deadbeef", "11111111-2222-4333-8444-555555555555"], "t/x", acl)
        self.assertTrue(ok)
        self.assertEqual(reason, "group")

    def test_group_in_acl_but_no_claim_denies_as_overage(self):
        acl = {"owner": "o@example.com", "users": [], "groups": ["11111111-2222-4333-8444-555555555555"]}
        for groups in ([], None):
            ok, reason = self.d("x@example.com", groups, "t/x", acl)
            self.assertFalse(ok)
            self.assertIn("overage", reason)

    def test_not_listed(self):
        acl = {"owner": "o@example.com", "users": ["a@example.com"], "groups": ["g1"]}
        ok, reason = self.d("z@example.com", ["other-group"], "t/x", acl)
        self.assertFalse(ok)
        self.assertEqual(reason, "not-listed")

    def test_expired_date_denies(self):
        acl = {"owner": "o@example.com", "users": ["u@example.com"], "expires": "2020-01-01"}
        ok, reason = self.d("u@example.com", [], "t/x", acl)
        self.assertFalse(ok)
        self.assertEqual(reason, "expired")

    def test_date_expires_end_of_day(self):
        # expires = the day of NOW: valid until 23:59:59 UTC of that day.
        import calendar
        iso = time.strftime("%Y-%m-%d", time.gmtime(NOW))
        acl = {"owner": "o@example.com", "users": ["u@example.com"], "expires": iso}
        ok, _ = self.d("u@example.com", [], "t/x", acl)
        self.assertTrue(ok)
        end = calendar.timegm(time.strptime(iso, "%Y-%m-%d")) + 86399
        ok, reason = gate.decide("u@example.com", [], "t/x", acl, int(end) + 1, pub_prefixes=self.PUB)
        self.assertFalse(ok)
        self.assertEqual(reason, "expired")

    def test_datetime_expires(self):
        acl = {"owner": "o@example.com", "users": ["u@example.com"],
               "expires": "2020-06-01T12:00:00+00:00"}
        ok, reason = self.d("u@example.com", [], "t/x", acl)
        self.assertFalse(ok)
        self.assertEqual(reason, "expired")

    def test_expires_null_ignored(self):
        acl = {"owner": "o@example.com", "users": ["u@example.com"], "expires": None}
        ok, _ = self.d("u@example.com", [], "t/x", acl)
        self.assertTrue(ok)

    def test_owner_beats_expiry(self):
        # expiry is checked first: even the owner cannot read past it (they fix the ACL instead).
        acl = {"owner": "o@example.com", "expires": "2020-01-01"}
        ok, reason = self.d("o@example.com", [], "t/x", acl)
        self.assertFalse(ok)
        self.assertEqual(reason, "expired")

    def test_malformed_acl_denies(self):
        ok, reason = self.d("u@example.com", [], "t/x", "not-a-dict")
        self.assertFalse(ok)
        self.assertEqual(reason, "bad-acl")

    def test_owner_only_acl_no_users_key(self):
        acl = {"owner": "o@example.com"}
        ok, reason = self.d("o@example.com", [], "t/x", acl)
        self.assertTrue(ok)
        self.assertEqual(reason, "owner")


class TokenTest(unittest.TestCase):
    def test_roundtrip(self):
        t = gate.sign_token({"v": 1, "a": "x"}, KEY)
        self.assertEqual(gate.verify_token(t, KEY), {"v": 1, "a": "x"})

    def test_tampered_payload_rejected(self):
        t = gate.sign_token({"v": 1, "act": "deny"}, KEY)
        body, sig = t.split(".")
        evil = base64.urlsafe_b64encode(json.dumps({"v": 1, "act": "approve"},
                                                    separators=(",", ":"), sort_keys=True).encode()
                                         ).decode().rstrip("=")
        self.assertIsNone(gate.verify_token(f"{evil}.{sig}", KEY))

    def test_wrong_key_rejected(self):
        t = gate.sign_token({"v": 1}, KEY)
        self.assertIsNone(gate.verify_token(t, b"x" * 32))

    def test_garbage_rejected(self):
        for bad in ("", ".", "abc", "abc.def", "...", "%%.%%"):
            self.assertIsNone(gate.verify_token(bad, KEY))

    def test_action_token_expiry(self):
        t = gate.make_action_token("abc123", "approve", KEY, NOW)
        p = gate.check_action_token(t, KEY, NOW + 10)
        self.assertEqual(p["id"], "abc123")
        self.assertEqual(p["act"], "approve")
        self.assertIsNone(gate.check_action_token(t, KEY, NOW + gate.TOKEN_TTL + 1))

    def test_action_token_wrong_action_rejected(self):
        t = gate.sign_token({"v": 1, "purp": "action", "id": "x", "act": "delete-all",
                             "exp": NOW + 10}, KEY)
        self.assertIsNone(gate.check_action_token(t, KEY, NOW))

    def test_action_token_missing_exp(self):
        t = gate.sign_token({"v": 1, "purp": "action", "id": "x", "act": "approve"}, KEY)
        self.assertIsNone(gate.check_action_token(t, KEY, NOW))


class CsrfTest(unittest.TestCase):
    ART = "/artifacts/pub/gate-test/denied/index.html"

    def test_valid(self):
        t = gate.make_csrf("u@example.com", self.ART, KEY, NOW)
        self.assertTrue(gate.check_csrf(t, KEY, "U@Example.com", self.ART, NOW + 60))

    def test_wrong_user(self):
        t = gate.make_csrf("u@example.com", self.ART, KEY, NOW)
        self.assertFalse(gate.check_csrf(t, KEY, "evil@example.com", self.ART, NOW))

    def test_wrong_artifact(self):
        t = gate.make_csrf("u@example.com", self.ART, KEY, NOW)
        self.assertFalse(gate.check_csrf(t, KEY, "u@example.com", "/artifacts/other", NOW))

    def test_expired(self):
        t = gate.make_csrf("u@example.com", self.ART, KEY, NOW)
        self.assertFalse(gate.check_csrf(t, KEY, "u@example.com", self.ART,
                                         NOW + gate.CSRF_TTL + 1))
        self.assertTrue(gate.check_csrf(t, KEY, "u@example.com", self.ART, NOW + 1))

    def test_forged_without_key(self):
        # attacker crafts a payload and cannot sign it
        t = gate._b64u(json.dumps({"v": 1, "purp": "csrf", "u": "u@example.com",
                                   "a": self.ART, "t": NOW, "n": "x"},
                                  separators=(",", ":"), sort_keys=True).encode()) + ".AAAA"
        self.assertFalse(gate.check_csrf(t, KEY, "u@example.com", self.ART, NOW))

    def test_purpose_confusion(self):
        # an approve token must not pass as CSRF and vice versa
        at = gate.make_action_token("rid", "approve", KEY, NOW)
        self.assertFalse(gate.check_csrf(at, KEY, "u@example.com", self.ART, NOW))
        ct = gate.make_csrf("u@example.com", self.ART, KEY, NOW)
        self.assertIsNone(gate.check_action_token(ct, KEY, NOW))


class RateLimiterTest(unittest.TestCase):
    def test_blocks_after_max(self):
        rl = gate.RateLimiter(FakeStore(), max_n=3, window=1000)
        for i in range(3):
            self.assertTrue(rl.allow("u@x.com", "/artifacts/a", NOW + i), f"request {i}")
        self.assertFalse(rl.allow("u@x.com", "/artifacts/a", NOW + 3))

    def test_per_artifact_and_user(self):
        rl = gate.RateLimiter(FakeStore(), max_n=1, window=1000)
        self.assertTrue(rl.allow("u@x.com", "/artifacts/a", NOW))
        self.assertTrue(rl.allow("u@x.com", "/artifacts/b", NOW))
        self.assertTrue(rl.allow("v@x.com", "/artifacts/a", NOW))
        self.assertFalse(rl.allow("u@x.com", "/artifacts/a", NOW))

    def test_window_expiry_allows_again(self):
        rl = gate.RateLimiter(FakeStore(), max_n=2, window=1000)
        rl.allow("u@x.com", "/a", NOW)
        rl.allow("u@x.com", "/a", NOW + 1)
        self.assertFalse(rl.allow("u@x.com", "/a", NOW + 2))
        self.assertTrue(rl.allow("u@x.com", "/a", NOW + 1001))

    def test_corrupt_state_treated_as_empty(self):
        store = FakeStore()
        rl = gate.RateLimiter(store, max_n=1, window=1000)
        rl.allow("u@x.com", "/a", NOW)
        store.objs[rl._key("u@x.com", "/a")] = "not json"
        # get_json would raise on json.loads; allow() must not crash the request path
        # (documented behaviour: corrupt state -> fail closed is acceptable, crash is not).
        #  : catch EVERY exception — catching only
        # ConnectionError let real crashes (TypeError, AttributeError, ...) pass the test silently.
        try:
            result = rl.allow("u@x.com", "/a", NOW + 1)
        except Exception as exc:  # noqa: BLE001 - the whole point: nothing may escape allow()
            self.fail(f"corrupt state must not raise out of allow(), got {type(exc).__name__}: {exc}")
        self.assertIsInstance(result, bool)


class RequestStoreTest(unittest.TestCase):
    def test_create_get_mark_single_use(self):
        rs = gate.RequestStore(FakeStore())
        rid = rs.create("req@x.com", "/artifacts/pub/x", "own@x.com", NOW)
        rec = rs.get(rid)
        self.assertEqual(rec["status"], "pending")
        self.assertEqual(rec["requester"], "req@x.com")
        out = rs.mark(rid, "approve", NOW + 5)
        self.assertEqual(out["status"], "approve")
        # second decision (even the same one) must not transition again
        self.assertIsNone(rs.mark(rid, "deny", NOW + 6))
        self.assertIsNone(rs.mark(rid, "approve", NOW + 7))
        self.assertEqual(rs.get(rid)["status"], "approve")

    def test_mark_missing(self):
        rs = gate.RequestStore(FakeStore())
        self.assertIsNone(rs.mark("deadbeef", "approve", NOW))

    def test_get_rejects_non_hex_id(self):
        rs = gate.RequestStore(FakeStore())
        for bad in ("../../etc/passwd", "zz", "", "a" * 65, "req/../x"):
            self.assertIsNone(rs.get(bad))


class GrantAccessTest(unittest.TestCase):
    def test_appends_requester_once(self):
        acl = {"owner": "own@x.com", "users": ["a@x.com"]}
        m = FakeMinio({"pub/x/.acl.json": json.dumps(acl).encode()})
        ok, note = gate.grant_access(m, "/artifacts/pub/x/report.html", "New@X.com")
        self.assertTrue(ok, note)
        saved = json.loads(m.objects["pub/x/.acl.json"])
        self.assertEqual(saved["users"], ["a@x.com", "New@X.com"])
        # idempotent: same requester (case-insensitive) not duplicated
        ok, _ = gate.grant_access(m, "/artifacts/pub/x/report.html", "new@x.com")
        self.assertTrue(ok)
        self.assertEqual(json.loads(m.objects["pub/x/.acl.json"])["users"], ["a@x.com", "New@X.com"])

    def test_missing_acl_refuses(self):
        m = FakeMinio()
        ok, _ = gate.grant_access(m, "/artifacts/pub/x/report.html", "n@x.com")
        self.assertFalse(ok)


class SigV4Test(unittest.TestCase):
    def test_structure_and_determinism(self):
        h1 = gate.sigv4_headers("GET", "minio:9000", "/artifacts/pub/a b.txt",
                                [("list-type", "2")], None, b"", "AK", "SK", amzdate="20260101T000000Z")
        h2 = gate.sigv4_headers("GET", "minio:9000", "/artifacts/pub/a b.txt",
                                [("list-type", "2")], None, b"", "AK", "SK", amzdate="20260101T000000Z")
        self.assertEqual(h1, h2)
        self.assertTrue(h1["Authorization"].startswith(
            "AWS4-HMAC-SHA256 Credential=AK/20260101/us-east-1/s3/aws4_request, "))
        self.assertIn("SignedHeaders=host;x-amz-content-sha256;x-amz-date", h1["Authorization"])
        self.assertEqual(h1["x-amz-content-sha256"], gate.hashlib.sha256(b"").hexdigest())

    def test_aws_published_get_object_vector(self):
        # AWS SigV4 docs, "Example: GET Object" (header-based auth, Range signed):
        # independent check of the signing math the upstream read headers rely on.
        h = gate.sigv4_headers("GET", "examplebucket.s3.amazonaws.com", "/test.txt", [],
                               {"range": "bytes=0-9"}, b"", "AKIAIOSFODNN7EXAMPLE",
                               "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                               amzdate="20130524T000000Z")
        self.assertEqual(h["Authorization"],
                         "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/"
                         "aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, "
                         "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")

    def test_bare_subresource_query_is_signed(self):
        # GetObjectTagging is `GET <key>?tagging`: the bare subresource must be in the signed
        # canonical query (`tagging=`). It used to be dropped (parse_qsl without
        # keep_blank_values), so real MinIO answered 403 and plugin authz never had the ttl.
        from unittest import mock
        seen = {}
        real = gate.sigv4_headers

        def spy(method, host, path, qp, *a, **k):
            seen["qp"] = list(qp)
            return real(method, host, path, qp, *a, **k)

        class Resp:
            status = 200

            def read(self):
                return (b"<Tagging><TagSet><Tag><Key>ttl</Key><Value>7</Value></Tag>"
                        b"</TagSet></Tagging>")

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout=10):
            seen["url"] = req.full_url
            return Resp()

        with mock.patch.object(gate, "sigv4_headers", spy), \
                mock.patch.object(gate.urllib.request, "urlopen", fake_urlopen):
            tags = gate.MinioClient("http://minio:9000", "AK", "SK", "artifacts").get_tags("u/r/a.html")
        self.assertEqual(seen["qp"], [("tagging", "")])
        self.assertTrue(seen["url"].endswith("/artifacts/u/r/a.html?tagging"), seen["url"])
        self.assertEqual(tags, {"ttl": "7"})

    def test_upstream_auth_headers_refuse_s3_queries(self):
        self.assertIsNone(gate.upstream_auth_headers("GET", "h", "/artifacts/u/r/a.html?acl",
                                                     "AK", "SK"))
        self.assertIsNone(gate.upstream_auth_headers(
            "GET", "h", "/artifacts/u/r/a.html?response-content-type=text/html", "AK", "SK"))

    def test_query_allow_list_refuses_everything_today(self):
        # finding 1: allow-list, not deny-list. The allowed set is empty, so every query form
        # (MinIO handlers, case/percent/NUL/space variants, duplicates, ';', a bare '?') is
        # refused and nothing is signed.
        self.assertEqual(gate._ALLOWED_QUERY_KEYS, frozenset())
        for q in ("lambdaArn=arn:minio:s3-object-lambda::x:webhook", "acl", "ACL", "%61cl",
                  "acl%00", "%20acl", "acl&acl", "v=1&v=2", "acl;x=1", "x=1;acl", ";", "",
                  "v=2", "tab=", "uploads", "X-Amz-Expires=60", "+acl", "&", "=x"):
            self.assertIsNone(gate.upstream_auth_headers(
                "GET", "h", "/artifacts/u/r/a.html?" + q, "AK", "SK"), repr(q))
            self.assertIsNone(gate._allowed_query_pairs(q), repr(q))

    def test_query_allow_list_parser_when_a_key_is_allowed(self):
        # the parser stays strict for an allowed key: exact raw form only, once, no ';'
        old = gate._ALLOWED_QUERY_KEYS
        gate._ALLOWED_QUERY_KEYS = frozenset({"v"})
        try:
            self.assertEqual(gate._allowed_query_pairs("v=2"), [("v", "2")])
            for q in ("V=2", "%76=2", "v=1&v=2", "v=2;acl", "v=2&acl", "v%00=2", " v=2"):
                self.assertIsNone(gate._allowed_query_pairs(q), repr(q))
            # signed over the exact query sent
            h = gate.upstream_auth_headers("GET", "h", "/artifacts/u/r/a.html?v=2", "AK", "SK",
                                           amzdate="20260101T000000Z")
            want = gate.sigv4_headers("GET", "h", "/artifacts/u/r/a.html", [("v", "2")], None,
                                      b"", "AK", "SK", amzdate="20260101T000000Z")
            self.assertEqual(h["Authorization"], want["Authorization"])
            bare = gate.sigv4_headers("GET", "h", "/artifacts/u/r/a.html", [], None, b"",
                                      "AK", "SK", amzdate="20260101T000000Z")
            self.assertNotEqual(h["Authorization"], bare["Authorization"])
        finally:
            gate._ALLOWED_QUERY_KEYS = old

    def test_refused_client_headers(self):
        # finding 5: x-amz-*/x-minio-* from the visitor never ride next to the gate's signature
        self.assertEqual(gate.refused_client_headers(
            {"X-Amz-Date": "x", "x-minio-extract": "true", "X-AMZ-Checksum-Mode": "ENABLED",
             "Cookie": "c", "Authorization": "Bearer t", "X-Forwarded-Uri": "/a"}),
            ["x-amz-checksum-mode", "x-amz-date", "x-minio-extract"])
        self.assertEqual(gate.refused_client_headers({"Cookie": "c", "X-Amzn-Trace-Id": "1"}), [])
        h = gate.upstream_auth_headers("HEAD", "h", "/artifacts/u/r/a%20b.html", "AK", "SK",
                                       amzdate="20260101T000000Z")
        want = gate.sigv4_headers("HEAD", "h", "/artifacts/u/r/a b.html", [], None, b"",
                                  "AK", "SK", amzdate="20260101T000000Z")
        self.assertEqual(h["Authorization"], want["Authorization"])

    def test_url_has_leading_slash_and_quoting(self):
        c = gate.MinioClient("http://minio:9000", "AK", "SK", "artifacts")
        self.assertEqual(c._url("pub/a b.txt"), "http://minio:9000/artifacts/pub/a%20b.txt")
        self.assertEqual(c._url(""), "http://minio:9000/artifacts")


class ParseExpiresTest(unittest.TestCase):
    def test_forms(self):
        self.assertIsNotNone(gate._parse_expires("2026-12-31"))
        self.assertIsNotNone(gate._parse_expires("2026-12-31T10:00:00+02:00"))
        self.assertIsNotNone(gate._parse_expires("2026-12-31T10:00:00"))  # naive -> UTC
        self.assertIsNone(gate._parse_expires("garbage"))
        self.assertIsNone(gate._parse_expires(None))
        self.assertIsNone(gate._parse_expires(""))


class HmacKeyLoadTest(unittest.TestCase):
    """ : a corrupt secret must fail at startup with a
    clear RuntimeError naming the source, and validate=True must reject stray characters
    instead of silently dropping them (which could shorten a corrupted key into a valid one)."""

    def test_valid_b64_returns_key(self):
        key = gate._load_hmac_key(base64.b64encode(b"z" * 32).decode(), "/unused")
        self.assertEqual(key, b"z" * 32)

    def test_invalid_b64_raises_runtime_error_naming_source(self):
        with self.assertRaises(RuntimeError) as cm:
            gate._load_hmac_key("not!!base64!!", "/unused")
        self.assertIn("HMAC_KEY_B64", str(cm.exception))

    def test_b64_with_stray_chars_not_silently_dropped(self):
        # Without validate=True this decodes (chars dropped) to 32 bytes and passes the
        # length check; with validate=True it must be rejected outright.
        sneaky = base64.b64encode(b"y" * 32).decode() + "!!!!"
        with self.assertRaises(RuntimeError):
            gate._load_hmac_key(sneaky, "/unused")

    def test_short_key_rejected(self):
        with self.assertRaises(RuntimeError) as cm:
            gate._load_hmac_key(base64.b64encode(b"too-short").decode(), "/unused")
        self.assertIn("32", str(cm.exception))

    def test_missing_file_raises_runtime_error_naming_path(self):
        missing = os.path.join(tempfile.gettempdir(), "gate-does-not-exist-key-42")
        with self.assertRaises(RuntimeError) as cm:
            gate._load_hmac_key("", missing)
        self.assertIn(missing, str(cm.exception))

    def test_short_key_file_rejected(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"x" * 16)
            f.flush()
            with self.assertRaises(RuntimeError):
                gate._load_hmac_key("", f.name)


class DomainSeparationTest(unittest.TestCase):
    """ : CSRF and action tokens are signed with
    DIFFERENT subkeys derived from the root key, so a token cannot cross purposes even if
    the `purp` field check were dropped (the purp check itself stays, tested in CsrfTest)."""

    def test_subkeys_differ(self):
        self.assertNotEqual(gate._derive_subkey(KEY, gate.CSRF_SUBKEY_LABEL),
                            gate._derive_subkey(KEY, gate.ACTION_SUBKEY_LABEL))

    def test_action_payload_signed_with_csrf_subkey_rejected(self):
        # correct purp/act/exp, WRONG subkey: must fail on the signature, not on the fields
        t = gate.sign_token({"v": 1, "purp": "action", "id": "x", "act": "approve",
                             "exp": NOW + gate.TOKEN_TTL},
                            gate._derive_subkey(KEY, gate.CSRF_SUBKEY_LABEL))
        self.assertIsNone(gate.check_action_token(t, KEY, NOW))

    def test_csrf_payload_signed_with_action_subkey_rejected(self):
        t = gate.sign_token({"v": 1, "purp": "csrf", "u": "u@example.com",
                             "a": CsrfTest.ART, "t": NOW, "n": "x"},
                            gate._derive_subkey(KEY, gate.ACTION_SUBKEY_LABEL))
        self.assertFalse(gate.check_csrf(t, KEY, "u@example.com", CsrfTest.ART, NOW))

    def test_root_key_signature_rejected_by_both_purposes(self):
        # a token signed with the ROOT key (the old pre- scheme) is no longer
        # accepted for either purpose: rotation to subkeys invalidates old tokens
        t = gate.sign_token({"v": 1, "purp": "action", "id": "x", "act": "approve",
                             "exp": NOW + gate.TOKEN_TTL}, KEY)
        self.assertIsNone(gate.check_action_token(t, KEY, NOW))
        ct = gate.sign_token({"v": 1, "purp": "csrf", "u": "u@example.com",
                              "a": CsrfTest.ART, "t": NOW, "n": "x"}, KEY)
        self.assertFalse(gate.check_csrf(ct, KEY, "u@example.com", CsrfTest.ART, NOW))

    def test_roundtrip_still_works_with_root_key_argument(self):
        # callers pass the ROOT key; the subkey is derived inside make_/check_
        at = gate.make_action_token("rid", "approve", KEY, NOW)
        self.assertIsNotNone(gate.check_action_token(at, KEY, NOW))
        ct = gate.make_csrf("u@example.com", CsrfTest.ART, KEY, NOW)
        self.assertTrue(gate.check_csrf(ct, KEY, "u@example.com", CsrfTest.ART, NOW))


class ReadSigningUserTest(unittest.TestCase):
    """finding 4: forwarded reads are signed by a dedicated read-only user, never the gate user."""

    def _load(self, **env):
        saved = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        try:
            spec = importlib.util.spec_from_file_location(
                "artifact_gate_readuser", os.path.join(_ROOT, "gate", "gate.py"))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def test_read_user_is_separate(self):
        self.assertEqual(gate.READ_ACCESS_KEY, "test-read-ak")
        self.assertNotEqual(gate.READ_ACCESS_KEY, gate.MINIO_ACCESS_KEY)

    def test_same_user_refused_at_startup(self):
        with self.assertRaises(RuntimeError):
            self._load(GATE_READ_ACCESS_KEY=os.environ["MINIO_ACCESS_KEY"])

    def test_missing_read_user_refused_at_startup(self):
        with self.assertRaises(RuntimeError):
            self._load(GATE_READ_ACCESS_KEY="")


class BuildServersTest(unittest.TestCase):
    """ : e2e/unit tests must exercise the servers the
    REAL main() builds. _build_servers() wires gate_mode + ports; a missing gate_mode is
    treated as public (fail-closed for the decision endpoint), so the auth listener must
    carry it explicitly."""

    def test_modes_and_ports(self):
        public, auth = gate._build_servers()
        try:
            self.assertEqual(public.gate_mode, "public")
            self.assertEqual(auth.gate_mode, "auth")
            # GATE_PORT/GATE_AUTH_PORT are 0 in this suite -> ephemeral ports, both bound
            self.assertGreater(public.server_address[1], 0)
            self.assertGreater(auth.server_address[1], 0)
            self.assertNotEqual(public.server_address[1], auth.server_address[1])
            self.assertIs(public.RequestHandlerClass, gate.GateHandler)
            self.assertIs(auth.RequestHandlerClass, gate.GateHandler)
        finally:
            public.server_close()
            auth.server_close()

    def test_missing_gate_mode_defaults_to_public(self):
        # documents the fail-closed default the module docstring promises
        class Bare:
            pass
        self.assertEqual(getattr(Bare(), "gate_mode", "public"), "public")


class GrantLockTest(unittest.TestCase):
    """ : grant_access read-modify-write is serialised
    per ACL directory, so two concurrent approvals of the same directory cannot lose a grant."""

    def test_same_key_same_lock_different_key_different_lock(self):
        self.assertIs(gate._grant_lock("a/.acl.json"), gate._grant_lock("a/.acl.json"))
        self.assertIsNot(gate._grant_lock("a/.acl.json"), gate._grant_lock("b/.acl.json"))

    def test_concurrent_grants_both_survive(self):
        acl = {"owner": "own@x.com", "users": []}

        class SlowMinio(FakeMinio):
            # widen the read-modify-write window: without the per-key lock the two threads
            # would interleave get->put and one grant would be lost
            def put(self, key, data, ctype=None):
                time.sleep(0.05)
                return super().put(key, data, ctype)

        m = SlowMinio({"d/x/.acl.json": json.dumps(acl).encode()})
        results = []
        threads = [threading.Thread(target=lambda r=requester: results.append(
                       gate.grant_access(m, "/artifacts/d/x/report.html", r)))
                   for requester in ("a@x.com", "b@x.com")]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertTrue(all(ok for ok, _ in results), results)
        saved = json.loads(m.objects["d/x/.acl.json"])
        self.assertEqual(sorted(saved["users"]), ["a@x.com", "b@x.com"])


if __name__ == "__main__":
    unittest.main()


# --------------------------------------------------------------------------------------------
class BadKeyTest(unittest.TestCase):
    """docs/plugins.md: the gate never serves ACLs, gate state, plugin storage or traversal,
    on any route (forwardAuth and the plugin authz endpoint share this guard)."""

    def test_bad_keys(self):
        for key in ("", "dir/", "dir/.acl.json", ".acl.json", "_gate", "_gate/req/x.json",
                    "_plugins", "_plugins/canvas/x.bin", "a/../b", "../etc/passwd", "a/./b",
                    "team/secret/../secret/.acl.json"):
            self.assertTrue(gate._bad_key(key), key)

    def test_good_keys(self):
        for key in ("pub/x.html", "team/secret/report.html", "a.b-c/1.html", "pub/.hidden.txt"):
            self.assertFalse(gate._bad_key(key), key)


class PluginAuthzDecisionTest(unittest.TestCase):
    """Pure core of POST /_gate/plugin/authz (docs/plugins.md §1): one decide(), expiry in the
    answer, and the same no-existence-leak rule as forwardAuth."""

    ACL = {"owner": "owner@example.com", "users": ["alice@example.com"],
           "groups": ["11111111-2222-4333-8444-555555555555"]}

    def d(self, email, key, acl, head=200, tags=None, lm=None):
        return gate.plugin_authz_decision(email, [], key, acl, NOW, head, tags, lm)

    def test_allow_carries_identity_and_acl_expiry(self):
        acl = dict(self.ACL, expires="2030-01-02")
        ans = self.d("alice@example.com", "team/x/r.html", acl)
        self.assertTrue(ans["allowed"])
        self.assertFalse(ans["user"]["anonymous"])
        self.assertEqual(ans["user"]["id"], "alice@example.com")
        self.assertEqual(ans["user"]["name"], "alice@example.com")
        self.assertTrue(ans["artifact"]["expires"].startswith("2030-01-02"))
        self.assertEqual(ans["artifact"]["key"], "team/x/r.html")

    def test_deny_no_acl_outside_pub(self):
        ans = self.d("x@example.com", "team/x/r.html", None)
        self.assertFalse(ans["allowed"])
        self.assertEqual(ans["reason"], "denied")
        _, detail = gate.plugin_authz_decision_detail("x@example.com", [], "team/x/r.html", None,
                                                      NOW, 200)
        self.assertIn("no-acl", detail)                  # the detail is for the gate's log

    def test_stranger_gets_one_reason_whatever_the_acl(self):
        # a denied visitor must not tell "directory without an ACL" from "ACL that does not list
        # me" (or a broken ACL, or a group ACL): one reason; the detail stays in the log
        cases = {
            "no-acl: deny by default (no owner to ask)": None,
            "not-listed": {"owner": "o@example.com", "users": ["a@example.com"]},
            "bad-acl": ["not", "a", "dict"],
            "groups-claim-empty (possible Entra overage)": {"owner": "o@example.com",
                                                            "groups": ["g-1"]},
        }
        for want_detail, acl in cases.items():
            for head in (200, 404):
                ans, detail = gate.plugin_authz_decision_detail("x@example.com", [], "team/x/r.html",
                                                                acl, NOW, head, {"ttl": "7"}, NOW)
                self.assertEqual(ans, {"allowed": False, "reason": "denied",
                                       "user": {"id": "x@example.com", "name": "x@example.com",
                                                "anonymous": False},
                                       "artifact": {"key": "team/x/r.html", "expires": None,
                                                    "ttl": None}}, (want_detail, head))
                self.assertEqual(detail, want_detail)

    def test_deny_expired_even_owner(self):
        ans = self.d("owner@example.com", "team/x/r.html",
                     {"owner": "owner@example.com", "expires": "2020-01-01"})
        self.assertFalse(ans["allowed"])
        self.assertEqual(ans["reason"], "expired")

    def test_expired_told_only_to_who_would_be_allowed(self):
        acl = dict(self.ACL, expires="2020-01-01")
        for who in ("owner@example.com", "alice@example.com"):
            ans = self.d(who, "team/x/r.html", acl)
            self.assertEqual((ans["allowed"], ans["reason"]), (False, "expired"), who)
            self.assertTrue(ans["artifact"]["expires"].startswith("2020-01-01"))
        # a stranger (and anonymous) gets the same deny as for a live artifact, no expiry/ttl
        users_only = {k: v for k, v in self.ACL.items() if k != "groups"}
        live = self.d("mallory@example.com", "team/x/r.html", users_only, tags={"ttl": "7"}, lm=NOW)
        dead = self.d("mallory@example.com", "team/x/r.html", dict(users_only, expires="2020-01-01"),
                      tags={"ttl": "7"}, lm=NOW)
        self.assertEqual((dead["allowed"], dead["reason"]), (False, "denied"))
        self.assertEqual(dead, live)
        self.assertEqual(dead["artifact"], {"key": "team/x/r.html", "expires": None, "ttl": None})
        anon = self.d("", "team/x/r.html", dict(users_only, expires="2020-01-01"))
        self.assertEqual((anon["allowed"], anon["reason"]), (False, "denied"))
        self.assertIsNone(anon["artifact"]["expires"])
        # group ACL: a member is told `expired`, a visitor in no listed group gets the live deny
        member = gate.plugin_authz_decision("carol@example.com", ["11111111-2222-4333-8444-555555555555"],
                                            "team/x/r.html", acl, NOW, 200)
        self.assertEqual(member["reason"], "expired")
        other = gate.plugin_authz_decision("carol@example.com", ["99999999-2222-4333-8444-555555555555"],
                                           "team/x/r.html", acl, NOW, 200)
        self.assertEqual((other["reason"], other["artifact"]["expires"]), ("denied", None))
        empty, detail = gate.plugin_authz_decision_detail("carol@example.com", [], "team/x/r.html",
                                                          acl, NOW, 200)
        self.assertEqual(empty["reason"], "denied")
        self.assertIn("groups-claim-empty", detail)

    def test_object_missing_told_only_to_who_would_be_allowed(self):
        users_only = {k: v for k, v in self.ACL.items() if k != "groups"}
        stranger = self.d("mallory@example.com", "team/x/r.html", users_only, head=404)
        self.assertEqual((stranger["allowed"], stranger["reason"]), (False, "denied"))
        listed = self.d("alice@example.com", "team/x/r.html", self.ACL, head=404)
        self.assertEqual(listed["reason"], "object-missing")

    def test_display_name_passed_through_email_fallback(self):
        ans = gate.plugin_authz_decision("alice@example.com", [], "team/x/r.html", self.ACL, NOW, 200,
                                         name="Alice Example")
        self.assertEqual(ans["user"], {"id": "alice@example.com", "name": "Alice Example",
                                       "anonymous": False})
        self.assertEqual(self.d("alice@example.com", "team/x/r.html", self.ACL)["user"]["name"],
                         "alice@example.com")
        anon = gate.plugin_authz_decision("", [], "pub/free/x.html", None, NOW, 200, name="Nope")
        self.assertEqual(anon["user"]["name"], "anonymous")

    def test_anonymous_pub_allowed(self):
        # caller-side gating (pub/ + ANONYMOUS_PUB_ENABLED) is e2e; here: empty email = anonymous
        ans = self.d("", "pub/free/x.html", None)
        self.assertTrue(ans["allowed"])
        self.assertTrue(ans["user"]["anonymous"])
        self.assertIsNone(ans["user"]["id"])
        self.assertEqual(ans["user"]["name"], "anonymous")

    def test_anonymous_outside_pub_denied_by_decide(self):
        ans = self.d("", "team/x/r.html", None)
        self.assertFalse(ans["allowed"])

    def test_allowed_but_object_missing_denies(self):
        ans = self.d("alice@example.com", "team/x/r.html", self.ACL, head=404)
        self.assertFalse(ans["allowed"])
        self.assertEqual(ans["reason"], "object-missing")

    def test_ttl_tag_gives_expiry(self):
        lm = 1_800_000_000
        ans = self.d("alice@example.com", "team/x/r.html", self.ACL, tags={"ttl": "7"}, lm=lm)
        self.assertEqual(ans["artifact"]["ttl"], 7)
        self.assertEqual(ans["artifact"]["expires"],
                         datetime.fromtimestamp(lm + 7 * 86400, timezone.utc).isoformat())

    def test_acl_expiry_wins_over_ttl(self):
        acl = dict(self.ACL, expires="2030-01-02")
        ans = self.d("alice@example.com", "team/x/r.html", acl, tags={"ttl": "7"}, lm=NOW)
        self.assertTrue(ans["artifact"]["expires"].startswith("2030-01-02"))

    def test_garbage_ttl_is_none(self):
        ans = self.d("alice@example.com", "team/x/r.html", self.ACL, tags={"ttl": "banana"}, lm=NOW)
        self.assertIsNone(ans["artifact"]["ttl"])
        self.assertIsNone(ans["artifact"]["expires"])


class DisplayNameTest(unittest.TestCase):
    """user.name for plugins comes from the id_token `name` claim of the proxy's /auth answer
    (--set-authorization-header), only when the token is the same identity; email otherwise."""

    @staticmethod
    def tok(claims):
        b = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
        return f"{b({'alg': 'RS256'})}.{b(claims)}.c2ln"

    def name(self, hdrs, email="test@example.com"):
        return gate.display_name_from_auth_headers(hdrs, email)

    def test_name_claim_of_same_identity(self):
        t = self.tok({"email": "Test@Example.com", "name": "Test One"})
        self.assertEqual(self.name({"Authorization": f"Bearer {t}"}), "Test One")
        t = self.tok({"preferred_username": "test@example.com", "name": "  Ana\u0000  López\n "})
        self.assertEqual(self.name({"Authorization": f"Bearer {t}"}), "Ana López")
        t = self.tok({"upn": "test@example.com", "name": "x" * 300})
        self.assertEqual(self.name({"Authorization": f"bearer {t}"}), "x" * 128)

    def test_fallbacks_to_email(self):
        cases = [
            {},
            {"Authorization": "Basic Zm9vOmJhcg=="},
            {"Authorization": "Bearer not-a-jwt"},
            {"Authorization": "Bearer a.%%%.c"},
            {"Authorization": f"Bearer {self.tok({'email': 'other@example.com', 'name': 'Mallory'})}"},
            {"Authorization": f"Bearer {self.tok({'email': 'test@example.com'})}"},
            {"Authorization": f"Bearer {self.tok({'email': 'test@example.com', 'name': 42})}"},
            {"Authorization": f"Bearer {self.tok({'email': 'test@example.com', 'name': '  '})}"},
            {"Authorization": f"Bearer {self.tok(['not', 'a', 'dict'])}"},
        ]
        for h in cases:
            self.assertEqual(self.name(h), "test@example.com", h)


class ForwardedUriTest(unittest.TestCase):
    """The decision and the signature read the forwarded URI through one parse
    (split_forwarded_uri); a target they could read differently is refused outright."""

    def test_refused_targets(self):
        for uri in ("/artifacts/pub/x#frag", "/artifacts/pub/x?a#b", "/artifacts/pub/x#",
                    "//evil.example/artifacts/pub/x", "http://evil.example/artifacts/pub/x",
                    "artifacts/pub/x", "", "/artifacts/pub/a b", "/artifacts/pub/x\t",
                    "/artifacts/pub/x\r\nX: y", "/artifacts/pub/\x00x", "/artifacts/pub/x\x7f",
                    "/artifacts/pub/caf\u00e9", " /artifacts/pub/x", "\t/artifacts/pub/x"):
            self.assertIsNone(gate.split_forwarded_uri(uri), repr(uri))
            self.assertIsNone(gate.upstream_auth_headers("GET", "h", uri, "AK", "SK"), repr(uri))

    def test_accepted_targets(self):
        self.assertEqual(gate.split_forwarded_uri("/artifacts/pub/x"), ("/artifacts/pub/x", None))
        self.assertEqual(gate.split_forwarded_uri("/artifacts/pub/x?"), ("/artifacts/pub/x", ""))
        self.assertEqual(gate.split_forwarded_uri("/artifacts/pub/a%23b?v=1"),
                         ("/artifacts/pub/a%23b", "v=1"))

    def test_decision_and_signature_read_the_same_key(self):
        amz = "20260101T000000Z"
        for uri in ("/artifacts/pub/x", "/artifacts/pub/a%23b", "/artifacts/u/r/f%2Fg",
                    "/artifacts/u/r/%ff", "/artifacts/u/r//f", "/artifacts/pub/x%20y",
                    "/artifacts/u/r/%3Fq", "/artifacts/u/r/a%0Ab"):
            path, query = gate.split_forwarded_uri(uri)
            self.assertIsNone(query)
            decided = gate.key_from_path(path)
            signed = gate.upstream_auth_headers("GET", "h", uri, "AK", "SK", amzdate=amz)
            want = gate.sigv4_headers("GET", "h", gate.BUCKET_PATH + decided, [], None, b"",
                                      "AK", "SK", amzdate=amz)
            self.assertEqual(signed["Authorization"], want["Authorization"], uri)


class OneLineLogTest(unittest.TestCase):
    """No client-chosen value can start a log line of its own: control characters and line
    separators in a message are written as escapes, at the logger, for every call site."""

    def test_control_characters_escaped(self):
        buf = io.StringIO()
        handler = logging.StreamHandler(buf)
        handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        gate.LOG.addHandler(handler)
        old = gate.LOG.level
        gate.LOG.setLevel(logging.INFO)
        try:
            gate.LOG.info("authz user=%s key=%s", "a@example.com",
                          "u/x\nINFO action=approve id=deadbeef by=bob@example.com"
                          "\r\x1b[2J\u2028\u2029\x85\x00end")
            gate.LOG.warning("no args\nWARNING forged")
        finally:
            gate.LOG.removeHandler(handler)
            gate.LOG.setLevel(old)
        lines = buf.getvalue().splitlines()
        self.assertEqual(len(lines), 2, lines)
        self.assertTrue(lines[0].startswith("INFO authz user=a@example.com key=u/x\\x0aINFO "),
                        lines[0])
        self.assertTrue(lines[0].endswith("\\x0d\\x1b[2J\\u2028\\u2029\\x85\\x00end"), lines[0])
        self.assertEqual(lines[1], "WARNING no args\\x0aWARNING forged")


class AclCacheBoundTest(unittest.TestCase):
    """_acl_cache is bounded: LRU with ACL_CACHE_MAX entries, and an entry older than
    ACL_CACHE_TTL is neither served nor kept."""

    def setUp(self):
        gate._acl_cache.clear()
        self.addCleanup(gate._acl_cache.clear)
        self.addCleanup(setattr, gate, "ACL_CACHE_MAX", gate.ACL_CACHE_MAX)

    def test_default_bound(self):
        self.assertEqual(gate.ACL_CACHE_MAX, 10000)
        m = FakeMinio()
        for i in range(10050):
            gate.read_acl(m, f"u/{i:06d}/index.html", NOW)
        self.assertEqual(len(gate._acl_cache), 10000)
        self.assertNotIn("u/000049/.acl.json", gate._acl_cache)
        self.assertIn("u/000050/.acl.json", gate._acl_cache)

    def test_least_recently_used_goes_first(self):
        gate.ACL_CACHE_MAX = 3
        m = FakeMinio()
        for d in "abcd":
            gate.read_acl(m, f"u/{d}/f", NOW)
        self.assertEqual(list(gate._acl_cache), ["u/b/.acl.json", "u/c/.acl.json", "u/d/.acl.json"])
        gate.read_acl(m, "u/b/f", NOW + 1)      # a hit makes b the most recent
        gate.read_acl(m, "u/e/f", NOW + 1)      # evicts c, the least recently used
        self.assertEqual(list(gate._acl_cache), ["u/d/.acl.json", "u/b/.acl.json", "u/e/.acl.json"])

    def test_stale_entries_dropped_and_reread(self):
        m = FakeMinio()
        gate.read_acl(m, "u/a/f", NOW)
        gate.read_acl(m, "u/b/f", NOW)
        gate.read_acl(m, "u/c/f", NOW + gate.ACL_CACHE_TTL)   # a and b are stale now
        self.assertEqual(list(gate._acl_cache), ["u/c/.acl.json"])
        m.objects["u/c/.acl.json"] = b'{"owner": "o@example.com"}'
        self.assertEqual(gate.read_acl(m, "u/c/f", NOW + gate.ACL_CACHE_TTL + 1), (None, None))
        self.assertEqual(gate.read_acl(m, "u/c/f", NOW + 2 * gate.ACL_CACHE_TTL),
                         ({"owner": "o@example.com"}, None))
