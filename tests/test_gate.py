#!/usr/bin/env python3
"""Unit tests for gate/gate.py ( authz decision, token signing/expiry/single-use,
CSRF, rate limit, request store, ACL write. Run:

    python3 -I -m unittest tests.test_gate -v
"""

import base64
import hashlib
import http.client
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
from unittest import mock
import urllib.parse

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
    """In-memory store with S3 write semantics: an ETag per object version, a conditional PUT
    (If-Match) answers 412 when the object is not that version, and a PUT replaces the tag set
    (no x-amz-tagging: the object is left untagged)."""

    def __init__(self, objects=None, tags=None):
        self.objects = dict(objects or {})   # key -> bytes
        self.tags = {k: dict(v) for k, v in (tags or {}).items()}   # key -> {tag: value}
        self.puts = []
        self.gets = []
        self.put_calls = []                  # (key, if_match, tagging, status)

    @staticmethod
    def etag_of(body):
        return '"%s"' % hashlib.md5(body).hexdigest()

    def etag(self, key):
        return self.etag_of(self.objects[key])

    def get(self, key):
        self.gets.append(key)
        if key in self.objects:
            return 200, self.objects[key]
        return 404, b""

    def get_with_etag(self, key):
        status, body = self.get(key)       # the ETag of the version this read returned
        return status, body, (self.etag_of(body) if status == 200 else None)

    def get_tags_checked(self, key):
        if key not in self.objects:
            return None, "HTTP 404"
        return dict(self.tags.get(key, {})), None

    def head(self, key):
        return 200 if key in self.objects else 404

    def put(self, key, data, ctype=None, if_match=None, tagging=None):
        if if_match is not None and (key not in self.objects or self.etag(key) != if_match):
            self.put_calls.append((key, if_match, tagging, 412))
            return 412
        self.objects[key] = data
        self.tags[key] = dict(urllib.parse.parse_qsl(tagging)) if tagging else {}
        self.puts.append(key)
        self.put_calls.append((key, if_match, tagging, 200))
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
        ok, reason = self.d("a@example.com", [], "u/x/report.html", None)
        self.assertFalse(ok)
        self.assertEqual(reason, "no-acl: deny by default (no owner to ask)")

    def test_owner_case_insensitive(self):
        acl = {"owner": "owner@example.com", "users": [], "groups": []}
        ok, reason = self.d("owner@example.com", [], "u/r/x", acl)
        self.assertTrue(ok)
        self.assertEqual(reason, "owner")

    def test_user_listed(self):
        acl = {"owner": "o@example.com", "users": ["Other@Example.com"], "groups": []}
        ok, reason = self.d("other@example.com", [], "u/r/x", acl)
        self.assertTrue(ok)
        self.assertEqual(reason, "user")

    def test_group_member(self):
        acl = {"owner": "o@example.com", "users": [], "groups": ["11111111-2222-4333-8444-555555555555"]}
        ok, reason = self.d("x@example.com", ["deadbeef", "11111111-2222-4333-8444-555555555555"], "u/r/x", acl)
        self.assertTrue(ok)
        self.assertEqual(reason, "group")

    def test_group_in_acl_but_no_claim_denies_as_overage(self):
        acl = {"owner": "o@example.com", "users": [], "groups": ["11111111-2222-4333-8444-555555555555"]}
        for groups in ([], None):
            ok, reason = self.d("x@example.com", groups, "u/r/x", acl)
            self.assertFalse(ok)
            self.assertIn("overage", reason)

    def test_not_listed(self):
        acl = {"owner": "o@example.com", "users": ["a@example.com"], "groups": ["g1"]}
        ok, reason = self.d("z@example.com", ["other-group"], "u/r/x", acl)
        self.assertFalse(ok)
        self.assertEqual(reason, "not-listed")

    def test_expired_date_denies(self):
        acl = {"owner": "o@example.com", "users": ["u@example.com"], "expires": "2020-01-01"}
        ok, reason = self.d("u@example.com", [], "u/r/x", acl)
        self.assertFalse(ok)
        self.assertEqual(reason, "expired")

    def test_date_expires_end_of_day(self):
        # expires = the day of NOW: valid until 23:59:59 UTC of that day.
        import calendar
        iso = time.strftime("%Y-%m-%d", time.gmtime(NOW))
        acl = {"owner": "o@example.com", "users": ["u@example.com"], "expires": iso}
        ok, _ = self.d("u@example.com", [], "u/r/x", acl)
        self.assertTrue(ok)
        end = calendar.timegm(time.strptime(iso, "%Y-%m-%d")) + 86399
        ok, reason = gate.decide("u@example.com", [], "u/r/x", acl, int(end) + 1, pub_prefixes=self.PUB)
        self.assertFalse(ok)
        self.assertEqual(reason, "expired")

    def test_datetime_expires(self):
        acl = {"owner": "o@example.com", "users": ["u@example.com"],
               "expires": "2020-06-01T12:00:00+00:00"}
        ok, reason = self.d("u@example.com", [], "u/r/x", acl)
        self.assertFalse(ok)
        self.assertEqual(reason, "expired")

    def test_expires_null_ignored(self):
        acl = {"owner": "o@example.com", "users": ["u@example.com"], "expires": None}
        ok, _ = self.d("u@example.com", [], "u/r/x", acl)
        self.assertTrue(ok)

    def test_owner_beats_expiry(self):
        # expiry is checked first: even the owner cannot read past it (they fix the ACL instead).
        acl = {"owner": "o@example.com", "expires": "2020-01-01"}
        ok, reason = self.d("o@example.com", [], "u/r/x", acl)
        self.assertFalse(ok)
        self.assertEqual(reason, "expired")

    def test_malformed_acl_denies(self):
        ok, reason = self.d("u@example.com", [], "u/r/x", "not-a-dict")
        self.assertFalse(ok)
        self.assertEqual(reason, "bad-acl")

    def test_owner_only_acl_no_users_key(self):
        acl = {"owner": "o@example.com"}
        ok, reason = self.d("o@example.com", [], "u/r/x", acl)
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


    # every spelling of one object key is one artifact: index.html, %69ndex.html, ...
    ENCODED_VARIANTS = ("/artifacts/u/r/index.html", "/artifacts/u/r/%69ndex.html",
                        "/artifacts/u/r/%69%6E%64ex.html", "/artifacts/u/r/index%2ehtml",
                        "/artifacts/%75/r/index.html", "/artifacts/u/%72/index.html")

    def test_percent_encoded_variants_share_one_limit(self):
        rl = gate.RateLimiter(FakeStore(), max_n=2, window=1000)
        got = [rl.allow("u@x.com", v, NOW + i) for i, v in enumerate(self.ENCODED_VARIANTS)]
        self.assertEqual(got, [True, True, False, False, False, False])
        self.assertEqual(len({rl._key("u@x.com", v) for v in self.ENCODED_VARIANTS}), 1)
        # another file of the same artifact, or another user, has its own limit
        self.assertTrue(rl.allow("u@x.com", "/artifacts/u/r/other.html", NOW + 9))
        self.assertTrue(rl.allow("v@x.com", "/artifacts/u/r/%69ndex.html", NOW + 9))

    def test_per_requester_limit_across_artifacts(self):
        store = FakeStore()
        rl = gate.RateLimiter(store, max_n=3, window=1000, per_requester=True)
        self.assertEqual([rl.allow("u@x.com", None, NOW + i) for i in range(4)],
                         [True, True, True, False])
        self.assertTrue(rl.allow("v@x.com", None, NOW + 4))             # per user
        self.assertTrue(rl.allow("u@x.com", None, NOW + 1000))          # the window slides
        self.assertTrue(all(k.startswith("rq/") for k in store.objs), store.objs)

    def test_module_limits_and_their_defaults(self):
        self.assertEqual((gate.RATE_LIMITER.max_n, gate.RATE_LIMITER.per_requester), (5, False))
        self.assertEqual((gate.REQUESTER_LIMITER.max_n, gate.REQUESTER_LIMITER.window,
                          gate.REQUESTER_LIMITER.per_requester), (20, 86400, True))
        self.assertEqual(gate.REQUESTS.max_pending, 10)


class RequestCapsConfigTest(unittest.TestCase):
    """GATE_REQUESTER_RATE_LIMIT_MAX and GATE_OWNER_PENDING_MAX: whole numbers from 1 to
    999999, or the gate refuses to start (a typo never turns a limit off)."""

    def _load(self, **env):
        return ReadSigningUserTest._load(self, **env)

    def test_values_are_read(self):
        mod = self._load(GATE_REQUESTER_RATE_LIMIT_MAX="7", GATE_OWNER_PENDING_MAX=" 3 ")
        self.assertEqual((mod.REQUESTER_RATE_LIMIT_MAX, mod.OWNER_PENDING_MAX), (7, 3))
        self.assertEqual((mod.REQUESTER_LIMITER.max_n, mod.REQUESTS.max_pending), (7, 3))

    def test_invalid_values_refused_at_startup(self):
        for name in ("GATE_REQUESTER_RATE_LIMIT_MAX", "GATE_OWNER_PENDING_MAX"):
            for bad in ("0", "-1", "", "ten", "1.5", "1e3", "1000000", "07", "+5"):
                with self.subTest(name=name, value=bad), self.assertRaises(RuntimeError):
                    self._load(**{name: bad})


class RequestStoreTest(unittest.TestCase):
    def test_record_names_the_decoded_object_key(self):
        rs = gate.RequestStore(FakeStore())
        for v in RateLimiterTest.ENCODED_VARIANTS:
            rec = rs.get(rs.create("req@x.com", v, "own@x.com", NOW))
            self.assertEqual(rec["artifact"], "/artifacts/u/r/index.html", v)
        # one decode only: an encoded "%" or "/" stays encoded, so the grant reads the same key
        for raw, key in (("/artifacts/u/r/100%2541.html", "u/r/100%41.html"),
                         ("/artifacts/u/a%252Fb/c.html", "u/a%2Fb/c.html"),
                         ("/artifacts/u/r/%C3%A9%20x.html", "u/r/\u00e9 x.html")):
            rec = rs.get(rs.create("req@x.com", raw, "own@x.com", NOW))
            self.assertEqual(gate.key_from_path(rec["artifact"]), key, raw)
            self.assertEqual(gate.canonical_artifact_path(rec["artifact"]), rec["artifact"])
        self.assertIsNone(gate.canonical_artifact_path("/other/u/r/x.html"))

    def test_owner_pending_cap(self):
        store = FakeStore()
        rs = gate.RequestStore(store, max_pending=2, link_ttl=100)
        self.assertTrue(rs.reserve_owner_slot("Own@x.com", "a" * 32, NOW))
        self.assertTrue(rs.reserve_owner_slot("own@x.com", "b" * 32, NOW + 1))
        self.assertFalse(rs.reserve_owner_slot("own@x.com", "c" * 32, NOW + 2))      # at the cap
        self.assertTrue(rs.reserve_owner_slot("other@x.com", "c" * 32, NOW + 2))     # per owner
        rs.release_owner_slot("own@x.com", "a" * 32, NOW + 3)                       # decided
        self.assertTrue(rs.reserve_owner_slot("own@x.com", "d" * 32, NOW + 4))
        self.assertFalse(rs.reserve_owner_slot("own@x.com", "e" * 32, NOW + 5))
        # an entry whose links expired holds no place any more
        self.assertTrue(rs.reserve_owner_slot("own@x.com", "e" * 32, NOW + 101))
        # unreadable or malformed state reads as no open requests (never a crash)
        for junk in ("not json", json.dumps({"pending": "x"}), json.dumps([1]),
                     json.dumps({"pending": [["a", "b"], [1, 2], "x"]})):
            store.objs[rs._owner_rel("own@x.com")] = junk
            self.assertTrue(rs.reserve_owner_slot("own@x.com", "f" * 32, NOW + 200), junk)

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
        m = FakeMinio({"u/x/.acl.json": json.dumps(acl).encode()})
        ok, note = gate.grant_access(m, "/artifacts/u/x/report.html", "New@X.com")
        self.assertTrue(ok, note)
        saved = json.loads(m.objects["u/x/.acl.json"])
        self.assertEqual(saved["users"], ["a@x.com", "New@X.com"])
        # idempotent: same requester (case-insensitive) not duplicated
        ok, _ = gate.grant_access(m, "/artifacts/u/x/report.html", "new@x.com")
        self.assertTrue(ok)
        self.assertEqual(json.loads(m.objects["u/x/.acl.json"])["users"], ["a@x.com", "New@X.com"])

    def test_missing_acl_refuses(self):
        m = FakeMinio()
        ok, _ = gate.grant_access(m, "/artifacts/u/x/report.html", "n@x.com")
        self.assertFalse(ok)

    def test_pub_takes_no_grant_whatever_acl_exists(self):
        # pub/ is anonymous-readable by design: an approval never writes there, not even into
        # a stray ACL at a pub root, and nothing is read first
        acl = json.dumps({"owner": "own@x.com", "users": ["a@x.com"]}).encode()
        m = FakeMinio({"pub/x/.acl.json": acl, "pub/.acl.json": acl})
        for path in ("/artifacts/pub/x/report.html", "/artifacts/pub/x/a/b.css",
                     "/artifacts/pub/flat.html"):
            self.assertEqual(gate.grant_access(m, path, "new@x.com"),
                             (False, "pub/ takes no access grants"), path)
        self.assertEqual((m.gets, m.puts), ([], []))
        self.assertEqual(m.objects["pub/x/.acl.json"], acl)


class ConditionalGrantTest(unittest.TestCase):
    """grant_access is a conditional read-modify-write: read with the ETag, PUT with If-Match
    under _grant_lock, one retry on 412, a second 412 gives up; owner, unknown fields and the
    ACL's tags (ttl) are kept."""

    ACL = {"owner": "own@x.com", "users": ["a@x.com"], "groups": ["g1"],
           "expires": "2030-01-01", "x-note": {"kept": True}}
    KEY = "u/r/.acl.json"
    PATH = "/artifacts/u/r/sub/report.html"

    class RacingMinio(FakeMinio):
        """Another writer changes the ACL right after each of the gate's next reads of it,
        i.e. between the gate's GET and its PUT."""

        def __init__(self, *a, writers=(), **kw):
            super().__init__(*a, **kw)
            self.writers = list(writers)

        def get(self, key):
            out = super().get(key)
            if key.endswith(".acl.json") and self.writers:
                self.writers.pop(0)(self)
            return out

    @staticmethod
    def other_writer_adds(user):
        def write(m):
            acl = json.loads(m.objects["u/r/.acl.json"])
            acl["users"].append(user)
            m.objects["u/r/.acl.json"] = json.dumps(acl).encode()   # plain PUT: a new version
        return write

    def setUp(self):
        gate._acl_cache.clear()
        self.addCleanup(gate._acl_cache.clear)

    class LostReplyMinio(FakeMinio):
        """The ACL write raises ConnectionError like a lost reply: after applying it
        (applied=True) or without applying it; reads after the write can fail too."""

        def __init__(self, *a, applied=True, reads_after_fail=False, **kw):
            super().__init__(*a, **kw)
            self.applied, self.reads_after_fail, self.written = applied, reads_after_fail, False

        def put(self, key, data, ctype=None, if_match=None, tagging=None):
            if key.endswith(".acl.json"):
                if self.applied:
                    super().put(key, data, ctype, if_match=if_match, tagging=tagging)
                self.written = True
                raise ConnectionError(f"minio PUT {key}: IncompleteRead")
            return super().put(key, data, ctype, if_match=if_match, tagging=tagging)

        def get(self, key):
            if self.written and self.reads_after_fail:
                raise ConnectionError(f"minio GET {key}: timed out")
            return super().get(key)

    def test_lost_reply_on_an_applied_write_is_confirmed_by_one_re_read(self):
        m = self.LostReplyMinio({self.KEY: json.dumps(self.ACL).encode()},
                                tags={self.KEY: {"ttl": "7"}})
        self.assertEqual(gate.grant_access(m, self.PATH, "new@x.com"),
                         (True, "added (confirmed by a re-read after a lost reply)"))
        self.assertEqual(m.gets, [self.KEY, self.KEY])               # the read, then one re-read
        self.assertEqual(json.loads(m.objects[self.KEY])["users"], ["a@x.com", "new@x.com"])
        self.assertEqual(m.tags[self.KEY], {"ttl": "7"})

    def test_lost_reply_not_applied_is_an_unknown_outcome(self):
        m = self.LostReplyMinio({self.KEY: json.dumps(self.ACL).encode()}, applied=False)
        ok, note = gate.grant_access(m, self.PATH, "new@x.com")
        self.assertEqual((ok, note), (False, "put failed: minio PUT u/r/.acl.json: IncompleteRead"
                                             "; not listed on a re-read"))
        self.assertTrue(gate.grant_outcome_unknown(note))
        self.assertEqual(m.gets, [self.KEY, self.KEY])

    def test_lost_reply_and_a_failed_re_read_is_an_unknown_outcome(self):
        m = self.LostReplyMinio({self.KEY: json.dumps(self.ACL).encode()}, reads_after_fail=True)
        ok, note = gate.grant_access(m, self.PATH, "new@x.com")
        self.assertEqual((ok, note), (False, "put failed: minio PUT u/r/.acl.json: IncompleteRead"
                                             "; the confirming read failed too: minio GET "
                                             "u/r/.acl.json: timed out"))
        self.assertTrue(gate.grant_outcome_unknown(note))
        self.assertIn("new@x.com", json.loads(m.objects[self.KEY])["users"])   # it was applied

    class ServerErrorMinio(FakeMinio):
        """The ACL write answers a 5xx, after applying it (applied=True) or without applying it;
        reads after the write can fail too."""

        def __init__(self, *a, status=500, applied=False, reads_after_fail=False, **kw):
            super().__init__(*a, **kw)
            self.status, self.applied = status, applied
            self.reads_after_fail, self.written = reads_after_fail, False

        def put(self, key, data, ctype=None, if_match=None, tagging=None):
            if key.endswith(".acl.json"):
                if self.applied:
                    super().put(key, data, ctype, if_match=if_match, tagging=tagging)
                self.written = True
                self.put_calls.append((key, if_match, tagging, self.status))
                return self.status
            return super().put(key, data, ctype, if_match=if_match, tagging=tagging)

        def get(self, key):
            if self.written and self.reads_after_fail:
                raise ConnectionError(f"minio GET {key}: timed out")
            return super().get(key)

    def test_store_5xx_on_the_write_is_an_unknown_outcome_with_a_re_read(self):
        for status in (500, 503):
            # not applied: the re-read does not list the requester, the outcome stays unknown
            m = self.ServerErrorMinio({self.KEY: json.dumps(self.ACL).encode()}, status=status)
            ok, note = gate.grant_access(m, self.PATH, "new@x.com")
            self.assertEqual((ok, note), (False, f"put HTTP {status}; not listed on a re-read"))
            self.assertTrue(gate.grant_outcome_unknown(note))
            self.assertEqual(m.gets, [self.KEY, self.KEY])            # the read, then one re-read
            self.assertEqual(len([c for c in m.put_calls if c[3] == status]), 1)   # no retry
            # applied, then the 5xx: the re-read lists the requester, so the grant happened
            m = self.ServerErrorMinio({self.KEY: json.dumps(self.ACL).encode()}, status=status,
                                      applied=True, tags={self.KEY: {"ttl": "7"}})
            self.assertEqual(gate.grant_access(m, self.PATH, "new@x.com"),
                             (True, f"added (confirmed by a re-read after HTTP {status})"))
            self.assertEqual(json.loads(m.objects[self.KEY])["users"], ["a@x.com", "new@x.com"])
            # applied, and the re-read fails too: unknown, and the requester is in fact listed
            m = self.ServerErrorMinio({self.KEY: json.dumps(self.ACL).encode()}, status=status,
                                      applied=True, reads_after_fail=True)
            ok, note = gate.grant_access(m, self.PATH, "new@x.com")
            self.assertEqual((ok, note), (False, f"put HTTP {status}; the confirming read failed "
                                                 f"too: minio GET u/r/.acl.json: timed out"))
            self.assertTrue(gate.grant_outcome_unknown(note))

    def test_which_failed_grants_may_have_changed_the_acl(self):
        # unknown: a lost write reply (after the re-read), an exception raised inside the grant;
        # known to have changed nothing: every refusal before the write and every status code
        for note in ("put failed: minio PUT k: IncompleteRead; not listed on a re-read",
                     "put failed: minio PUT k: timed out; the confirming read failed too: x",
                     "unexpected RuntimeError", "put HTTP 500; not listed on a re-read",
                     "put HTTP 503; the confirming read failed too: x", "put HTTP 500"):
            self.assertTrue(gate.grant_outcome_unknown(note), note)
        for note in ("put HTTP 412", "put HTTP 403", "put HTTP 400", "put HTTP 404",
                     "put HTTP 409", "acl unreadable: missing",
                     "acl unreadable: minio GET k: IncompleteRead", "acl tags unreadable: HTTP 403",
                     "acl unreadable: users is not a list", "no artifact root", "bad artifact path",
                     "pub/ takes no access grants", "", None):
            self.assertFalse(gate.grant_outcome_unknown(note), note)

    def test_read_returns_acl_and_etag(self):
        m = FakeMinio({self.KEY: json.dumps(self.ACL).encode()})
        acl, etag, err = gate.read_acl_for_write(m, self.KEY)
        self.assertEqual((acl, etag, err), (self.ACL, m.etag(self.KEY), None))
        self.assertEqual(gate.read_acl_for_write(FakeMinio(), self.KEY), (None, None, "missing"))
        bad = FakeMinio({self.KEY: b"{not json"})
        self.assertEqual(gate.read_acl_for_write(bad, self.KEY)[2], "malformed JSON")

    def test_put_carries_if_match_of_the_read(self):
        m = FakeMinio({self.KEY: json.dumps(self.ACL).encode()})
        etag = m.etag(self.KEY)
        self.assertEqual(gate.grant_access(m, self.PATH, "new@x.com"), (True, "added"))
        self.assertEqual([(k, im, st) for k, im, _t, st in m.put_calls], [(self.KEY, etag, 200)])

    def test_owner_and_unknown_fields_are_kept(self):
        m = FakeMinio({self.KEY: json.dumps(self.ACL).encode()})
        gate.grant_access(m, self.PATH, "new@x.com")
        saved = json.loads(m.objects[self.KEY])
        self.assertEqual(saved, dict(self.ACL, users=["a@x.com", "new@x.com"]))

    def test_race_first_put_412_then_retry_keeps_both_writers(self):
        m = self.RacingMinio({self.KEY: json.dumps(self.ACL).encode()},
                             writers=[self.other_writer_adds("other@x.com")])
        self.assertEqual(gate.grant_access(m, self.PATH, "new@x.com"), (True, "added"))
        self.assertEqual([st for *_x, st in m.put_calls], [412, 200])
        saved = json.loads(m.objects[self.KEY])
        self.assertEqual(saved["users"], ["a@x.com", "other@x.com", "new@x.com"])
        self.assertEqual(saved["owner"], "own@x.com")

    def test_two_412_give_up_and_leave_the_other_writers_acl_untouched(self):
        m = self.RacingMinio({self.KEY: json.dumps(self.ACL).encode()},
                             writers=[self.other_writer_adds("o1@x.com"),
                                      self.other_writer_adds("o2@x.com")])
        self.assertEqual(gate.grant_access(m, self.PATH, "new@x.com"), (False, "put HTTP 412"))
        self.assertEqual([st for *_x, st in m.put_calls], [412, 412])
        self.assertEqual(json.loads(m.objects[self.KEY])["users"], ["a@x.com", "o1@x.com", "o2@x.com"])
        self.assertEqual(m.puts, [])

    def test_ttl_tag_is_sent_with_the_write(self):
        m = FakeMinio({self.KEY: json.dumps(self.ACL).encode()}, tags={self.KEY: {"ttl": "7"}})
        self.assertEqual(gate.grant_access(m, self.PATH, "new@x.com"), (True, "added"))
        self.assertEqual([t for _k, _im, t, _st in m.put_calls], ["ttl=7"])
        self.assertEqual(m.tags[self.KEY], {"ttl": "7"})
        # an untagged ACL stays untagged (no header at all)
        m = FakeMinio({self.KEY: json.dumps(self.ACL).encode()})
        gate.grant_access(m, self.PATH, "new@x.com")
        self.assertEqual([t for _k, _im, t, _st in m.put_calls], [None])

    def test_unreadable_tags_fail_closed(self):
        class NoTags(FakeMinio):
            def get_tags_checked(self, key):
                return None, "HTTP 403"
        m = NoTags({self.KEY: json.dumps(self.ACL).encode()}, tags={self.KEY: {"ttl": "7"}})
        self.assertEqual(gate.grant_access(m, self.PATH, "new@x.com"),
                         (False, "acl tags unreadable: HTTP 403"))
        self.assertEqual(m.put_calls, [])

    def test_no_etag_means_no_write(self):
        class NoEtag(FakeMinio):
            def get_with_etag(self, key):
                status, body, _ = super().get_with_etag(key)
                return status, body, None
        m = NoEtag({self.KEY: json.dumps(self.ACL).encode()})
        self.assertEqual(gate.grant_access(m, self.PATH, "new@x.com"),
                         (False, "acl unreadable: no ETag"))
        self.assertEqual(m.put_calls, [])

    def test_other_write_errors_are_not_retried(self):
        class Refused(FakeMinio):
            def put(self, key, data, ctype=None, if_match=None, tagging=None):
                self.put_calls.append((key, if_match, tagging, 403))
                return 403
        m = Refused({self.KEY: json.dumps(self.ACL).encode()})
        self.assertEqual(gate.grant_access(m, self.PATH, "new@x.com"), (False, "put HTTP 403"))
        self.assertEqual(len(m.put_calls), 1)

    def test_already_listed_writes_nothing(self):
        m = FakeMinio({self.KEY: json.dumps(self.ACL).encode()})
        self.assertEqual(gate.grant_access(m, self.PATH, "A@X.com"), (True, "already listed"))
        self.assertEqual(m.put_calls, [])


class MinioClientWriteTest(unittest.TestCase):
    """The client half of the conditional write: _call returns the response headers (the GET's
    ETag), and put() sends If-Match and x-amz-tagging as SigV4-signed headers."""

    def _client_with(self, status=200, body=b"", headers=None):
        seen = {}

        class Resp:
            def __init__(self):
                self.status, self.headers = status, headers or {}

            def read(self):
                return body

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout=10):
            seen["req"] = req
            return Resp()

        from unittest import mock
        patch = mock.patch.object(gate.urllib.request, "urlopen", fake_urlopen)
        patch.start()
        self.addCleanup(patch.stop)
        return gate.MinioClient("http://minio:9000", "AK", "SK", "artifacts"), seen

    def test_call_returns_response_headers_and_get_with_etag(self):
        c, _ = self._client_with(200, b"{}", {"ETag": '"abc"', "Content-Length": "2"})
        self.assertEqual(c._call("GET", "u/r/.acl.json"),
                         (200, b"{}", {"etag": '"abc"', "content-length": "2"}))
        self.assertEqual(c.get_with_etag("u/r/.acl.json"), (200, b"{}", '"abc"'))
        self.assertEqual(c.get("u/r/.acl.json"), (200, b"{}"))

    def test_put_signs_if_match_and_tagging(self):
        c, seen = self._client_with(200)
        self.assertEqual(c.put("u/r/.acl.json", b"{}", "application/json",
                               if_match='"abc"', tagging="ttl=7"), 200)
        req = seen["req"]
        sent = {k.lower(): v for k, v in req.header_items()}
        self.assertEqual((sent["if-match"], sent["x-amz-tagging"]), ('"abc"', "ttl=7"))
        self.assertIn("SignedHeaders=content-type;host;if-match;x-amz-content-sha256;"
                      "x-amz-date;x-amz-tagging,", sent["authorization"])
        want = gate.sigv4_headers("PUT", "minio:9000", "/artifacts/u/r/.acl.json", [],
                                  {"content-type": "application/json", "if-match": '"abc"',
                                   "x-amz-tagging": "ttl=7"}, b"{}", "AK", "SK",
                                  amzdate=sent["x-amz-date"])
        self.assertEqual(sent["authorization"], want["Authorization"])

    def test_plain_put_has_neither_header(self):
        c, seen = self._client_with(200)
        c.put("_gate/req/x.json", b"{}", "application/json")
        sent = {k.lower() for k, _ in seen["req"].header_items()}
        self.assertFalse({"if-match", "x-amz-tagging"} & sent, sent)

    def test_cut_or_malformed_reply_is_a_connection_error(self):
        # http.client.HTTPException is not an OSError: a store reply cut short (IncompleteRead)
        # or malformed must still come out as ConnectionError, which every caller handles, and
        # carry the class name only, never bytes of the reply
        from unittest import mock

        class Cut:
            status, headers = 200, {}

            def read(self):
                raise http.client.IncompleteRead(b'{"owner": "partial-reply-bytes', 16)

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        class CutBody:
            def read(self, *a):
                raise http.client.IncompleteRead(b"partial-reply-bytes", 16)

            def close(self):
                pass

        def http_error(req, timeout=10):
            raise gate.urllib.error.HTTPError(req.full_url, 412, "Precondition Failed", {}, CutBody())

        c = gate.MinioClient("http://minio:9000", "AK", "SK", "artifacts")
        for opener in (lambda req, timeout=10: Cut(), http_error,
                       mock.Mock(side_effect=http.client.BadStatusLine("partial-reply-bytes"))):
            with mock.patch.object(gate.urllib.request, "urlopen", opener):
                with self.assertRaises(ConnectionError) as cm:
                    c.get_with_etag("u/r/.acl.json")
                msg = str(cm.exception)
                self.assertTrue(msg.startswith("minio GET u/r/.acl.json: "), msg)
                self.assertNotIn("partial-reply-bytes", msg)
                with self.assertRaises(ConnectionError):
                    c.put("u/r/.acl.json", b"{}", "application/json", if_match='"e"')
                tags, err = c.get_tags_checked("u/r/.acl.json")
                self.assertIsNone(tags)
                self.assertNotIn("partial-reply-bytes", err)
        with mock.patch.object(gate.urllib.request, "urlopen", lambda req, timeout=10: Cut()):
            with self.assertRaises(ConnectionError) as cm:
                c.get("u/r/.acl.json")
        self.assertEqual(str(cm.exception), "minio GET u/r/.acl.json: IncompleteRead")

    def test_tags_checked_fails_closed_where_get_tags_is_best_effort(self):
        c, _ = self._client_with(403, b"<Error/>")
        self.assertEqual(c.get_tags_checked("u/r/.acl.json"), (None, "HTTP 403"))
        self.assertEqual(c.get_tags("u/r/.acl.json"), {})


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
            headers = {}

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
            def put(self, key, data, *args, **kwargs):
                time.sleep(0.05)
                return super().put(key, data, *args, **kwargs)

        m = SlowMinio({"u/x/.acl.json": json.dumps(acl).encode()})
        results = []
        threads = [threading.Thread(target=lambda r=requester: results.append(
                       gate.grant_access(m, "/artifacts/u/x/report.html", r)))
                   for requester in ("a@x.com", "b@x.com")]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertTrue(all(ok for ok, _ in results), results)
        saved = json.loads(m.objects["u/x/.acl.json"])
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
        ans = self.d("alice@example.com", "u/x/r.html", acl)
        self.assertTrue(ans["allowed"])
        self.assertFalse(ans["user"]["anonymous"])
        self.assertEqual(ans["user"]["id"], "alice@example.com")
        self.assertEqual(ans["user"]["name"], "alice@example.com")
        self.assertTrue(ans["artifact"]["expires"].startswith("2030-01-02"))
        self.assertEqual(ans["artifact"]["key"], "u/x/r.html")

    def test_deny_no_acl_outside_pub(self):
        ans = self.d("x@example.com", "u/x/r.html", None)
        self.assertFalse(ans["allowed"])
        self.assertEqual(ans["reason"], "denied")
        _, detail = gate.plugin_authz_decision_detail("x@example.com", [], "u/x/r.html", None,
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
                ans, detail = gate.plugin_authz_decision_detail("x@example.com", [], "u/x/r.html",
                                                                acl, NOW, head, {"ttl": "7"}, NOW)
                self.assertEqual(ans, {"allowed": False, "reason": "denied",
                                       "user": {"id": "x@example.com", "name": "x@example.com",
                                                "anonymous": False},
                                       "artifact": {"key": "u/x/r.html", "expires": None,
                                                    "ttl": None}}, (want_detail, head))
                self.assertEqual(detail, want_detail)

    def test_deny_expired_even_owner(self):
        ans = self.d("owner@example.com", "u/x/r.html",
                     {"owner": "owner@example.com", "expires": "2020-01-01"})
        self.assertFalse(ans["allowed"])
        self.assertEqual(ans["reason"], "expired")

    def test_expired_told_only_to_who_would_be_allowed(self):
        acl = dict(self.ACL, expires="2020-01-01")
        for who in ("owner@example.com", "alice@example.com"):
            ans = self.d(who, "u/x/r.html", acl)
            self.assertEqual((ans["allowed"], ans["reason"]), (False, "expired"), who)
            self.assertTrue(ans["artifact"]["expires"].startswith("2020-01-01"))
        # a stranger (and anonymous) gets the same deny as for a live artifact, no expiry/ttl
        users_only = {k: v for k, v in self.ACL.items() if k != "groups"}
        live = self.d("mallory@example.com", "u/x/r.html", users_only, tags={"ttl": "7"}, lm=NOW)
        dead = self.d("mallory@example.com", "u/x/r.html", dict(users_only, expires="2020-01-01"),
                      tags={"ttl": "7"}, lm=NOW)
        self.assertEqual((dead["allowed"], dead["reason"]), (False, "denied"))
        self.assertEqual(dead, live)
        self.assertEqual(dead["artifact"], {"key": "u/x/r.html", "expires": None, "ttl": None})
        anon = self.d("", "u/x/r.html", dict(users_only, expires="2020-01-01"))
        self.assertEqual((anon["allowed"], anon["reason"]), (False, "denied"))
        self.assertIsNone(anon["artifact"]["expires"])
        # group ACL: a member is told `expired`, a visitor in no listed group gets the live deny
        member = gate.plugin_authz_decision("carol@example.com", ["11111111-2222-4333-8444-555555555555"],
                                            "u/x/r.html", acl, NOW, 200)
        self.assertEqual(member["reason"], "expired")
        other = gate.plugin_authz_decision("carol@example.com", ["99999999-2222-4333-8444-555555555555"],
                                           "u/x/r.html", acl, NOW, 200)
        self.assertEqual((other["reason"], other["artifact"]["expires"]), ("denied", None))
        empty, detail = gate.plugin_authz_decision_detail("carol@example.com", [], "u/x/r.html",
                                                          acl, NOW, 200)
        self.assertEqual(empty["reason"], "denied")
        self.assertIn("groups-claim-empty", detail)

    def test_object_missing_told_only_to_who_would_be_allowed(self):
        users_only = {k: v for k, v in self.ACL.items() if k != "groups"}
        stranger = self.d("mallory@example.com", "u/x/r.html", users_only, head=404)
        self.assertEqual((stranger["allowed"], stranger["reason"]), (False, "denied"))
        listed = self.d("alice@example.com", "u/x/r.html", self.ACL, head=404)
        self.assertEqual(listed["reason"], "object-missing")

    def test_display_name_passed_through_email_fallback(self):
        ans = gate.plugin_authz_decision("alice@example.com", [], "u/x/r.html", self.ACL, NOW, 200,
                                         name="Alice Example")
        self.assertEqual(ans["user"], {"id": "alice@example.com", "name": "Alice Example",
                                       "anonymous": False})
        self.assertEqual(self.d("alice@example.com", "u/x/r.html", self.ACL)["user"]["name"],
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
        ans = self.d("", "u/x/r.html", None)
        self.assertFalse(ans["allowed"])

    def test_allowed_but_object_missing_denies(self):
        ans = self.d("alice@example.com", "u/x/r.html", self.ACL, head=404)
        self.assertFalse(ans["allowed"])
        self.assertEqual(ans["reason"], "object-missing")

    def test_ttl_tag_gives_expiry(self):
        lm = 1_800_000_000
        ans = self.d("alice@example.com", "u/x/r.html", self.ACL, tags={"ttl": "7"}, lm=lm)
        self.assertEqual(ans["artifact"]["ttl"], 7)
        self.assertEqual(ans["artifact"]["expires"],
                         datetime.fromtimestamp(lm + 7 * 86400, timezone.utc).isoformat())

    def test_acl_expiry_wins_over_ttl(self):
        acl = dict(self.ACL, expires="2030-01-02")
        ans = self.d("alice@example.com", "u/x/r.html", acl, tags={"ttl": "7"}, lm=NOW)
        self.assertTrue(ans["artifact"]["expires"].startswith("2030-01-02"))

    def test_garbage_ttl_is_none(self):
        ans = self.d("alice@example.com", "u/x/r.html", self.ACL, tags={"ttl": "banana"}, lm=NOW)
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


class AclRootTest(unittest.TestCase):
    """The ACL of an artifact lives at its root (u/<run>/, g/<slug>/<run>/) and governs every
    file of it at any depth. One helper (acl_key_for) derives it for read_acl, grant_access and
    decide(); a key with no artifact root is denied whatever ACL objects exist; a pub/ key
    answers to its pub root (pub/<run>/, or pub/ itself for a single file)."""

    ROOT_ACL = {"owner": "own@x.com", "users": ["alice@x.com"]}

    def setUp(self):
        gate._acl_cache.clear()
        self.addCleanup(gate._acl_cache.clear)

    def test_root_acl_key_at_every_depth(self):
        cases = {
            "u/r/index.html": "u/r/.acl.json",
            "u/r/assets/css/app.css": "u/r/.acl.json",
            "u/r/a/b/c/d/e.js": "u/r/.acl.json",
            "g/team/r/index.html": "g/team/r/.acl.json",
            "g/team/r/a/b.css": "g/team/r/.acl.json",
        }
        for key, want in cases.items():
            self.assertEqual(gate.acl_key_for(key), want, key)

    def test_keys_without_artifact_root(self):
        for key in ("u/x.html", "u/r", "u/", "u//x.html", "g/team/x.html", "g/team/r", "g/team",
                    "g//r/x.html", "g/team//x.html", "acl/run.json", "acl/r/x.json",
                    "_gate/req/x.json", "_mcp/x.json", "team/secret/report.html", "x.html",
                    ".acl.json", "U/r/x.html", "public/x.html", ""):
            self.assertIsNone(gate.acl_key_for(key), key)

    def test_pub_root_follows_how_pub_is_published(self):
        # the CLI publishes pub/<run>/<file> (a run directory, like u/<run>/), the MCP publishes
        # pub/<name>-<id>.<ext> (one file directly under the prefix)
        cases = {
            "pub/x.html": "pub/.acl.json",
            "pub/mcp-report-0123abcd.html": "pub/.acl.json",
            "pub/run/index.html": "pub/run/.acl.json",
            "pub/run/a/b.css": "pub/run/.acl.json",
            "pub/run/a/b/c/d.js": "pub/run/.acl.json",
        }
        for key, want in cases.items():
            self.assertEqual(gate.acl_key_for(key), want, key)
        for key in ("pub/x.html", "pub/run/index.html", "pub/run/a/b/c.css"):
            self.assertTrue(gate.decide("a@x.com", [], key, None, NOW)[0], key)

    def test_pub_keys_without_a_pub_root(self):
        # an empty <run> or an empty path below it has no root, like u/ and g/
        for key in ("pub/", "pub//x.html", "pub//", "pub/run/"):
            self.assertIsNone(gate.acl_key_for(key), key)
        # every pub prefix ends in "/": one that does not has no root (fails closed)
        self.assertIsNone(gate.acl_key_for("pub/run/x.html", pub_prefixes=("pub",)))
        self.assertIsNone(gate.acl_key_for("pubx.html", pub_prefixes=("pub",)))
        # another prefix, several segments deep: the same two shapes below it
        deep = ("public/reports/",)
        self.assertEqual(gate.acl_key_for("public/reports/r1/a/b.html", pub_prefixes=deep),
                         "public/reports/r1/.acl.json")
        self.assertEqual(gate.acl_key_for("public/reports/one.html", pub_prefixes=deep),
                         "public/reports/.acl.json")
        self.assertIsNone(gate.acl_key_for("public/other/x.html", pub_prefixes=deep))

    def test_stray_pub_root_acl_governs_every_depth(self):
        # a stray pub/<run>/.acl.json (no publisher writes one) closes its whole run, at any
        # depth, not only the files next to it; a deeper one is never read
        stray = {"owner": "own@x.com", "users": ["alice@x.com"]}
        m = FakeMinio({"pub/open/.acl.json": json.dumps(stray).encode(),
                       "pub/open/sub/.acl.json": json.dumps({"owner": "carol@x.com"}).encode()})
        for key in ("pub/open/index.html", "pub/open/sub/x.html", "pub/open/sub/deeper/y.css"):
            acl, err = gate.read_acl(m, key, NOW, bypass_cache=True)
            self.assertEqual((acl, err), (stray, None), key)
            self.assertFalse(gate.decide("carol@x.com", [], key, acl, NOW)[0], key)
            self.assertFalse(gate.decide("", [], key, acl, NOW)[0], key)          # anonymous
            self.assertEqual(gate.decide("alice@x.com", [], key, acl, NOW), (True, "user"), key)
        self.assertEqual(set(m.gets), {"pub/open/.acl.json"})
        # a single-file pub artifact answers to pub/.acl.json only, never to a run's ACL
        self.assertEqual(gate.read_acl(m, "pub/flat.html", NOW, bypass_cache=True), (None, None))

    def test_decide_denies_a_key_without_root_whatever_the_acl(self):
        permissive = {"owner": "a@x.com", "users": ["a@x.com"], "groups": ["g1"]}
        for key in ("u/x.html", "g/team/x.html", "acl/run.json", "team/secret/r.html", "x.html"):
            for acl in (None, permissive):
                self.assertEqual(gate.decide("a@x.com", ["g1"], key, acl, NOW),
                                 (False, "no-artifact-root: deny"), (key, acl))
        # the same ACL at an artifact root lets the owner in, at any depth
        self.assertEqual(gate.decide("a@x.com", [], "u/r/a/b.js", permissive, NOW), (True, "owner"))

    def test_read_acl_reads_the_root_never_a_nested_acl(self):
        m = FakeMinio({"u/r/.acl.json": json.dumps(self.ROOT_ACL).encode(),
                       "u/r/a/.acl.json": json.dumps({"owner": "mallory@x.com"}).encode(),
                       "g/team/r/.acl.json": json.dumps(self.ROOT_ACL).encode(),
                       "g/team/r/a/b/.acl.json": b"{}"})
        for key in ("u/r/index.html", "u/r/a/x.js", "u/r/a/b/c/d.css", "g/team/r/index.html",
                    "g/team/r/a/b/x.css"):
            self.assertEqual(gate.read_acl(m, key, NOW, bypass_cache=True), (self.ROOT_ACL, None), key)
        self.assertEqual(set(m.gets), {"u/r/.acl.json", "g/team/r/.acl.json"})
        # through decide(): the nested ACL's owner is not let in, the root's user is
        acl, _ = gate.read_acl(m, "u/r/a/x.js", NOW)
        self.assertFalse(gate.decide("mallory@x.com", [], "u/r/a/x.js", acl, NOW)[0])
        self.assertTrue(gate.decide("alice@x.com", [], "u/r/a/x.js", acl, NOW)[0])
        # and a nested ACL is never served (guard: true before this change as well)
        self.assertTrue(gate._bad_key("u/r/a/.acl.json"))

    def test_read_acl_without_root_reads_nothing(self):
        acl = b'{"owner": "a@x.com", "users": ["a@x.com"]}'
        m = FakeMinio({"u/.acl.json": acl, "g/team/.acl.json": acl, "acl/.acl.json": acl,
                       ".acl.json": acl})
        for key in ("u/x.html", "g/team/x.html", "acl/run.json", "x.html"):
            self.assertEqual(gate.read_acl(m, key, NOW), (None, None), key)
        self.assertEqual(m.gets, [])
        self.assertEqual(len(gate._acl_cache), 0)

    def test_one_helper_for_read_acl_grant_access_and_decide(self):
        from unittest import mock
        acl = {"owner": "own@x.com", "users": []}
        m = FakeMinio({"elsewhere/.acl.json": json.dumps(acl).encode()})
        calls = []

        def fake(key, pub_prefixes=gate.PUB_PREFIXES):
            calls.append(key)
            return "elsewhere/.acl.json"

        with mock.patch.object(gate, "acl_key_for", fake):
            self.assertEqual(gate.read_acl(m, "u/r/a.js", NOW, bypass_cache=True), (acl, None))
            ok, note = gate.grant_access(m, "/artifacts/u/r/a/b.js", "new@x.com")
            self.assertTrue(ok, note)
            self.assertEqual(m.puts, ["elsewhere/.acl.json"])     # the write follows the helper
            self.assertIn("elsewhere/.acl.json", gate._grant_locks)
            self.assertEqual(gate.decide("own@x.com", [], "anything", acl, NOW), (True, "owner"))
        # read_acl, grant_access (which reads and writes the key it derived), decide()
        self.assertEqual(calls, ["u/r/a.js", "u/r/a/b.js", "anything"])
        self.assertEqual(m.gets, ["elsewhere/.acl.json", "elsewhere/.acl.json"])
        with mock.patch.object(gate, "acl_key_for", lambda key, pub_prefixes=None: None):
            self.assertEqual(gate.decide("own@x.com", [], "u/r/a.js", acl, NOW),
                             (False, "no-artifact-root: deny"))
            self.assertEqual(gate.read_acl(m, "u/r/a.js", NOW), (None, None))
            self.assertEqual(gate.grant_access(m, "/artifacts/u/r/a.js", "x@x.com"),
                             (False, "no artifact root"))

    def test_grant_for_a_nested_file_writes_only_the_root_acl(self):
        m = FakeMinio({"u/r/.acl.json": json.dumps(self.ROOT_ACL).encode(), "u/r/a/b/c.js": b"x"})
        ok, note = gate.grant_access(m, "/artifacts/u/r/a/b/c.js", "new@x.com")
        self.assertTrue(ok, note)
        self.assertEqual(m.puts, ["u/r/.acl.json"])
        self.assertEqual(json.loads(m.objects["u/r/.acl.json"])["users"], ["alice@x.com", "new@x.com"])
        self.assertEqual([k for k in m.objects if k.endswith(".acl.json")], ["u/r/.acl.json"])
        m = FakeMinio({"g/team/r/.acl.json": json.dumps(self.ROOT_ACL).encode()})
        ok, note = gate.grant_access(m, "/artifacts/g/team/r/a/b.css", "new@x.com")
        self.assertTrue(ok, note)
        self.assertEqual(m.puts, ["g/team/r/.acl.json"])

    def test_grant_never_uses_or_creates_a_nested_acl(self):
        nested = json.dumps({"owner": "own@x.com", "users": []}).encode()
        m = FakeMinio({"u/r/a/.acl.json": nested})         # a stray nested ACL, no root ACL
        self.assertEqual(gate.grant_access(m, "/artifacts/u/r/a/x.js", "new@x.com"),
                         (False, "acl unreadable: missing"))
        self.assertEqual(m.puts, [])
        self.assertEqual(m.objects["u/r/a/.acl.json"], nested)
        # no artifact root: refused before any read or write
        m = FakeMinio({"u/.acl.json": nested, "acl/.acl.json": nested})
        for path in ("/artifacts/u/x.js", "/artifacts/acl/run.json", "/artifacts/other/r/x.js"):
            self.assertEqual(gate.grant_access(m, path, "new@x.com"), (False, "no artifact root"), path)
        self.assertEqual((m.gets, m.puts), ([], []))

    def test_artifact_root_path_is_what_a_grant_covers(self):
        for path, want in (("/artifacts/u/r/index.html", "/artifacts/u/r/"),
                           ("/artifacts/u/r/a/b/c.css", "/artifacts/u/r/"),
                           ("/artifacts/g/team/r/a/b.js", "/artifacts/g/team/r/"),
                           ("/artifacts/pub/run/a/x.html", "/artifacts/pub/run/"),
                           ("/artifacts/u/x.html", None), ("/artifacts/acl/r.json", None),
                           ("/elsewhere/u/r/x.html", None)):
            self.assertEqual(gate.artifact_root_path(path), want, path)

    def test_grant_refuses_paths_the_gate_never_serves(self):
        acl = json.dumps({"owner": "own@x.com", "users": []}).encode()
        m = FakeMinio({"u/secret/.acl.json": acl, "u/other/.acl.json": acl})
        for path in ("/artifacts/u/secret/../other/x.html", "/artifacts/u/secret/./x.html",
                     "/artifacts/u/secret/%2e%2e/other/x.html", "/artifacts/u/secret/.acl.json",
                     "/artifacts/u/secret/sub/.acl.json", "/artifacts/u/secret/",
                     "/artifacts/_gate/req/x.json", "/artifacts/_mcp/x/y.json"):
            self.assertEqual(gate.grant_access(m, path, "new@x.com"), (False, "bad artifact path"),
                             path)
        self.assertEqual((m.gets, m.puts), ([], []))

    def test_mcp_prefix_is_never_served(self):
        for key in ("_mcp", "_mcp/x.json", "_mcp/sessions/a/b.json", "_mcp/.acl.json"):
            self.assertTrue(gate._bad_key(key), key)
        self.assertFalse(gate._bad_key("_mcpx/y.json"))     # the prefix only ...
        self.assertIsNone(gate.acl_key_for("_mcpx/y.json"))  # ... and that key has no root

    def test_plugin_answer_uses_the_same_decision(self):
        acl = {"owner": "a@x.com"}
        ans, detail = gate.plugin_authz_decision_detail("a@x.com", [], "u/x.html", acl, NOW, 200,
                                                        {"ttl": "7"}, NOW)
        self.assertEqual((ans["allowed"], ans["reason"], detail),
                         (False, "denied", "no-artifact-root: deny"))
        self.assertEqual(ans["artifact"], {"key": "u/x.html", "expires": None, "ttl": None})
        ans = gate.plugin_authz_decision("a@x.com", [], "u/r/a/b.js", acl, NOW, 200)
        self.assertEqual((ans["allowed"], ans["reason"]), (True, "owner"))


class PubAuthDecisionTest(unittest.TestCase):
    """The anonymous pub/ decision (GET /_gate/pub-auth): allowed only for an existing pub/
    object whose pub root has no ACL; every other request is refused, before any store read
    when its shape alone is refused (the refused-character list included)."""

    ACL = {"owner": "own@x.com", "users": ["alice@x.com"]}

    def setUp(self):
        gate._acl_cache.clear()
        self.addCleanup(gate._acl_cache.clear)
        self.m = FakeMinio({"pub/run/index.html": b"<h1>run</h1>",
                            "pub/run/assets/app.css": b"body{}",
                            "pub/flat-0123abcd.html": b"<h1>flat</h1>",
                            "pub/closed/index.html": b"x", "pub/closed/sub/y.html": b"y",
                            "pub/closed/.acl.json": json.dumps(self.ACL).encode(),
                            "u/canary/c.html": b"CANARY-U", "g/s/canary/c.html": b"CANARY-G",
                            "acl/canary.html": b"CANARY-ACL", "_gate/canary.json": b"CANARY-GATE"})
        self.heads = []
        head = self.m.head

        def counting_head(key):
            self.heads.append(key)
            return head(key)
        self.m.head = counting_head

    def d(self, uri, method="GET", headers=(), enabled=True):
        return gate.pub_auth_decision(method, uri, self.m, NOW, header_names=headers,
                                      enabled=enabled)

    def test_existing_pub_object_without_acl_is_allowed(self):
        for uri, key in (("/artifacts/pub/run/index.html", "pub/run/index.html"),
                         ("/artifacts/pub/run/assets/app.css", "pub/run/assets/app.css"),
                         ("/artifacts/pub/flat-0123abcd.html", "pub/flat-0123abcd.html")):
            for method in ("GET", "HEAD"):
                self.assertEqual(self.d(uri, method), (True, key, "pub: anonymous, no ACL"),
                                 (uri, method))

    def test_acl_at_the_pub_root_refuses_and_decide_still_evaluates_it(self):
        # an ACL'd pub/ key is refused to anonymous callers with the one uniform answer (no
        # signed-in fallback, which would tell a prober which keys exist behind an ACL); the
        # signed-in decision stays decide() on /_gate/auth
        for uri in ("/artifacts/pub/closed/index.html", "/artifacts/pub/closed/sub/y.html"):
            allowed, _key, reason = self.d(uri)
            self.assertEqual((allowed, reason), (False, "acl present"), uri)
        acl, err = gate.read_acl(self.m, "pub/closed/sub/y.html", NOW)
        self.assertEqual((acl, err), (self.ACL, None))
        self.assertEqual(gate.decide("alice@x.com", [], "pub/closed/sub/y.html", acl, NOW),
                         (True, "user"))
        self.assertEqual(gate.decide("own@x.com", [], "pub/closed/index.html", acl, NOW),
                         (True, "owner"))
        self.assertFalse(gate.decide("carol@x.com", [], "pub/closed/index.html", acl, NOW)[0])

    def test_missing_object_refused(self):
        self.assertEqual(self.d("/artifacts/pub/run/ghost.html")[0::2], (False, "object missing"))
        self.assertEqual(self.d("/artifacts/pub/ghost-run/x.html")[0::2], (False, "object missing"))

    def test_never_served_shapes_refused_before_any_store_read(self):
        for uri in ("/artifacts/pub/run/.acl.json", "/artifacts/pub/.acl.json",
                    "/artifacts/pub/run/", "/artifacts/pub/", "/artifacts/pub",
                    "/artifacts/_gate/canary.json", "/artifacts/_mcp/x.json",
                    "/artifacts/_plugins/c/x.bin", "/artifacts/acl/canary.html",
                    "/artifacts/u/canary/c.html", "/artifacts/g/s/canary/c.html",
                    "/artifacts/", "/artifacts", "/elsewhere/pub/run/index.html", "/",
                    "/_gate/pub-auth"):
            for method in ("GET", "HEAD"):
                self.assertFalse(self.d(uri, method)[0], (uri, method))
        self.assertEqual((self.m.gets, self.heads), ([], []))

    def test_c29_list_never_decided(self):
        # the security probe list, with canaries in u/, g/, acl/ and _gate/, plus the other
        # refused characters; none reaches the store
        targets = ("u/canary/c.html", "g/s/canary/c.html", "acl/canary.html", "_gate/canary.json")
        spellings = ("pub/../{}", "pub/%2e%2e/{}", "pub/%2E%2E/{}", "pub/%252e%252e/{}",
                     "pub//../{}", "pub/x;/../{}", "pub/run/..%2f..%2f{}", "pub/run%2f..%2f..%2f{}",
                     "pub/%2e%2e%2f{}", "pub/run/%5c..%5c{}", "pub/.%2e/{}")
        for t in targets:
            for s in spellings:
                uri = "/artifacts/" + s.format(t)
                self.assertFalse(self.d(uri)[0], uri)
        for raw in ("pub/run/a%00b.html", "pub/run/a%0ab.html", "pub/run/a%0db.html",
                    "pub/run/a%09b.html", "pub/run/a%7fb.html", "pub/run/a%c2%85b.html",
                    "pub/run/a%5cb.html", "pub/run/a%3bb.html", "pub/run/a%23b.html",
                    "pub/run/a%3fb.html", "pub/run/a%25b.html", "pub/run/a..b.html",
                    "pub/run//index.html", "pub//run/index.html", "pub/run/%ff.html",
                    "pub/run/index.html#x", "pub/run/index.html?x=1", "pub/run/index.html?",
                    "pub/run/in dex.html"):
            self.assertFalse(self.d("/artifacts/" + raw)[0], raw)
        self.assertEqual((self.m.gets, self.heads), ([], []))

    def test_spoofed_forwarded_uri_aimed_at_u_or_g_refused(self):
        # u/ and g/ objects without an ACL: the anonymous endpoint never decides them
        for uri in ("/artifacts/u/canary/c.html", "/artifacts/g/s/canary/c.html",
                    "/artifacts/u/canary/../../pub/run/index.html"):
            self.assertFalse(self.d(uri)[0], uri)
        self.assertEqual((self.m.gets, self.heads), ([], []))

    def test_writes_client_s3_headers_and_disabled_refused(self):
        uri = "/artifacts/pub/run/index.html"
        self.assertTrue(self.d(uri)[0])                                     # control
        for method in ("PUT", "POST", "DELETE", "PATCH", "OPTIONS", "get", ""):
            self.assertEqual(self.d(uri, method)[0::2], (False, "method"), method)
        for h in ("X-Amz-Checksum-Mode", "x-amz-server-side-encryption-customer-algorithm",
                  "X-Minio-Extract"):
            self.assertEqual(self.d(uri, headers=["Host", h])[0::2], (False, "client S3 header"), h)
        self.assertEqual(self.d(uri, enabled=False)[0::2], (False, "anonymous pub/ disabled"))
        with mock.patch.object(gate, "ANONYMOUS_PUB_ENABLED", False):
            self.assertFalse(gate.pub_auth_decision("GET", uri, self.m, NOW)[0])
        with mock.patch.object(gate, "ANONYMOUS_PUB_ENABLED", True):
            self.assertTrue(gate.pub_auth_decision("GET", uri, self.m, NOW)[0])

    def test_store_failures_fail_closed(self):
        uri = "/artifacts/pub/run/index.html"

        class Down(FakeMinio):
            def get(self, key):
                raise ConnectionError("minio GET x: timed out")

        class Denied(FakeMinio):
            def get(self, key):
                return 403, b""

        class HeadDown(FakeMinio):
            def head(self, key):
                raise ConnectionError("minio HEAD x: timed out")
        for cls in (Down, Denied, HeadDown):
            gate._acl_cache.clear()
            m = cls({"pub/run/index.html": b"x"})
            self.assertFalse(gate.pub_auth_decision("GET", uri, m, NOW, enabled=True)[0], cls)
        gate._acl_cache.clear()
        m = FakeMinio({"pub/run/index.html": b"x", "pub/run/.acl.json": b"not json"})
        self.assertEqual(gate.pub_auth_decision("GET", uri, m, NOW, enabled=True)[0::2],
                         (False, "acl unreadable (malformed JSON)"))

    def test_what_traefik_forwards_is_what_is_decided(self):
        # the Traefik model of tests/check_oauth2_routes.py gives the path a pub/ read is
        # forwarded with (X-Forwarded-Uri, trustForwardHeader false) and the path MinIO then
        # receives: they are one path, so the gate decides the key the store serves. Probe
        # spellings that Traefik keeps under pub/ are refused or decided as that same key.
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import check_oauth2_routes as routing
        served = {"/artifacts/pub/run/index.html": "pub/run/index.html",
                  "/artifacts/pub/%72un/index.html": "pub/run/index.html",
                  "/artifacts/pub/run/./index.html": "pub/run/index.html",
                  "/artifacts/pub/x/../run/index.html": "pub/run/index.html"}
        refused = ["/artifacts/pub/%252e%252e/u/canary/c.html", "/artifacts/pub/x;/../u/canary/c.html",
                   "/artifacts/pub/x%2f..%2f..%2fu/canary/c.html", "/artifacts/pub/%5c..%5cu/canary/c.html",
                   "/artifacts/pub/run/index.html%00", "/artifacts/pub/run/index.html%3b",
                   "/artifacts/pub/run/index.html%23", "/artifacts/pub/run/index.html%3F"]
        for target, key in served.items():
            rpath, upstream = routing.traefik(target)
            self.assertTrue(rpath.startswith("/artifacts/pub/"), target)
            self.assertEqual(self.d(upstream), (True, key, "pub: anonymous, no ACL"), target)
        for target in refused:
            res = routing.traefik(target)
            if res is None:
                continue                                  # Traefik answers 400 itself
            rpath, upstream = res
            if not rpath.startswith("/artifacts/pub/"):
                continue                                  # not on the anonymous rule
            self.assertFalse(self.d(upstream)[0], (target, upstream))

    def test_null_acl_at_the_pub_root_is_refused(self):
        # an ACL object whose JSON is `null` exists: it is unusable (malformed), never "no ACL"
        for body in (b"null", b" null ", b"null\n", b"\tnull"):
            gate._acl_cache.clear()
            m = FakeMinio({"pub/n/index.html": b"x", "pub/n/.acl.json": body,
                           "u/n/index.html": b"x", "u/n/.acl.json": body})
            for key in ("pub/n/index.html", "u/n/index.html"):
                self.assertEqual(gate.read_acl(m, key, NOW, bypass_cache=True),
                                 (None, gate.ACL_MALFORMED), (body, key))
            self.assertEqual(gate.pub_auth_decision("GET", "/artifacts/pub/n/index.html", m, NOW,
                                                    enabled=True)[0::2],
                             (False, "acl unreadable (malformed JSON)"), body)
        # control: the same root without an ACL object is open
        gate._acl_cache.clear()
        m = FakeMinio({"pub/n/index.html": b"x"})
        self.assertTrue(gate.pub_auth_decision("GET", "/artifacts/pub/n/index.html", m, NOW,
                                               enabled=True)[0])

    def test_pub_key_refused_characters(self):
        for key in ("pub/a..b", "pub/a//b", "pub/a\\b", "pub/a;b", "pub/a%b", "pub/a#b",
                    "pub/a?b", "pub/a\x00b", "pub/a\x1fb", "pub/a\x7fb", "pub/a\x85b",
                    "pub/a\x9fb"):
            self.assertTrue(gate.pub_key_refused(key), repr(key))
        for key in ("pub/run/index.html", "pub/a.b-c_d=e/f.css", "pub/café.html",
                    "pub/a b.html", "pub/.hidden"):
            self.assertFalse(gate.pub_key_refused(key), repr(key))


class BadKeyEmptySegmentTest(unittest.TestCase):
    """Every route refuses a key with an empty segment or a NUL: the store refuses both, so
    the gate never decides them under a root."""

    def test_empty_segment_and_nul(self):
        for key in ("u/r//x.html", "u//r/x.html", "/u/r/x.html", "pub//x.html", "pub/run//x",
                    "g/s/r//a.css", "u/r/a\x00b.html", "pub/x\x00"):
            self.assertTrue(gate._bad_key(key), repr(key))
        for key in ("u/r/x.html", "pub/x.html", "g/s/r/a/b.css"):
            self.assertFalse(gate._bad_key(key), key)


class PubReasonTest(unittest.TestCase):
    """decide()'s reason and the module docstring say pub/ is anonymous read by design."""

    def test_reason_and_docstring(self):
        self.assertEqual(gate.decide("a@x.com", [], "pub/run/x.html", None, NOW),
                         (True, "pub: no ACL (anonymous read by design)"))
        self.assertEqual(gate.PUB_OPEN_REASON, "pub: no ACL (anonymous read by design)")
        doc = gate.__doc__
        self.assertNotIn("any signed-in user of the tenant", doc)
        self.assertIn("`pub/` is anonymous read by design", doc)
        self.assertIn("/_gate/pub-auth", doc)
        self.assertIn("never answers 200 without a valid session", doc)


class RefusedIdentityTest(unittest.TestCase):
    """A directory guest's UPN (`#EXT#`) is refused by the gate, whatever the ACLs say."""

    def test_guest_upn_refused(self):
        for email in ("alice_example.org#EXT#@tenant.example", "ALICE_EXAMPLE.ORG#ext#@TENANT.EXAMPLE",
                      "a#Ext#b@example.org"):
            self.assertTrue(gate.refused_identity(email), email)
        for email in ("alice@example.org", "ext@example.org", "a#ex#t@example.org", "#ext@x.org",
                      "", None):
            self.assertFalse(gate.refused_identity(email), email)
