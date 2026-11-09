"""Unit tests for mcp/artifacts_lib.py — pure helpers, no mcp SDK needed."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mcp"))
import artifacts_lib as al  # noqa: E402


class SafeNameTest(unittest.TestCase):
    def test_strips_paths_and_traversal(self):
        self.assertEqual(al.safe_object_name("../../etc/passwd"), "passwd")
        self.assertEqual(al.safe_object_name("a b/../../x.html"), "x.html")

    def test_charset(self):
        self.assertEqual(al.safe_object_name("héllo wörld!.html"), "h_llo_w_rld_.html")


class ValidateKeyTest(unittest.TestCase):
    def test_ok(self):
        os.environ["ARTIFACTS_BUCKET"] = "artifacts"
        self.assertEqual(al.validate_key("pub/x.html"), "pub/x.html")
        self.assertEqual(al.validate_key("/artifacts/pub/x.html"), "pub/x.html")

    def test_traversal_rejected(self):
        for bad in ("", "..", "a/../b", "a\\b", "a//b", "/./x"):
            with self.assertRaises(ValueError):
                al.validate_key(bad)

    def test_forbidden_prefixes(self):
        for bad in ("_gate/req/x.json", "_plugins/canvas/doc.bin", "_gate", "_plugins"):
            with self.assertRaises(ValueError):
                al.validate_key(bad)

    def test_acl_files_rejected(self):
        with self.assertRaises(ValueError):
            al.validate_key("u/run1/.acl.json")


class KeyForHtmlTest(unittest.TestCase):
    def test_public_under_pub(self):
        k = al.key_for_html("My Report!!", True)
        self.assertTrue(k.startswith("pub/My_Report-"))
        self.assertTrue(k.endswith(".html"))
        self.assertNotIn("!", k)

    def test_private_is_gated_key(self):
        k = al.key_for_html("x", False)
        self.assertTrue(k.startswith("u/x-"))
        self.assertTrue(k.endswith("/index.html"))
        self.assertNotIn("pub/", k)

    def test_unique(self):
        self.assertNotEqual(al.key_for_html("x", True), al.key_for_html("x", True))


class PluginLinksTest(unittest.TestCase):
    def test_links(self):
        os.environ["ARTIFACTS_PLUGINS"] = "canvas=/_canvas/; other =/_other/"
        os.environ.pop("ARTIFACTS_BUCKET", None)
        out = al.plugin_links("https://a.example/", "pub/x.html")
        self.assertEqual(out, [
            {"name": "canvas", "url": "https://a.example/_canvas/artifacts/pub/x.html"},
            {"name": "other", "url": "https://a.example/_other/artifacts/pub/x.html"},
        ])

    def test_malformed_skipped(self):
        os.environ["ARTIFACTS_PLUGINS"] = "broken=/_broken;ok=/_ok/;"
        out = al.plugin_links("https://a.example", "k")
        self.assertEqual([p["name"] for p in out], ["ok"])


class AclForTest(unittest.TestCase):
    def test_shape(self):
        import json
        acl = json.loads(al.acl_for("Owner@Example.com", ["B@x.com", "a@x.com", "a@x.com"],
                                    ["g2", "g1"], 7))
        self.assertEqual(acl["owner"], "owner@example.com")
        self.assertEqual(acl["users"], ["a@x.com", "b@x.com"])
        self.assertEqual(acl["groups"], ["g1", "g2"])
        self.assertRegex(acl["expires"], r"^\d{4}-\d{2}-\d{2}$")


class SigV4ShapeTest(unittest.TestCase):
    def test_signed_request_headers(self):
        c = al.S3Client(endpoint="http://127.0.0.1:9000", access_key="AK", secret_key="SK",
                        bucket="artifacts", region="us-east-1")
        req = c._signed_request("PUT", "pub/x.html", b"hi", {"Content-Type": "text/html"})
        self.assertEqual(req.get_method(), "PUT")
        self.assertEqual(req.full_url, "http://127.0.0.1:9000/artifacts/pub/x.html")
        h = {k.lower(): v for k, v in req.headers.items()}
        self.assertIn("AWS4-HMAC-SHA256 Credential=AK/", h["authorization"])
        self.assertIn("x-amz-content-sha256", h)
        self.assertEqual(h["content-type"], "text/html")


if __name__ == "__main__":
    unittest.main()
