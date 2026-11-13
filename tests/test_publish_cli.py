#!/usr/bin/env python3
"""cli/publish.sh with -g: the slug is checked before anything is written, and a valid slug
publishes the ACL at the artifact root g/<slug>/<run>/.acl.json with the group id as a JSON
string. Runs the script against a local stand-in for the S3 write host and the read host.

    python3 -I -m unittest discover -s tests -p 'test_publish_cli.py' -v
"""
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUBLISH = os.path.join(ROOT, "cli", "publish.sh")
GID = "11111111-2222-4333-8444-555555555555"


class FakeHosts(BaseHTTPRequestHandler):
    """PUT: the S3 write host (records path and body). GET: the read host (302 to the login,
    what publish.sh expects for a gated artifact)."""
    puts = []

    def log_message(self, *a):
        pass

    def do_PUT(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        FakeHosts.puts.append((self.path, body))
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "/oauth2/sign_in")
        self.send_header("Content-Length", "0")
        self.end_headers()


class PublishGroupSlugTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeHosts)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = "http://127.0.0.1:%d" % cls.server.server_address[1]
        cls.tmp = tempfile.mkdtemp(prefix="publish-cli-")
        cls.file = os.path.join(cls.tmp, "report.html")
        with open(cls.file, "w") as f:
            f.write("<p>report</p>")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        FakeHosts.puts.clear()

    def publish(self, slug):
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": self.tmp,
               "ARTIFACTS_CONFIG": os.path.join(self.tmp, "absent.conf"),
               "ARTIFACTS_ACCESS_KEY": "test-ak", "ARTIFACTS_SECRET_KEY": "test-sk-not-a-secret",
               "ARTIFACTS_WRITE_BASE": self.base, "ARTIFACTS_READ_BASE": self.base,
               "ARTIFACTS_OWNER": "owner@example.com",
               "ARTIFACTS_GROUPS": "team-a=%s;team/sub=%s;Team=%s" % (GID, GID, GID)}
        return subprocess.run(["bash", PUBLISH, "-g", slug, "-r", "run1", "-t", "7", self.file],
                              env=env, capture_output=True, text=True, timeout=60)

    def test_bad_slug_refused_before_any_write(self):
        for slug in ("team/sub", "Team", "team_a", "-team", "team-", "..", "a/../b", "team a",
                     "téam", "team\n"):
            p = self.publish(slug)
            self.assertEqual(p.returncode, 2, (slug, p.stderr))
            self.assertIn("invalid group slug", p.stderr, slug)
        self.assertEqual(FakeHosts.puts, [])

    @unittest.skipUnless(shutil.which("curl"), "publishing needs curl (>= 8, --aws-sigv4)")
    def test_valid_slug_publishes_the_root_acl_with_the_group_id(self):
        p = self.publish("team-a")
        self.assertEqual(p.returncode, 0, p.stderr)
        paths = [path for path, _ in FakeHosts.puts]
        self.assertEqual(paths[0], "/artifacts/g/team-a/run1/.acl.json")    # the ACL goes first
        self.assertIn("/artifacts/g/team-a/run1/index.html", paths)
        acl = json.loads(FakeHosts.puts[0][1])
        self.assertEqual((acl["owner"], acl["users"], acl["groups"]),
                         ("owner@example.com", [], [GID]))


if __name__ == "__main__":
    unittest.main()
