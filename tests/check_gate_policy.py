#!/usr/bin/env python3
"""The gate S3 user's policy, as the chart's bootstrap Job and deploy/compose/bootstrap.sh
create it: both documents are the same, and the gate may write an ACL only at an artifact root
(needs helm).

    python3 -I tests/check_gate_policy.py   # HELM=/path/to/helm to pick another binary

The gate writes only u/<run>/.acl.json and g/<slug>/<run>/.acl.json (gate/gate.py acl_key_for)
and its own state under _gate/. A policy `*` matches any run of characters, `/` included, so an
Allow on u/*/.acl.json alone also covers u/<run>/<dir>/.acl.json: the documents must take the
deeper forms back with an explicit Deny. This evaluates both documents with the S3 rules (an
explicit Deny wins, no matching Allow is a deny, `*` is any run of characters, `?` one
character) over a table of keys and actions. deploy/compose/e2e.sh probes the same rule against
a real MinIO with the gate's own client. Stdlib only.
"""
import json
import os
import re
import subprocess
import sys
import textwrap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHART = os.path.join(ROOT, "helm", "artifacts")
VALUES = os.path.join(CHART, "values.yaml")
COMPOSE_BOOTSTRAP = os.path.join(ROOT, "deploy", "compose", "bootstrap.sh")
HELM = os.environ.get("HELM", "helm")
BUCKET = "artifacts"

# The keys the gate's ACL writes may touch: the artifact roots (a run literally named
# `.acl.json` is still a root: acl_key_for gives it u/.acl.json/.acl.json).
ROOT_ACLS = ["u/r/.acl.json", "g/s/r/.acl.json", "u/.acl.json/.acl.json", "g/s/.acl.json/.acl.json"]
# Everything else that ends in .acl.json: below a root, or where no root is.
NESTED_ACLS = ["u/r/a/.acl.json", "u/r/a/b/.acl.json", "u/r/.acl.json/.acl.json",
               "g/s/r/a/.acl.json", "g/s/r/a/b/c/.acl.json"]
ROOTLESS_ACLS = ["u/.acl.json", "g/s/.acl.json", "g/.acl.json", ".acl.json", "acl/.acl.json",
                 "pub/.acl.json", "pub/x/.acl.json", "other/.acl.json", "other/x/y/.acl.json",
                 "_mcp/x/.acl.json", "_plugins/c/.acl.json"]
OBJECTS = ["u/r/index.html", "g/s/r/a/b.css", "pub/x/index.html", "_plugins/c/x.bin",
           "_mcp/x.json", "top.html"]
STATE = ["_gate/req/x.json", "_gate/rl/x.json"]
EVERY_KEY = ROOT_ACLS + NESTED_ACLS + ROOTLESS_ACLS + OBJECTS + STATE

# action -> the keys it must be allowed on; every other key of EVERY_KEY must be denied.
EXPECTED = {
    "s3:PutObject": ROOT_ACLS + STATE,
    "s3:PutObjectTagging": [],
    "s3:GetObject": EVERY_KEY,
    "s3:GetObjectTagging": EVERY_KEY,
    "s3:DeleteObject": [],
}


def heredoc(text, name, where):
    """The JSON of `cat > /tmp/<name> <<JSON ... JSON` in a shell script, at any indentation."""
    m = re.search(r"^([ \t]*)cat > /tmp/%s <<JSON\n(.*?)^\1JSON$" % re.escape(name), text,
                  re.S | re.M)
    if not m:
        sys.exit("FAIL: no /tmp/%s heredoc in %s" % (name, where))
    return json.loads(textwrap.dedent(m.group(2)).replace("${BUCKET}", BUCKET))


def wildcard(pattern, value):
    rx = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern)
    return re.fullmatch(rx, value, re.S) is not None


def allowed(policy, action, key):
    resource = "arn:aws:s3:::%s/%s" % (BUCKET, key)

    def hit(effect):
        for st in policy["Statement"]:
            if st["Effect"] != effect:
                continue
            actions = st["Action"] if isinstance(st["Action"], list) else [st["Action"]]
            resources = st["Resource"] if isinstance(st["Resource"], list) else [st["Resource"]]
            if any(wildcard(a, action) for a in actions) and \
                    any(wildcard(r, resource) for r in resources):
                return True
        return False
    return hit("Allow") and not hit("Deny")


def check(cond, msg):
    if not cond:
        sys.exit("FAIL: " + msg)
    print("ok:", msg)


def main():
    p = subprocess.run([HELM, "template", "t", CHART, "-f", VALUES], capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit("FAIL: helm template exited %d: %s" % (p.returncode, p.stderr.strip()))
    chart = heredoc(p.stdout, "policy-gate.json", "the rendered bootstrap Job")
    with open(COMPOSE_BOOTSTRAP) as f:
        compose = heredoc(f.read(), "policy-gate.json", COMPOSE_BOOTSTRAP)
    check(chart == compose, "chart and compose create the same gate policy")
    # the evaluator itself: `*` crosses `/`, which is why the Deny is needed at all
    check(wildcard("arn:aws:s3:::b/u/*/.acl.json", "arn:aws:s3:::b/u/r/a/.acl.json"),
          "a policy `*` matches across `/` (the evaluator follows S3)")
    for action, want in EXPECTED.items():
        wrong = [(k, allowed(chart, action, k)) for k in EVERY_KEY
                 if allowed(chart, action, k) != (k in want)]
        check(not wrong, "%s allowed on exactly %d of %d keys%s" % (
            action, len(want), len(EVERY_KEY), "" if not wrong else ": wrong %s" % wrong))
    for k in NESTED_ACLS + ROOTLESS_ACLS:
        check(not allowed(chart, "s3:PutObject", k), "gate cannot write %s" % k)


if __name__ == "__main__":
    main()
