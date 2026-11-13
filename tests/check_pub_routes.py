#!/usr/bin/env python3
"""Where the chart decides an anonymous pub/ read (needs helm).

    python3 -I tests/check_pub_routes.py      # HELM=/path/to/helm to pick another binary

artifactsGate.anonymousPubThroughGate (default false) moves the anonymous pub/ read from
"straight to MinIO" (rule 2 of artifacts-routes.yaml, today's shape) to "the gate decides
first" (forwardAuth middleware gate-pub-auth -> the gate's /_gate/pub-auth). This renders:

  - the defaults: no anonymous pub/ rule, no gate-pub-auth anywhere;
  - anonymousPubEnabled only: rule 2 straight to MinIO with its .acl.json and listing
    exclusions, gate-pub-auth rendered but used by no route (dormant);
  - anonymousPubThroughGate: every rule that can serve pub/ carries gate-pub-auth, after
    artifacts-csp (so the gate's own 404 carries the sandbox CSP) and before
    artifacts-strip-to-minio; no rule sends anything to MinIO without a forwardAuth; rule 2
    has no exclusions (every pub/ shape reaches the gate); the public gate route (rule 4)
    keeps /_gate/pub-auth off; the middleware asks the decision listener with
    trustForwardHeader false whatever gate.trustForwardHeader says;
  - the refusals: anonymousPubThroughGate without anonymousPubEnabled, a non-boolean value,
    and anonymous pub/ with publicExposure.

Request targets go through the Traefik model of tests/check_oauth2_routes.py (normalizePath,
sanitizePath, routing path), so encoded and traversal spellings are checked as Traefik routes
them. Stdlib only.
"""
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check_oauth2_routes as routing  # noqa: E402  (Traefik rule parser and evaluator)

ROOT = os.path.dirname(HERE)
CHART = os.path.join(ROOT, "helm", "artifacts")
VALUES = os.path.join(CHART, "values.yaml")
HELM = os.environ.get("HELM", "helm")
TMP = tempfile.mkdtemp(prefix="pub-routes-")
MINIO_SERVICE = "minio"                     # values.yaml minio.service
FORWARD_AUTH = {"gate-auth", "gate-pub-auth"}

# request targets on the artifacts host, as sent; REFUSED_CHARS: traversal spellings and the
# characters the anonymous decision refuses
PUB_TARGETS = ["/artifacts/pub/run/index.html", "/artifacts/pub/run/a/b.css",
               "/artifacts/pub/flat-0123abcd.html", "/artifacts/pub/run/.acl.json",
               "/artifacts/pub/.acl.json", "/artifacts/pub/run/", "/artifacts/pub/",
               "/artifacts/pub/run/x%2Fy", "/artifacts/pub/%72un/index.html"]
OTHER_TARGETS = ["/artifacts/u/r/index.html", "/artifacts/g/s/r/index.html",
                 "/artifacts/_gate/req/x.json", "/artifacts/acl/r.json", "/artifacts/top.html"]
REFUSED_CHARS = ["/artifacts/pub/../u/c.html", "/artifacts/pub/%2e%2e/u/c.html",
                 "/artifacts/pub/%252e%252e/u/c.html", "/artifacts/pub//../u/c.html",
                 "/artifacts/pub/x;/../u/c.html", "/artifacts/pub/x/..;/../g/s/r/c.html",
                 "/artifacts/pub/x%2f..%2f..%2fu/c.html", "/artifacts/pub/%5c..%5cu/c.html",
                 "/artifacts/pub/../_gate/c.json", "/artifacts/pub/../acl/c.json"]


def render(values=None):
    args = [HELM, "template", "t", CHART, "-f", VALUES]
    if values is not None:
        path = os.path.join(TMP, "values-%d.yaml" % len(os.listdir(TMP)))
        with open(path, "w") as f:
            json.dump(values, f)          # JSON is YAML: no YAML library needed
        args += ["-f", path]
    p = subprocess.run(args, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def ok_render(values=None):
    rc, out, err = render(values)
    if rc != 0:
        sys.exit("FAIL: helm template with %s exited %d: %s" % (json.dumps(values), rc, err.strip()))
    return out


def check(cond, msg):
    if not cond:
        sys.exit("FAIL: " + msg)
    print("ok:", msg)


def documents(text):
    """{(kind, name): document text} for every rendered object."""
    out = {}
    for d in text.split("\n---\n"):
        kind = next((ln[6:].strip() for ln in d.splitlines() if ln.startswith("kind: ")), None)
        name = next((ln[8:].strip() for ln in d.splitlines() if ln.startswith("  name: ")), None)
        if kind:
            out[(kind, name)] = d
    return out


def rules(text):
    """[{priority, match, middlewares, services, tree}] of every `- kind: Rule`, in Traefik's
    order (higher priority first, then the longer rule)."""
    lines = text.splitlines()
    out, cur, section = [], None, None
    for i, line in enumerate(lines):
        ind = len(line) - len(line.lstrip())
        if re.match(r"^\s*- kind: Rule\s*$", line):
            cur = {"priority": 0, "match": None, "middlewares": [], "services": [], "indent": ind}
            section = None
            out.append(cur)
            continue
        if cur is None or not line.strip() or line.lstrip().startswith("#"):
            continue
        if ind <= cur["indent"]:
            cur = None
            continue
        m = re.match(r"^\s*([A-Za-z]+):\s*(.*)$", line)
        if m and ind == cur["indent"] + 2:
            section, rest = m.group(1), m.group(2).strip()
            if section == "priority":
                cur["priority"] = int(rest)
            elif section == "match":
                body = []
                for nxt in lines[i + 1:]:
                    if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= ind:
                        break
                    body.append(nxt.strip())
                cur["match"] = " ".join(body) if rest in (">-", ">", "|", "|-") else rest
            continue
        if section in ("middlewares", "services"):
            m = re.search(r"\bname:\s*([A-Za-z0-9_.-]+)", line)
            if m:
                cur[section].append(m.group(1))
    rs = [r for r in out if r["match"]]
    for r in rs:
        r["tree"] = routing.parse(r["match"])
    rs.sort(key=lambda r: (-r["priority"], -len(r["match"])))
    return rs


def winner(rs, routing_path):
    """The rule Traefik picks for a GET of `routing_path` (no S3 headers, no query)."""
    return next((r for r in rs if routing.ev(r["tree"], routing_path)), None)


def routed(rs, target):
    """(rule or None, upstream path) for a raw request target, or None when Traefik answers
    400 before routing."""
    res = routing.traefik(target)
    if res is None:
        return None
    rpath, upstream = res
    return winner(rs, rpath), upstream


def main():
    # ---- defaults: no anonymous pub/ at all -----------------------------------------------
    text = ok_render()
    check("gate-pub-auth" not in text and "/_gate/pub-auth" not in text,
          "defaults: no gate-pub-auth middleware and no reference to it")
    rs = rules(text)
    check(not [r for r in rs if "/pub/" in r["match"]], "defaults: no rule names pub/")

    # ---- anonymousPubEnabled only: today's rule 2, middleware dormant ------------------------
    text = ok_render({"artifactsGate": {"anonymousPubEnabled": True}})
    docs = documents(text)
    check(("Middleware", "gate-pub-auth") in docs,
          "anonymous pub/ on: gate-pub-auth is rendered (dormant until the route uses it)")
    rs = rules(text)
    check(not [r for r in rs if "gate-pub-auth" in r["middlewares"]],
          "anonymous pub/ on, not through the gate: no route uses gate-pub-auth")
    pub = [r for r in rs if "/artifacts/pub/" in r["match"]]
    check(len(pub) == 1 and pub[0]["middlewares"] == ["artifacts-strip-to-minio", "artifacts-csp"]
          and pub[0]["services"] == [MINIO_SERVICE],
          "anonymous pub/ on: rule 2 goes straight to MinIO with [strip, csp] (unchanged)")
    check("!PathRegexp(`\\.acl\\.json$`)" in pub[0]["match"] and "!PathRegexp(`/$`)" in pub[0]["match"],
          "anonymous pub/ on: rule 2 keeps its .acl.json and listing exclusions (unchanged)")
    check("/_gate/pub-auth" not in [r for r in rs if r["priority"] == 400][0]["match"],
          "anonymous pub/ on: the public gate route (rule 4) is unchanged")

    # ---- through the gate --------------------------------------------------------------------
    for trust in (False, True):
        text = ok_render({"artifactsGate": {"anonymousPubEnabled": True,
                                            "anonymousPubThroughGate": True},
                          "gate": {"trustForwardHeader": trust, "authPort": 18081}})
        docs = documents(text)
        mw = docs.get(("Middleware", "gate-pub-auth"), "")
        check("address: http://artifact-gate.sso.svc.cluster.local:18081/_gate/pub-auth" in mw,
              "gate-pub-auth asks /_gate/pub-auth on the decision listener (gate.authPort)")
        check(re.search(r"^\s*trustForwardHeader: false$", mw, re.M) is not None,
              "gate-pub-auth trustForwardHeader is false (gate.trustForwardHeader=%s)" % trust)
        check('authResponseHeaders: ["Authorization", "X-Amz-Date", "X-Amz-Content-Sha256"]' in mw,
              "gate-pub-auth copies the signed upstream read, like gate-auth")
    text = ok_render({"artifactsGate": {"anonymousPubEnabled": True, "anonymousPubThroughGate": True},
                      "artifactsExtraHosts": ["b.example.com"]})
    rs = rules(text)
    pub = [r for r in rs if "/artifacts/pub/" in r["match"]]
    check(len(pub) == 1 and pub[0]["middlewares"] == ["artifacts-csp", "gate-pub-auth",
                                                       "artifacts-strip-to-minio"]
          and pub[0]["services"] == [MINIO_SERVICE],
          "through the gate: rule 2 is [artifacts-csp, gate-pub-auth, artifacts-strip-to-minio] "
          "-> MinIO")
    check("PathRegexp" not in pub[0]["match"],
          "through the gate: rule 2 has no exclusions (every pub/ shape reaches the gate)")
    to_minio = [r for r in rs if MINIO_SERVICE in r["services"]]
    check(to_minio and all(FORWARD_AUTH & set(r["middlewares"]) for r in to_minio),
          "through the gate: every rule to MinIO (%d) carries a forwardAuth" % len(to_minio))
    for t in PUB_TARGETS:
        res = routed(rs, t)
        check(res is not None and res[0] is pub[0],
              "through the gate: %s is decided by gate-pub-auth" % t)
    for t in OTHER_TARGETS:
        res = routed(rs, t)
        check(res is not None and res[0] is not None and "gate-pub-auth" not in res[0]["middlewares"],
              "through the gate: %s is not on the anonymous rule" % t)
    for t in REFUSED_CHARS:
        res = routed(rs, t)
        if res is None:
            print("ok: through the gate: %s refused by Traefik (400) before routing" % t)
            continue
        rule, upstream = res
        check(rule is None or not (MINIO_SERVICE in rule["services"]
                                   and not FORWARD_AUTH & set(rule["middlewares"])),
              "through the gate: %s never reaches MinIO without a gate decision (upstream %s, %s)"
              % (t, upstream, rule and rule["middlewares"]))
    gate_public = [r for r in rs if r["priority"] == 400][0]
    check("!Path(`/_gate/pub-auth`)" in gate_public["match"]
          and winner(rs, "/_gate/pub-auth") is None and winner(rs, "/_gate/auth") is None,
          "through the gate: /_gate/pub-auth and /_gate/auth are routed nowhere (rule 4 keeps "
          "them off the public gate listener)")
    check(winner(rs, "/_gate/request") is gate_public,
          "through the gate: the request-access surface is still routed (rule 4)")

    # ---- refusals ----------------------------------------------------------------------------
    for values, needle in (
            ({"artifactsGate": {"anonymousPubThroughGate": True}}, "needs artifactsGate.anonymousPubEnabled=true"),
            ({"artifactsGate": {"anonymousPubEnabled": True, "anonymousPubThroughGate": "true"}},
             "anonymousPubThroughGate must be a boolean"),
            ({"artifactsGate": {"anonymousPubEnabled": True, "anonymousPubThroughGate": True},
              "publicExposure": True}, "must never coexist with public exposure")):
        rc, _out, err = render(values)
        check(rc != 0 and needle in err, "refused: %s" % json.dumps(values))
    print("pub routes: all checks passed")


if __name__ == "__main__":
    main()
