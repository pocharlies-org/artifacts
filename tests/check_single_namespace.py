#!/usr/bin/env python3
"""Render the chart with namespaces.sso equal to minio.namespace and assert that every object
and every reference lands in that one namespace (needs helm).

    python3 -I tests/check_single_namespace.py   # HELM=/path/to/helm to pick another binary

The chart puts the gate, the login proxy and the middlewares in namespaces.sso, and the routes
and the bootstrap Job in minio.namespace. With both set to one value, Traefik's default refusal
of cross-namespace references must have nothing to refuse: every object's metadata.namespace,
every `namespace:` reference (route services, middlewares, the errors service) and every
in-cluster `<service>.<namespace>.svc.cluster.local` address must name that namespace, and no
two objects may share a kind and a name. Every optional template branch is switched on (anonymous
pub/ route, a plugin without its own namespace, the gate image mode, the publisher user, the
login proxy lists) so that no template is left out. The default render (two namespaces) is
checked as a control, so the check cannot pass by finding nothing, and in it every object must
sit in its own one of the two (namespaces.sso: gate, login proxy, middlewares; minio.namespace:
routes, bootstrap Job), which the single-namespace render cannot tell apart. Stdlib only.
"""
import json
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHART = os.path.join(ROOT, "helm", "artifacts")
VALUES = os.path.join(CHART, "values.yaml")
HELM = os.environ.get("HELM", "helm")
NS = "artifacts"
OPTIONS = {
    "artifactsGate": {"anonymousPubEnabled": True},
    "artifactsExtraHosts": ["b.example.com"],
    "plugins": [{"name": "canvas", "pathPrefix": "/_canvas/", "service": "artifact-canvas", "port": 8080}],
    "gate": {"bakedImage": True, "bakedImageDigest": "sha256:" + "0123456789abcdef" * 4},
    "bootstrap": {"publisherSecretName": "artifact-publisher-s3"},
    "ingressRouteAnnotations": {"kubernetes.io/ingress.class": "traefik-internal"},
    "oauth2Proxy": {"emailDomains": ["example.com"], "trustedProxyIPs": ["10.42.0.0/16"],
                    "extraArgs": ["--allowed-group=00000000-0000-0000-0000-000000000001"]},
}
# objects the chart renders with OPTIONS on (kind, name)
EXPECTED = {
    ("Deployment", "artifact-gate"), ("Service", "artifact-gate"),
    ("Deployment", "oauth2-proxy-artifacts"), ("Service", "oauth2-proxy-artifacts"),
    ("Middleware", "gate-auth"), ("Middleware", "artifacts-errors"),
    ("Middleware", "artifacts-csp"), ("Middleware", "artifacts-strip-to-minio"),
    ("IngressRoute", "artifacts-routes"), ("IngressRoute", "artifacts-plugin-canvas"),
    ("Job", "artifacts-bootstrap"),
}
# where each kind lands with the example values (namespaces.sso: sso, minio.namespace: minio)
PLACEMENT = {"Deployment": "sso", "Service": "sso", "Middleware": "sso",
             "IngressRoute": "minio", "Job": "minio"}
VALUE_OF = {"sso": "namespaces.sso", "minio": "minio.namespace"}
REF_RE = re.compile(r"\bnamespace:\s*([^\s,}]+)")
SVC_RE = re.compile(r"\b([a-z0-9-]+)\.([a-z0-9-]+)\.svc\.cluster\.local\b")


def render(values):
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        json.dump(values, f)              # JSON is YAML: no YAML library needed
    try:
        p = subprocess.run([HELM, "template", "t", CHART, "-f", VALUES, "-f", f.name],
                           capture_output=True, text=True)
    finally:
        os.unlink(f.name)
    if p.returncode != 0:
        sys.exit("FAIL: helm template exited %d: %s" % (p.returncode, p.stderr.strip()))
    return p.stdout


def check(cond, msg):
    if not cond:
        sys.exit("FAIL: " + msg)
    print("ok:", msg)


def objects(text):
    """[(kind, name, metadata.namespace or None, document)] for every rendered object."""
    out = []
    for d in text.split("\n---\n"):
        lines = d.splitlines()
        kind = next((ln[6:].strip() for ln in lines if ln.startswith("kind: ")), None)
        if not kind:
            continue
        meta, ns, name = False, None, None
        for ln in lines:
            if ln.startswith("metadata:"):
                meta = True
                continue
            if meta and ln and not ln.startswith(" "):
                break
            if meta and ln.startswith("  namespace: "):
                ns = ln.split(":", 1)[1].strip()
            if meta and ln.startswith("  name: "):
                name = ln.split(":", 1)[1].strip()
        out.append((kind, name, ns, d))
    return out


def namespaces_seen(text):
    """{namespace: count} over metadata, `namespace:` references and in-cluster addresses."""
    seen = {}
    body = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    for m in REF_RE.finditer(body):
        seen[m.group(1)] = seen.get(m.group(1), 0) + 1
    for m in SVC_RE.finditer(body):
        seen[m.group(2)] = seen.get(m.group(2), 0) + 1
    return seen


# control: the example values put objects in two namespaces, and the check sees both
control = render(OPTIONS)
check(set(namespaces_seen(control)) == {"sso", "minio"},
      "control: the default namespaces render two namespaces (sso, minio) and the check sees both")
cobjs = objects(control)
check({(k, n) for k, n, _ns, _d in cobjs} == EXPECTED and len(cobjs) == len(EXPECTED),
      "control: all %d objects rendered once" % len(EXPECTED))
for kind, name, ns, _d in cobjs:
    want = PLACEMENT.get(kind)
    check(ns == want, "control: %s/%s is in %s (%s)%s" % (
        kind, name, want, VALUE_OF.get(want), "" if ns == want else ", rendered in %s" % ns))

text = render(dict(OPTIONS, namespaces={"sso": NS}, minio={"namespace": NS}))
objs = objects(text)
keys = [(k, n) for k, n, _ns, _d in objs]
check(set(keys) == EXPECTED, "all %d objects rendered: %s" % (len(EXPECTED), ", ".join(
    "%s/%s" % k for k in sorted(EXPECTED))))
check(len(keys) == len(set(keys)), "no two objects share a kind and a name")
for kind, name, ns, _d in objs:
    check(ns == NS, "%s/%s has metadata.namespace %s" % (kind, name, NS))
seen = namespaces_seen(text)
check(set(seen) == {NS}, "every namespace reference and in-cluster address names %s (%s)" % (
    NS, ", ".join("%s x%d" % kv for kv in sorted(seen.items()))))
refs = sum(1 for ln in text.splitlines() if REF_RE.search(ln) and not ln.lstrip().startswith("#")
           and not ln.startswith("  namespace: "))
check(refs >= 9, "cross-object references checked: %d (route services, middlewares, errors service)" % refs)
print("single namespace: all checks passed")
