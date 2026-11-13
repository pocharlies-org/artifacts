#!/usr/bin/env python3
"""Render the chart with its defaults and with every option set, and assert what each value
does (needs helm).

    python3 -I tests/check_chart_values.py      # HELM=/path/to/helm to pick another binary

Covered values: ingressRouteAnnotations (on every IngressRoute, plugin routes included),
gate.trustForwardHeader (gate-auth forwardAuth, default false), oauth2Proxy.emailDomains,
oauth2Proxy.trustedProxyIPs and oauth2Proxy.extraArgs (login proxy flags; no
--email-domain=* once a domain list is set; extraArgs accepts only a non-empty
--allowed-group), the artifacts-csp response headers, the
container resources of the gate, the login proxy and the bootstrap Job (ephemeral-storage
from values), the route that keeps /_gate/plugin/ off the public gate listener, and the
example login-proxy image (digest-pinned, v7.15.5 or newer, the same image the compose stack
runs), the names written into Traefik rules: artifactsHost, artifactsExtraHosts and
plugins[].pathPrefix (a safe charset only, so a backtick can never rewrite a rule), and the
gate's request-access caps (gate.requestCaps, whole numbers only). Every refusal the chart
makes for these values is exercised too. Stdlib only.
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
COMPOSE = os.path.join(ROOT, "deploy", "compose", "docker-compose.yml")
HELM = os.environ.get("HELM", "helm")
TMP = tempfile.mkdtemp(prefix="chart-values-")


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


def block(doc, key, indent):
    """The lines nested under the first `<indent spaces><key>:` line of doc."""
    lines = doc.splitlines()
    head = " " * indent + key + ":"
    for i, ln in enumerate(lines):
        if ln.rstrip() == head:
            body = []
            for nxt in lines[i + 1:]:
                if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= indent:
                    break
                body.append(nxt)
            return body
    return None


def annotations(doc):
    body = block(doc, "annotations", 2)
    if body is None:
        return None
    out = {}
    for ln in body:
        k, v = ln.strip().split(": ", 1)
        out[k] = json.loads(v) if v.startswith('"') else v
    return out


def proxy_args(text):
    doc = documents(text)[("Deployment", "oauth2-proxy-artifacts")]
    out = []
    for ln in block(doc, "args", 10):
        s = ln.strip()
        if s.startswith("- "):
            v = s[2:]
            out.append(json.loads(v) if v.startswith('"') else v)
    return out


def resources(doc):
    """{'limits': {...}, 'requests': {...}} of the only container of doc."""
    out, cur = {}, None
    for ln in block(doc, "resources", 10):
        s = ln.strip()
        if s.endswith(":"):
            cur = out.setdefault(s[:-1], {})
        else:
            k, v = s.split(": ", 1)
            cur[k] = v
    return out


def gate_env(doc):
    """{name: value} of the gate container's plain env entries (`- name:` + `value:` lines)."""
    out, name = {}, None
    for ln in doc.splitlines():
        s = ln.strip()
        if s.startswith("- name: "):
            name = s[len("- name: "):]
        elif s.startswith("value: ") and name is not None:
            v = s[len("value: "):]
            out[name] = json.loads(v) if v.startswith('"') else v
            name = None
        else:
            name = None
    return out


def winner(text, path):
    """Service names of the rule Traefik picks for a GET of path on the artifacts host."""
    rs = sorted(((p, m, s, routing.parse(m)) for p, m, s in routing.routes(text)),
                key=lambda r: (-r[0], -len(r[1])))
    for _p, _m, svc, tree in rs:
        if routing.ev(tree, path):
            return svc
    return []


INGRESS_ROUTES = ("artifacts-routes", "artifacts-plugin-canvas")
PLUGIN = [{"name": "canvas", "pathPrefix": "/_canvas/", "service": "artifact-canvas", "port": 8080}]
GATE_RES = {"limits": {"cpu": "200m", "memory": "128Mi"}, "requests": {"cpu": "25m", "memory": "64Mi"}}
JOB_RES = {"limits": {"cpu": "200m", "memory": "128Mi"}, "requests": {"cpu": "10m", "memory": "32Mi"}}
EPH = {"requests": {"ephemeral-storage": "16Mi"}, "limits": {"ephemeral-storage": "64Mi"}}


def with_eph(res):
    return {k: dict(v, **EPH[k]) for k, v in res.items()}


# ---- defaults: today's behaviour except the two hardening defaults ----------------------
default = ok_render({"plugins": PLUGIN})
docs = documents(default)
for name in INGRESS_ROUTES:
    check(annotations(docs[("IngressRoute", name)]) is None,
          "default: IngressRoute %s has no annotations" % name)
check("    trustForwardHeader: false\n" in docs[("Middleware", "gate-auth")],
      "default: gate-auth trustForwardHeader is false")
csp = block(docs[("Middleware", "artifacts-csp")], "customResponseHeaders", 4)
check([ln.strip() for ln in csp if not ln.strip().startswith("#")]
      == ["Content-Security-Policy: sandbox allow-scripts", "X-Content-Type-Options: nosniff",
          "Referrer-Policy: no-referrer"],
      "artifacts-csp sends exactly the sandbox CSP, nosniff and no-referrer")
args = proxy_args(default)
check([a for a in args if a.startswith("--email-domain")] == ["--email-domain=*"],
      "default: login proxy keeps --email-domain=* (no domain list)")
check(not [a for a in args if a.startswith(("--trusted-proxy-ip", "--trusted-ip"))],
      "default: no --trusted-proxy-ip and no --trusted-ip (trusted proxies are set by value only)")
check(args[-1] == "--silence-ping-logging=true", "default: no extra args after the chart's flags")
# the example image: the release that has --trusted-proxy-ip and the fixes emailDomains and
# trustedProxyIPs rely on (README, "Forwarded headers"), by digest; compose runs the same one
img = next(ln.split("image: ", 1)[1] for ln in docs[("Deployment", "oauth2-proxy-artifacts")].splitlines()
           if ln.strip().startswith("image: "))
m = re.fullmatch(r"quay\.io/oauth2-proxy/oauth2-proxy:v(\d+)\.(\d+)\.(\d+)@sha256:[0-9a-f]{64}", img)
check(m is not None and tuple(map(int, m.groups())) >= (7, 15, 5),
      "default: login proxy image is oauth2-proxy v7.15.5 or newer, pinned by digest (%s)" % img)
with open(COMPOSE) as f:
    compose_imgs = [ln.split("image: ", 1)[1].split("#")[0].strip()
                    for ln in f if ln.strip().startswith("image: quay.io/oauth2-proxy/")]
check(compose_imgs == [img], "compose stack runs the chart's login proxy image")
check(resources(docs[("Deployment", "artifact-gate")]) == GATE_RES,
      "default: gate resources unchanged (25m/64Mi requests, 200m/128Mi limits)")
check(resources(docs[("Deployment", "oauth2-proxy-artifacts")]) == GATE_RES,
      "default: login proxy resources unchanged (25m/64Mi requests, 200m/128Mi limits)")
check(resources(docs[("Job", "artifacts-bootstrap")]) == JOB_RES,
      "default: bootstrap Job resources unchanged (10m/32Mi requests, 200m/128Mi limits)")
check("ephemeral-storage" not in default, "default: no ephemeral-storage anywhere")
env = gate_env(docs[("Deployment", "artifact-gate")])
check((env.get("GATE_REQUESTER_RATE_LIMIT_MAX"), env.get("GATE_OWNER_PENDING_MAX")) == ("20", "10"),
      "default: request caps 20 per requester and 10 open per owner, as quoted strings")

# the gate's public listener gets request-access paths, never a decision endpoint
for path in ("/_gate/plugin/authz", "/_gate/plugin/", "/_gate/plugin/x", "/_gate/auth", "/_gate/healthz"):
    check("artifact-gate" not in winner(default, path), "no route sends %s to the gate" % path)
for path in ("/_gate/request", "/_gate/approve", "/_gate/plugin"):
    check(winner(default, path) == ["artifact-gate"], "%s still reaches the gate (port 8080)" % path)

# ---- every option set ------------------------------------------------------------------
ANN = {"kubernetes.io/ingress.class": "traefik-internal"}
full = ok_render({
    "plugins": PLUGIN,
    "artifactsExtraHosts": ["b.example.com"],
    "ingressRouteAnnotations": ANN,
    "gate": {"trustForwardHeader": True, "resources": EPH,
             "requestCaps": {"perRequester": 7, "ownerPending": 999999}},
    "oauth2Proxy": {"emailDomains": ["example.com", "*.example.org"],
                    "trustedProxyIPs": ["10.42.0.0/16", "fd00::/8", "192.0.2.10"],
                    "extraArgs": ["--allowed-group=00000000-0000-0000-0000-000000000001",
                                  "--allowed-group=00000000-0000-0000-0000-000000000002"],
                    "resources": EPH},
    "bootstrap": {"resources": EPH},
})
docs = documents(full)
check(sorted(n for k, n in docs if k == "IngressRoute") == sorted(INGRESS_ROUTES),
      "set: two IngressRoutes rendered (artifacts host + plugin)")
for name in INGRESS_ROUTES:
    check(annotations(docs[("IngressRoute", name)]) == ANN,
          "set: IngressRoute %s carries exactly kubernetes.io/ingress.class: traefik-internal" % name)
check(full.count("kubernetes.io/ingress.class") == len(INGRESS_ROUTES),
      "set: the annotation is on IngressRoutes only")
check("    trustForwardHeader: true\n" in docs[("Middleware", "gate-auth")],
      "set: gate.trustForwardHeader=true renders true")
args = proxy_args(full)
check([a for a in args if a.startswith("--email-domain")]
      == ["--email-domain=example.com", "--email-domain=*.example.org"],
      "set: one --email-domain per listed domain and no --email-domain=*")
check([a for a in args if a.startswith("--trusted-proxy-ip")]
      == ["--trusted-proxy-ip=10.42.0.0/16", "--trusted-proxy-ip=fd00::/8",
          "--trusted-proxy-ip=192.0.2.10"],
      "set: one --trusted-proxy-ip per listed address or range")
check(args.index("--trusted-proxy-ip=10.42.0.0/16") == args.index("--reverse-proxy=true") + 1,
      "set: --trusted-proxy-ip follows --reverse-proxy=true")
check(args[-2:] == ["--allowed-group=00000000-0000-0000-0000-000000000001",
                    "--allowed-group=00000000-0000-0000-0000-000000000002"],
      "set: extra args (one --allowed-group per group) appended last, in order")
one_group = proxy_args(ok_render(
    {"oauth2Proxy": {"extraArgs": ["--allowed-group=00000000-0000-0000-0000-000000000001"]}}))
check(one_group[-1] == "--allowed-group=00000000-0000-0000-0000-000000000001"
      and sum(a.startswith("--allowed-group") for a in one_group) == 1,
      "set: extraArgs accepts --allowed-group=<id> (rendered once, last)")
check(resources(docs[("Deployment", "artifact-gate")]) == with_eph(GATE_RES),
      "set: gate ephemeral-storage request and limit from values (cpu/memory defaults kept)")
env = gate_env(docs[("Deployment", "artifact-gate")])
check((env.get("GATE_REQUESTER_RATE_LIMIT_MAX"), env.get("GATE_OWNER_PENDING_MAX")) == ("7", "999999"),
      "set: gate.requestCaps reach the gate (7 per requester, 999999 open per owner)")
check(resources(docs[("Deployment", "oauth2-proxy-artifacts")]) == with_eph(GATE_RES),
      "set: login proxy ephemeral-storage request and limit from values")
check(resources(docs[("Job", "artifacts-bootstrap")]) == with_eph(JOB_RES),
      "set: bootstrap Job ephemeral-storage request and limit from values")
check(ok_render({"oauth2Proxy": {"emailDomains": [".example.com"]}}).count("- --email-domain=.example.com") == 1,
      "set: a leading-dot subdomain entry is accepted")

# ---- names written into Traefik rules: hosts and plugin prefixes ------------------------
names = ok_render({"artifactsHost": "a1.example-2.org", "artifactsExtraHosts": ["b.example.com", "192.0.2.10"],
                   "plugins": [dict(PLUGIN[0], pathPrefix="/_canvas/v2/"),
                               {"name": "x-1", "pathPrefix": "/_x-1_y/", "service": "s", "port": 80}]})
rules = [m for _p, m, _s in routing.routes(names)]
host_match = "(Host(`a1.example-2.org`) || Host(`b.example.com`) || Host(`192.0.2.10`))"
check(rules and all(m.startswith(host_match + " && ") for m in rules),
      "set: every rule starts with the host matcher of artifactsHost + artifactsExtraHosts")
check(host_match + " && PathPrefix(`/_canvas/v2/`)" in rules
      and host_match + " && PathPrefix(`/_x-1_y/`)" in rules,
      "set: nested plugin prefixes and '_' / '-' in a segment are accepted")
check(all(m.count("`") % 2 == 0 for m in rules), "set: every rule has balanced backticks")

# ---- refusals ----------------------------------------------------------------------------
OP = "oauth2Proxy"
refusals = [
    ({"gate": {"trustForwardHeader": "true"}}, "gate.trustForwardHeader must be a boolean"),
    ({"gate": {"trustForwardHeader": "false"}}, "gate.trustForwardHeader must be a boolean"),
    ({"ingressRouteAnnotations": "traefik-internal"}, "ingressRouteAnnotations must be a map"),
    ({"ingressRouteAnnotations": {"bad key": "x"}}, "not a valid annotation key"),
    ({"ingressRouteAnnotations": {"a: b\n  c": "x"}}, "not a valid annotation key"),
    ({OP: {"emailDomains": "example.com"}}, "oauth2Proxy.emailDomains must be a list"),
    ({OP: {"emailDomains": ["*"]}}, "`*` is not a domain"),
    ({OP: {"emailDomains": ["example.com", "*"]}}, "`*` is not a domain"),
    ({OP: {"emailDomains": ["exa mple.com"]}}, "is not a domain name"),
    ({OP: {"emailDomains": ["localhost"]}}, "is not a domain name"),
    ({OP: {"emailDomains": ["*example.com"]}}, "is not a domain name"),
    ({OP: {"emailDomains": ["example.com\n            - --skip-auth-regex=.*"]}}, "is not a domain name"),
    ({OP: {"trustedProxyIPs": "10.0.0.0/8"}}, "oauth2Proxy.trustedProxyIPs must be a list"),
    ({OP: {"trustedProxyIPs": ["any"]}}, "is not an IP address or CIDR range"),
    ({OP: {"trustedProxyIPs": ["10.0.0.0/8 --x"]}}, "is not an IP address or CIDR range"),
    ({OP: {"trustedProxyIPs": ["10.0.0.0/8\n            - --x"]}}, "is not an IP address or CIDR range"),
    ({OP: {"extraArgs": "--allowed-group=x"}}, "oauth2Proxy.extraArgs must be a list"),
    ({OP: {"extraArgs": ["--email-domain=*"]}}, "set --email-domain through oauth2Proxy.emailDomains"),
    ({OP: {"extraArgs": ["--email-domain=example.com"]}}, "set --email-domain through oauth2Proxy.emailDomains"),
    ({OP: {"extraArgs": ["--trusted-proxy-ip=10.0.0.0/8"]}},
     "set --trusted-proxy-ip through oauth2Proxy.trustedProxyIPs"),
    ({OP: {"extraArgs": ["--trusted-ip=0.0.0.0/0"]}}, "--trusted-ip is refused"),
    ({OP: {"extraArgs": ["--trusted-ip"]}}, "--trusted-ip is refused"),
    ({OP: {"extraArgs": ["allowed-group=x"]}}, "must be one flag"),
    ({OP: {"extraArgs": ["--allowed-group", "x"]}}, "only --allowed-group=<id> is accepted"),
    ({OP: {"extraArgs": ["--allowed-group=x", "x"]}}, "must be one flag"),
    ({OP: {"extraArgs": ["--allowed-group=x\n- --skip-auth-regex=.*"]}}, "must be one flag"),
] + [
    # allow-list: a flag appended last overrides the chart's own, so only --allowed-group=<id>
    ({OP: {"extraArgs": [a]}}, "only --allowed-group=<id> is accepted")
    for a in ("--skip-auth-regex=.*", "--skip-auth-route=/x", "--skip-jwt-bearer-tokens",
              "--skip-jwt-bearer-tokens=true", "--ping-user-agent=x",
              "--cookie-domain=.example.com", "--oidc-email-claim=email",
              "--whitelist-domain=*", "--skip-provider-button=false",
              "--allowed-group=", "--allowed-group")
] + [
    # an allowed entry does not let a later one through
    ({OP: {"extraArgs": ["--allowed-group=00000000-0000-0000-0000-000000000001",
                         "--skip-auth-regex=.*"]}}, "only --allowed-group=<id> is accepted"),
] + [
    # plugin prefixes: written into PathPrefix(`...`), so only [a-z0-9_-] segments
    ({"plugins": [dict(PLUGIN[0], pathPrefix=p)]}, "may only hold lowercase letters")
    for p in ("/_x/`) || PathPrefix(`/", "/_canvas/`) || Host(`evil.example`) && PathPrefix(`/",
              "/_Canvas/", "/_can vas/", "/_canvas/../", "/_canvas/./", "/_canvas//", "/_can.vas/",
              "/_can\nvas/", "/_canvas/%2e/", "/_can\\vas/")
] + [
    # host names: written into Host(`...`), so a lowercase DNS name only
    ({key: val}, "is not a host name")
    for key, vals in (("artifactsExtraHosts", (["b.example.com`) || PathPrefix(`/"],
                                               ["b.example.com`) || Host(`evil.example"],
                                               ["B.example.com"], ["b.example.com:443"],
                                               ["*.example.com"], ["b example.com"], ["-b.example.com"],
                                               ["b-.example.com"], ["b..example.com"], ["b.example.com."],
                                               [""], [5], ["a" * 64 + ".example.com"],
                                               ["b.example.com", "c.example.com\n"])),
                      ("artifactsHost", ("artifacts.example.com`) || Host(`evil.example", "",
                                         "Artifacts.example.com", "artifacts.example.com/x")))
    for val in vals
] + [
    ({"artifactsExtraHosts": "b.example.com"}, "artifactsExtraHosts must be a list"),
] + [
    # request caps: a whole number from 1 to 999999, never a string, a fraction or nothing
    ({"gate": {"requestCaps": {key: val}}}, "gate.requestCaps.%s must be a whole number" % key)
    for key in ("perRequester", "ownerPending")
    for val in (0, -1, 1.5, 1000000, "20", "", True, None, [5], {"n": 5})
] + [
    ({"gate": {"requestCaps": "20"}}, "gate.requestCaps must be a map"),
]
for values, needle in refusals:
    rc, _, err = render(values)
    check(rc != 0 and needle in err, "refused: %s" % json.dumps(values))
print("chart values: all checks passed")
