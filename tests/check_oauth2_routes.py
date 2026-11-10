"""CI check: the rendered chart never routes oauth2-proxy's /auth to the browser side.

Reads `helm template` output on stdin. Every Traefik route rule that mentions the
oauth2-proxy prefix must exclude /auth as a PREFIX with a regex (oauth2-proxy also serves it
as /auth/, /auth;x and /auth%2f, which Traefik decodes to /auth/), in any case, and must keep
the browser endpoints (sign_in, start, callback, sign_out) routed.
Stdlib only: python3 -I tests/check_oauth2_routes.py < rendered.yaml
"""
import re
import sys

PREFIX = "/oauth2-artifacts"
# what Traefik sees as req.URL.Path for the spellings the e2e probes (decoded, not cleaned)
BLOCKED = ["/auth", "/auth/", "/auth;x", "/auth/x", "/AUTH", "/Auth/", "//auth"]
ROUTED = ["/sign_in", "/start", "/callback", "/sign_out", "/static/css/x.css"]


def rules(text):
    """Every `match:` expression (single line or a folded `>-` block)."""
    lines = text.splitlines()
    out = []
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)match:\s*(.*)$", line)
        if not m:
            continue
        indent, rest = len(m.group(1)), m.group(2).strip()
        if rest in (">-", ">", "|", "|-"):
            body = []
            for nxt in lines[i + 1:]:
                if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= indent:
                    break
                body.append(nxt.strip())
            rest = " ".join(body)
        out.append(rest)
    return out


def main():
    text = sys.stdin.read()
    routes = [r for r in rules(text) if PREFIX in r]
    if not routes:
        print("FAIL: no route for %s found in the rendered chart" % PREFIX)
        return 1
    fail = 0
    for r in routes:
        neg = re.findall(r"!PathRegexp\(`([^`]*)`\)", r)
        excl = [re.compile(x) for x in neg]
        prefix = re.search(r"PathPrefix\(`([^`]*)`\)", r)
        exact = set(re.findall(r"!Path\(`([^`]*)`\)", r))
        allowed = lambda p: ((not prefix or p.startswith(prefix.group(1))) and p not in exact
                             and not any(e.search(p) for e in excl))
        for s in BLOCKED:
            if allowed(PREFIX + s):
                print("FAIL: %s%s is routed by: %s" % (PREFIX, s, r))
                fail = 1
        for s in ROUTED:
            if not allowed(PREFIX + s):
                print("FAIL: %s%s is no longer routed by: %s" % (PREFIX, s, r))
                fail = 1
    if not fail:
        print("PASS: %d oauth2-proxy route(s) exclude /auth as a prefix (%d spellings) and keep %d browser endpoints"
              % (len(routes), len(BLOCKED), len(ROUTED)))
    return fail


if __name__ == "__main__":
    sys.exit(main())
