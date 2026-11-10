"""Raw-socket probe of oauth2-proxy's surface through the compose stack's Caddy (e2e.sh).

oauth2-proxy runs with --upstream=static://202 and --set-authorization-header: any path its
router does not claim answers 202 + `Authorization: Bearer <id_token>`. The front proxy must
route only the browser endpoints. Each request target below is sent VERBATIM over a raw
socket (no client-side normalization) with a valid Bearer id_token.

  probe <host:port>        blocked spellings: no 202, no Authorization / X-Auth-Request-*
                           header, status 400 or 404; browser endpoints: reach oauth2-proxy
                           (not Caddy's bare 404) and leak no identity header either.
                           The id_token comes from env OAUTH2_PROBE_TOKEN (not argv).
  login <user> <password> <gated-url> <expect>
                           browser login, no Bearer: gated read -> 302 sign_in -> Dex login
                           form -> approval -> callback (session cookie) -> gated read 200
                           whose body holds <expect>.
Prints PASS:/FAIL: lines; exits 1 on any FAIL. Stdlib only: python3 -I tests/oauth2_probe.py
"""
import html
import os
import re
import socket
import sys
import urllib.parse

HOST_HEADER = b"127.0.0.1:8080"

# every spelling that must never be answered by oauth2-proxy's catch-all (202 + id_token)
BLOCKED = [
    # /auth (the gate's in-network identity check) in every spelling
    b"/oauth2/auth", b"/oauth2/auth/", b"/oauth2/auth;x", b"/oauth2/auth%2f", b"/oauth2/auth%3b",
    b"/oauth2/auth%3f", b"/oauth2/auth%23", b"/oauth2/auth%00", b"/oauth2/auth%20", b"/oauth2/auth%09",
    b"/oauth2/auth.", b"/oauth2/auth..", b"/oauth2/auth#x", b"/oauth2/a%75th", b"/oauth2/%61%75%74%68",
    b"/oauth2/%2561uth", b"/oauth2/%252561uth", b"/oauth2/%c0%afauth", b"/oauth2/%ef%bc%a1uth",
    b"/oauth2/\xef\xbd\x81uth", b"/oauth2/AUTH", b"/OAUTH2/AUTH", b"/oAuTh2/aUtH", b"/oauth2\\auth",
    b"/oauth2%5cauth", b"/oauth2/x%5c..%5cauth", b"/oauth2/x/..%2fauth", b"/oauth2/x%2f..%2fauth",
    b"/oauth2/x%252f..%252fauth", b"/oauth2/./auth", b"/oauth2//auth", b"//oauth2/auth",
    b"/./oauth2/auth", b"/x/../oauth2/auth", b"/%6fauth2/auth", b"/oauth%32/auth", b"/oauth2%2fauth",
    b"/oauth2%252fauth", b"/_canvas/../oauth2/auth", b"/artifacts/../oauth2/auth", b"/oauth2/auth?x=1",
    b"/oauth2/userinfo", b"/oauth2/auth\t", b"http://127.0.0.1:8080/oauth2/auth",
    b"http://127.0.0.1:8080//oauth2/auth", b"/oauth2/%61uth", b"/oauth2/AuTh;",
    b"/oauth2/auth%2F..%2Fsign_in", b"/oauth2/sign_in/../auth", b"/oauth2/sign_in%2f..%2fauth",
    b"/oauth2/sign_in%252f..%252fauth", b"/oauth2/static/../auth", b"/oauth2/static%2f..%2fauth",
    b"/oauth2/start/..;/auth",
    # anything else oauth2-proxy's router does not claim falls to the same 202
    b"/oauth2/zzz", b"/oauth2/", b"/oauth2", b"/oauth2/ping", b"/oauth2/ready", b"/oauth2/robots.txt",
    b"/oauth2/sign_inX", b"/oauth2/sign_in/", b"/oauth2/sign_in/x", b"/oauth2/sign_in;x",
    b"/oauth2/sign_in%3bx", b"/oauth2/sign_outX", b"/oauth2/callback/x", b"/oauth2/start/",
    b"/oauth2/SIGN_IN", b"/oauth2/Sign_In", b"/OAUTH2/sign_in", b"/oauth2/START?rd=%2F",
    b"/oauth2/%73ign_in", b"/oauth2/sign_%69n?rd=%2F", b"/oauth2/x/../sign_in", b"/oauth2//sign_in",
    b"/oauth2/./sign_in", b"//oauth2/sign_in", b"/oauth2/x%2f..%2fsign_in", b"/oauth2/x/..;/sign_in",
    b"/oauth2/static", b"/oauth2/static/", b"/oauth2/static/css/", b"/oauth2/static/%2e%2e/auth",
    b"/oauth2/static/css/..%2f..%2fauth", b"/oauth2/%73tatic/css/bulma.min.css",
    b"/oauth2/static/css/%62ulma.min.css", b"/oauth2/Static/css/bulma.min.css",
    b"/oauth2/userinfo?x=1", b"/oauth2/zzz?rd=%2F",
]
# browser endpoints: (target, accepted statuses)
BROWSER = [
    (b"/oauth2/sign_in", ("200", "302")),
    (b"/oauth2/sign_in?rd=%2Fartifacts%2Fu%2Fx", ("200", "302")),
    (b"/oauth2/start?rd=%2F", ("302",)),
    (b"/oauth2/callback?code=x&state=y", ("400", "403", "500")),   # oauth2-proxy's error page
    (b"/oauth2/sign_out", ("302",)),
    (b"/oauth2/static/css/bulma.min.css", ("200",)),
    (b"/oauth2/static/css/all.min.css", ("200",)),
]
LEAK_HEADERS = ("authorization:", "x-auth-request-")


def raw(host, port, target, token):
    s = socket.create_connection((host, port), timeout=10)
    req = b"GET " + target + b" HTTP/1.1\r\nHost: " + HOST_HEADER + b"\r\n"
    if token:
        req += b"Authorization: Bearer " + token.encode() + b"\r\n"
    s.sendall(req + b"Connection: close\r\n\r\n")
    data = b""
    try:
        while True:
            c = s.recv(65536)
            if not c:
                break
            data += c
    except OSError:
        pass
    s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin1").split("\r\n")
    parts = lines[0].split(" ") if lines else []
    status = parts[1] if len(parts) > 1 else "???"
    leak = [ln.split(":")[0] for ln in lines[1:] if ln.lower().startswith(LEAK_HEADERS)]
    hdrs = {ln.split(":", 1)[0].strip().lower(): ln.split(":", 1)[1].strip()
            for ln in lines[1:] if ":" in ln}
    return status, leak, hdrs, body


def show(t):
    return repr(t)[2:-1]


def probe(hostport):
    token = os.environ.get("OAUTH2_PROBE_TOKEN", "")
    if not token:
        print("FAIL: OAUTH2_PROBE_TOKEN is empty (a valid Dex id_token is required)")
        return 1
    host, port = hostport.rsplit(":", 1)
    fail = leaks = 0
    for t in BLOCKED:
        st, lk, _, _ = raw(host, int(port), t, token)
        bad = st == "202" or bool(lk)
        leaks += bad
        if bad or st not in ("400", "404"):
            print("FAIL: oauth2 blocked %s -> %s%s" % (show(t), st, " LEAK " + ",".join(lk) if lk else ""))
            fail = 1
        else:
            print("PASS: oauth2 blocked %s -> %s" % (show(t), st))
    print("%s: oauth2 raw probe: %d leak(s) (202 or identity header) of %d spellings"
          % ("PASS" if leaks == 0 else "FAIL", leaks, len(BLOCKED)))
    for t, ok in BROWSER:
        st, lk, hdrs, body = raw(host, int(port), t, token)
        # Caddy's own 404 is bare (no body); anything in `ok` comes from oauth2-proxy
        reached = st in ok and not (st == "404" and not body)
        if not reached or lk:
            print("FAIL: oauth2 browser endpoint %s -> %s%s" % (show(t), st, " LEAK " + ",".join(lk) if lk else ""))
            fail = 1
        else:
            print("PASS: oauth2 browser endpoint %s -> %s (oauth2-proxy)" % (show(t), st))
    return fail


# ---- browser login (no Bearer): cookies by host, redirects followed by hand --------------
class Browser:
    def __init__(self):
        self.jar = {}   # host:port -> {name: value}

    def req(self, method, url, data=None):
        u = urllib.parse.urlsplit(url)
        hp = u.netloc
        target = (u.path or "/") + ("?" + u.query if u.query else "")
        head = "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n" % (method, target, hp)
        if self.jar.get(hp):
            head += "Cookie: %s\r\n" % "; ".join("%s=%s" % kv for kv in self.jar[hp].items())
        body = b""
        if data is not None:
            body = urllib.parse.urlencode(data).encode()
            head += "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n" % len(body)
        host, _, port = hp.partition(":")
        s = socket.create_connection((host, int(port or 80)), timeout=15)
        s.sendall(head.encode() + b"\r\n" + body)
        resp = b""
        while True:
            c = s.recv(65536)
            if not c:
                break
            resp += c
        s.close()
        h, _, b = resp.partition(b"\r\n\r\n")
        lines = h.decode("latin1").split("\r\n")
        status = int(lines[0].split(" ")[1])
        loc = None
        for ln in lines[1:]:
            k, _, v = ln.partition(":")
            k, v = k.strip().lower(), v.strip()
            if k == "set-cookie":
                name, _, val = v.split(";", 1)[0].partition("=")
                if "max-age=0" in v.lower() or "expires=thu, 01 jan 1970" in v.lower():
                    self.jar.setdefault(hp, {}).pop(name, None)
                else:
                    self.jar.setdefault(hp, {})[name] = val
            elif k == "location":
                loc = urllib.parse.urljoin(url, v)
        if "transfer-encoding: chunked" in h.decode("latin1").lower():
            b = dechunk(b)
        return status, loc, b.decode("utf-8", "replace")

    def follow(self, method, url, data=None, trail=None):
        for _ in range(15):
            st, loc, body = self.req(method, url, data)
            if trail is not None:
                trail.append("%s %s -> %d" % (method, url.split("?")[0], st))
            if st in (301, 302, 303, 307) and loc:
                method, url, data = "GET", loc, None
                continue
            return st, url, body
        raise RuntimeError("too many redirects")


def dechunk(b):
    out = b""
    while b:
        size, _, rest = b.partition(b"\r\n")
        n = int(size.split(b";")[0] or b"0", 16)
        if n == 0:
            break
        out += rest[:n]
        b = rest[n + 2:]
    return out


def form(body, base):
    m = re.search(r'<form[^>]*action="([^"]*)"', body, re.I)
    action = urllib.parse.urljoin(base, html.unescape(m.group(1))) if m else base
    fields = {}
    for inp in re.findall(r"<input[^>]*>", body, re.I):
        n = re.search(r'name="([^"]*)"', inp)
        v = re.search(r'value="([^"]*)"', inp)
        if n:
            fields[html.unescape(n.group(1))] = html.unescape(v.group(1)) if v else ""
    return action, fields


def login(user, password, gated, expect):
    b, trail, fail = Browser(), [], 0
    st = b.req("GET", gated)[0]
    if st != 302:
        print("FAIL: login: anonymous gated read answered %d, expected 302" % st)
        return 1
    st, url, body = b.follow("GET", gated, trail=trail)
    # Dex: password-DB login form (one connector, so no connector picker)
    if 'name="password"' not in body:
        print("FAIL: login: no Dex login form after sign_in (%d at %s)" % (st, url))
        return 1
    print("PASS: login: sign_in redirected to the IdP login form")
    action, fields = form(body, url)
    fields.update({"login": user, "password": password})
    st, url, body = b.follow("POST", action, fields, trail=trail)
    if 'name="approval"' in body or "approval" in url:
        action, fields = form(body, url)
        fields["approval"] = "approve"
        st, url, body = b.follow("POST", action, fields, trail=trail)
    for line in trail:
        print("  login| " + line)
    if not any("/oauth2/callback -> 302" in line for line in trail):
        print("FAIL: login: oauth2-proxy callback did not complete")
        fail = 1
    else:
        print("PASS: login: oauth2-proxy callback set the session")
    if st == 200 and url == gated and expect in body:
        print("PASS: login: gated read with the session cookie (200, body ok)")
    else:
        print("FAIL: login: gated read with the session cookie answered %d at %s" % (st, url))
        fail = 1
    return fail


def main(argv):
    if len(argv) >= 2 and argv[0] == "probe":
        return probe(argv[1])
    if len(argv) >= 5 and argv[0] == "login":
        return login(*argv[1:5])
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
