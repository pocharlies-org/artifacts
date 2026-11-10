"""CI check: the rendered chart routes ONLY oauth2-proxy's browser endpoints to it.

oauth2-proxy runs with --upstream=static://202 and --set-authorization-header: any path its
router does not claim (/auth, /zzz, /, /ping, /userinfo, /sign_inX, /SIGN_IN, ...) answers
202 + `Authorization: Bearer <id_token>`. The chart must route an allow-list only: sign_in,
start, callback, sign_out (exact) and static/<file>.

Reads `helm template` output on stdin, collects every Traefik IngressRoute rule (match,
priority, services), and for each probe picks the rule Traefik would pick (highest priority
first) and checks whether it sends the request to oauth2-proxy.

Traefik model (verified against the Traefik v3.5+ source, v3.7.18 at the time of writing:
pkg/server/server_entrypoint_tcp.go normalizePath + sanitizePath, sanitizePath on by
default, and pkg/muxer/http/mux.go withRoutingPath + matcher.go):
  1. the request target is parsed by net/http (invalid %-encodings and control characters
     are refused with 400);
  2. normalizePath: %xx upper-cased, unreserved %xx (A-Z a-z 0-9 - . _ ~) decoded in the raw
     path;
  3. sanitizePath: path parameters of `..;`, `.;` and `;` segments dropped, then the raw path
     is cleaned (dot segments and `//` removed, url.URL.JoinPath) — this cleaned raw path is
     ALSO what the backend receives;
  4. Path/PathPrefix/PathRegexp match the "routing path": that raw path with every %xx
     decoded EXCEPT the reserved ones (RFC 3986 gen-delims/sub-delims and %25), which stay
     encoded.
Two sets of probes:
  ROUTING   routing paths given literally (what a matcher sees), including the fully
            decoded-once spellings of the older Traefik model;
  RAW       request targets as sent on the wire, run through the model above; whenever one
            is routed to oauth2-proxy, the path oauth2-proxy receives must be exactly an
            allowed endpoint (its router is case-sensitive and matches the still-encoded path).
Stdlib only: python3 -I tests/check_oauth2_routes.py < rendered.yaml
"""
import re
import sys

PREFIX = "/oauth2-artifacts"
EXACT = ["/sign_in", "/start", "/callback", "/sign_out"]
STATIC_RE = re.compile(r"^/static/([A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+$")

ROUTED = EXACT + ["/static/css/bulma.min.css", "/static/css/all.min.css",
                  "/static/webfonts/fa-solid-900.woff2"]
# routing paths (as a matcher sees them) that must never reach oauth2-proxy
BLOCKED_ROUTING = [
    "", "/", "//", "/auth", "/auth/", "/auth;x", "/auth/x", "/AUTH", "/Auth/", "//auth",
    "/%61uth", "/%2561uth", "/%252561uth", "/x%2f..%2fauth", "/x%2F..%2Fauth", "/auth%2F",
    "/auth%3B", "/zzz", "/ping", "/ready", "/robots.txt", "/metrics", "/userinfo",
    "/userinfo/", "/sign_inX", "/sign_in/", "/sign_in/x", "/sign_in;x", "/sign_in%3Bx",
    "/sign_in%2F..%2Fauth", "/SIGN_IN", "/Sign_In", "/sign_IN", "/START", "/Callback",
    "/sign_out/", "/sign_outX", "/callback/x", "/start/../auth", "/static", "/static/",
    "/static/css", "/static/css/", "/static/../auth", "/static/./css/x.css",
    "/static/css/../../auth", "/static/%2e%2e/auth", "/static/%2E%2E/auth",
    "/static/css%2Fx.css", "/static/css/x.css%2F", "/static/css/.css", "/static/css/x.",
    "/static/css/x css.css", "/Static/css/x.css", "/STATIC/css/x.css", "/static//css/x.css",
    "/s%74atic/css/x.css", "/%73ign_in", "/sign_in%00", "/sign_in ", "/sign_in\t",
    "/sign_in\n", "/sign_in.", "/sign_in..", "/sign_in\\x", "/\\auth",
]
# request targets as sent (the e2e raw probe's spellings, on the chart's prefix)
RAW = [
    "/auth", "/auth/", "/auth;x", "/auth%2f", "/auth%3b", "/auth%3f", "/auth%23",
    "/auth%00", "/auth%20", "/auth%09", "/auth.", "/auth..", "/a%75th", "/%61%75%74%68",
    "/%2561uth", "/%252561uth", "/%c0%afauth", "/%ef%bc%a1uth", "/\xef\xbd\x81uth", "/AUTH",
    "/aUtH", "\\auth", "%5cauth", "/x%5c..%5cauth", "/x/..%2fauth", "/x%2f..%2fauth",
    "/x%252f..%252fauth", "/./auth", "//auth", "%2fauth", "%252fauth", "/auth?x=1",
    "/userinfo", "/%61uth", "/AuTh;", "/auth%2F..%2Fsign_in", "/sign_in/../auth",
    "/sign_in%2f..%2fauth", "/sign_in%252f..%252fauth", "/static/../auth",
    "/static%2f..%2fauth", "/start/..;/auth", "/zzz", "/", "", "/ping", "/sign_inX",
    "/sign_in/", "/sign_in/x", "/SIGN_IN", "/Sign_In", "/%73ign_in", "/sign_%69n",
    "/x/../sign_in", "//sign_in", "/./sign_in", "/sign_in;x", "/;/sign_in", "/x/..;/sign_in",
    "/static/css/%62ulma.min.css", "/%73tatic/css/bulma.min.css", "/static/%2e%2e/auth",
    "/static/css/..%2f..%2fauth", "/static/css/", "/static/", "/callback?code=x&state=y",
    "/sign_in?rd=%2Fartifacts%2Fu%2Fx", "/start?rd=%2F", "/sign_out",
]
# full targets that do not start with the prefix but resolve into it
RAW_ABS = ["/x/.." + PREFIX + "/auth", "/." + PREFIX + "/auth", "/" + PREFIX + "/auth",
           "/_canvas/.." + PREFIX + "/auth", "/artifacts/.." + PREFIX + "/auth",
           "/%6fauth2-artifacts/auth", "/oauth2-%61rtifacts/zzz", "/OAUTH2-ARTIFACTS/auth",
           "/x/.." + PREFIX + "/sign_in"]

UNRESERVED = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
RESERVED = set(":/?#[]@!$&'()*+,;=%")   # Traefik keeps these encoded in the routing path
HEX = "0123456789abcdefABCDEF"


# ---- Go net/url bits Traefik relies on ----------------------------------------------------
def go_unescape(s):
    b, out, i = s.encode("latin1"), bytearray(), 0
    while i < len(b):
        if b[i:i + 1] == b"%":
            h = b[i + 1:i + 3].decode("latin1")
            if len(h) != 2 or any(c not in HEX for c in h):
                raise ValueError("invalid percent-encoding")
            out.append(int(h, 16))
            i += 3
        else:
            out.append(b[i])
            i += 1
    return bytes(out)


def go_should_escape_path(c):
    if c.isascii() and (c.isalnum() or c in "-_.~"):
        return False
    return c not in "$&+,/:;=@"


def go_escape_path(raw_bytes):
    return "".join(chr(x) if x < 128 and not go_should_escape_path(chr(x)) else "%%%02X" % x
                   for x in raw_bytes)


def go_valid_encoded(s):
    for c in s:
        if c in "!$&'()*:;=@[]%+,/":
            continue
        if go_should_escape_path(c):
            return False
    return True


def go_clean(p):
    """Go path.Clean for an absolute or relative slash path."""
    if p == "":
        return "."
    rooted = p.startswith("/")
    out = []
    for seg in p.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if out and out[-1] != "..":
                out.pop()
            elif not rooted:
                out.append("..")
            continue
        out.append(seg)
    s = ("/" if rooted else "") + "/".join(out)
    return s or ("/" if rooted else ".")


def traefik(target):
    """Raw request target -> (routing path, path the backend receives), or None (400)."""
    t = target.split("?", 1)[0]
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in t):
        return None                                   # net/http: invalid control character
    if t.startswith("http://") or t.startswith("https://"):
        t = "/" + t.split("/", 3)[3] if t.count("/") >= 3 else "/"
    if not t.startswith("/"):
        return None                                   # net/http refuses a relative target
    try:
        decoded = go_unescape(t)
    except ValueError:
        return None
    # EscapedPath(): the raw spelling when it is a valid encoding of Path, else Go's own
    esc = t if (go_valid_encoded(t) and all(ord(c) < 128 for c in t)) else go_escape_path(decoded)
    # normalizePath
    out, i = [], 0
    while i < len(esc):
        if esc[i] == "%":
            enc = esc[i:i + 3].upper()
            ch = chr(int(enc[1:], 16))
            out.append(ch if ch in UNRESERVED else enc)
            i += 3
        else:
            out.append(esc[i])
            i += 1
    p = "".join(out)
    # sanitizePath: path parameters of dot/empty segments, then JoinPath (clean, keep trailing /)
    if ";" in p:
        segs = p.split("/")
        for k, s in enumerate(segs):
            if s.startswith("..;"):
                segs[k] = ".."
            elif s.startswith(".;"):
                segs[k] = "."
            elif s.startswith(";"):
                segs[k] = ""
        p = "/".join(segs)
    cleaned = go_clean(p)
    if p.endswith("/") and not cleaned.endswith("/"):
        cleaned += "/"
    # routing path: decode every %xx except the reserved ones
    rp, i = [], 0
    while i < len(cleaned):
        if cleaned[i] == "%":
            enc = cleaned[i:i + 3]
            ch = chr(int(enc[1:], 16))
            rp.append(enc if ch in RESERVED else ch)
            i += 3
        else:
            rp.append(cleaned[i])
            i += 1
    return "".join(rp), cleaned


# ---- Traefik rule language (the subset the chart uses) ----------------------------------
TOK = re.compile(r"\s*(\|\||&&|!|\(|\)|,|`[^`]*`|\"(?:[^\"\\]|\\.)*\"|[A-Za-z]+)")


def parse(rule):
    toks, pos = [], 0
    while pos < len(rule):
        if rule[pos:].strip() == "":
            break
        m = TOK.match(rule, pos)
        if not m:
            raise ValueError("cannot tokenize rule at %r" % rule[pos:pos + 30])
        toks.append(m.group(1))
        pos = m.end()
    it = {"i": 0}

    def peek():
        return toks[it["i"]] if it["i"] < len(toks) else None

    def take(x=None):
        t = peek()
        if x is not None and t != x:
            raise ValueError("expected %s, got %s in %s" % (x, t, rule))
        it["i"] += 1
        return t

    def expr():
        n = term()
        while peek() == "||":
            take()
            n = ("or", n, term())
        return n

    def term():
        n = factor()
        while peek() == "&&":
            take()
            n = ("and", n, factor())
        return n

    def factor():
        t = peek()
        if t == "!":
            take()
            return ("not", factor())
        if t == "(":
            take()
            n = expr()
            take(")")
            return n
        name = take()
        if not re.match(r"^[A-Za-z]+$", name or ""):
            raise ValueError("unexpected token %r in %s" % (name, rule))
        take("(")
        args = []
        while peek() != ")":
            a = take()
            args.append(a[1:-1])
            if peek() == ",":
                take()
        take(")")
        return ("m", name, args)

    tree = expr()
    if peek() is not None:
        raise ValueError("trailing tokens in %s" % rule)
    return tree


def ev(node, path):
    """Evaluate for a GET on the artifacts host, carrying no S3/MinIO headers or query."""
    kind = node[0]
    if kind == "or":
        return ev(node[1], path) or ev(node[2], path)
    if kind == "and":
        return ev(node[1], path) and ev(node[2], path)
    if kind == "not":
        return not ev(node[1], path)
    name, args = node[1], node[2]
    if name in ("Host", "HostRegexp"):
        return True
    if name == "Method":
        return args[0] == "GET"
    if name == "Path":
        return path == args[0]
    if name == "PathPrefix":
        return path.startswith(args[0])
    if name == "PathRegexp":
        return re.search(args[0], path) is not None
    if name in ("Header", "HeaderRegexp", "Query", "QueryRegexp", "ClientIP"):
        return False
    raise ValueError("unknown matcher %s" % name)


def routes(text):
    """[(priority, match, [service names])] for every `- kind: Rule` in the rendered YAML."""
    lines = text.splitlines()
    out, cur, section = [], None, None
    for i, line in enumerate(lines):
        ind = len(line) - len(line.lstrip())
        if re.match(r"^\s*- kind: Rule\s*$", line):
            cur, section = {"priority": 0, "match": None, "services": [], "indent": ind}, None
            out.append(cur)
            continue
        if cur is None or not line.strip():
            continue
        if ind <= cur["indent"]:                       # the rule item ended
            cur = None
            continue
        m = re.match(r"^\s*([A-Za-z]+):\s*(.*)$", line)
        if m and ind == cur["indent"] + 2:
            section, rest = m.group(1), m.group(2).strip()
            if section == "priority":
                cur["priority"] = int(rest)
            elif section == "match":
                if rest in (">-", ">", "|", "|-"):
                    body = []
                    for nxt in lines[i + 1:]:
                        if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= ind:
                            break
                        body.append(nxt.strip())
                    rest = " ".join(body)
                cur["match"] = rest
            continue
        if section == "services":
            m = re.search(r"\bname:\s*([A-Za-z0-9_.-]+)", line)
            if m:
                cur["services"].append(m.group(1))
    return [(r["priority"], r["match"], r["services"]) for r in out if r["match"]]


def main():
    text = sys.stdin.read()
    rs = [(p, m, s, parse(m)) for p, m, s in routes(text)]
    # Traefik: higher priority first; on a tie the longer rule wins
    rs.sort(key=lambda r: (-r[0], -len(r[1])))
    to_proxy = [r for r in rs if any(x.startswith("oauth2-proxy") for x in r[2])]
    mention = [r for r in rs if PREFIX in r[1]]
    if not to_proxy or not mention:
        print("FAIL: no route to oauth2-proxy / for %s in the rendered chart" % PREFIX)
        return 1

    def winner(path):
        for r in rs:
            if ev(r[3], path):
                return r
        return None

    def proxied(path):
        w = winner(path)
        return w is not None and any(x.startswith("oauth2-proxy") for x in w[2])

    def canonical(upstream):
        if not upstream.startswith(PREFIX):
            return False
        rest = upstream[len(PREFIX):]
        return rest in EXACT or bool(STATIC_RE.match(rest))

    fail = 0
    for s in ROUTED:
        if not proxied(PREFIX + s):
            print("FAIL: %s%s is no longer routed to oauth2-proxy" % (PREFIX, s))
            fail = 1
    for s in BLOCKED_ROUTING:
        if proxied(PREFIX + s):
            print("FAIL: routing path %r reaches oauth2-proxy" % (PREFIX + s))
            fail = 1
    raw_routed = 0
    for t in [PREFIX + s for s in RAW] + RAW_ABS:
        res = traefik(t)
        if res is None:
            continue                                   # 400 before routing
        rpath, upstream = res
        if proxied(rpath):
            raw_routed += 1
            if not canonical(upstream):
                print("FAIL: %r reaches oauth2-proxy as %r (not an allowed endpoint)" % (t, upstream))
                fail = 1
    # errors middleware (401 -> sign_in) calls oauth2-proxy directly: an allowed endpoint
    for q in re.findall(r"^\s*query:\s*(\S+)", text, re.M):
        if q.startswith(PREFIX) and q[len(PREFIX):].split("?", 1)[0] not in EXACT:
            print("FAIL: errors middleware query %s is not an allowed endpoint" % q)
            fail = 1
    if not fail:
        print("PASS: %d rule(s) route to oauth2-proxy (%d mention %s); %d browser endpoints routed, "
              "%d routing paths blocked, %d raw spellings checked (%d routed, all as an exact "
              "allowed endpoint)" % (len(to_proxy), len(mention), PREFIX, len(ROUTED),
                                     len(BLOCKED_ROUTING), len(RAW) + len(RAW_ABS), raw_routed))
    return fail


if __name__ == "__main__":
    sys.exit(main())
