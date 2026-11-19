# The artifacts plugin contract

A **plugin** is a small service that adds a feature on top of artifacts (the canvas is
the first one). It runs next to the gate, gets one route on the artifacts host, gets one
prefix of the artifacts bucket, and **never decides access on its own** — it asks the
gate. Everything a plugin may rely on from the core is specified here; everything not
specified here is the plugin's own business.

The invariant that holds the whole design together: **who sees a plugin's data about an
artifact = who sees the artifact**, decided by the gate's single `decide()`. A plugin
must never leak an artifact's existence, content, or metadata to someone the gate would
deny.

## 1. Authorization API — `POST /_gate/plugin/authz`

The gate's decision endpoint for plugins. It lives **only on the internal (decision)
listener** (`GATE_AUTH_PORT`, default `8081`) — the same listener as `/_gate/auth`. It is
never routed publicly: the chart's public routes exclude it, and the gate itself answers
404 on the public listener. Plugin traffic must reach it cluster-internal only, and the
port must be closed to everything else by a NetworkPolicy: allow it from the reverse proxy
(forwardAuth) and the plugin pods only. The gate does not restrict callers itself; anyone
who reaches the port can ask what a cookie they hold may read (no more than they can read
at the edge, but each ask costs one proxy call and two MinIO calls).

### Request

```
POST /_gate/plugin/authz HTTP/1.1
Content-Type: application/json          (or application/x-www-form-urlencoded)
Content-Length: <n>                     (required, at most 16384; no chunked body)
Cookie: <the visitor's Cookie header, forwarded verbatim>
Authorization: <the visitor's Authorization header, if any, forwarded verbatim>

{"artifact": "/<bucket>/<key>"}         (form field `artifact=` for the form encoding)
```

Forward the visitor's `Cookie` **and** `Authorization` exactly as received; the gate
passes them to oauth2-proxy `/auth` and trusts nothing the client sent as
`X-Auth-Request-*`. The session cookie is the credential. A `Bearer` id_token in
`Authorization` counts only where oauth2-proxy runs with `--skip-jwt-bearer-tokens`: the
local compose stack sets it (its e2e reads with a Dex id_token), the Helm chart does not and
refuses it in `oauth2Proxy.extraArgs`, so behind the chart a request with a Bearer token and
no session cookie is `unauthenticated`. Send the body with a `Content-Length` (a JSON body of
at most 16 KiB): the gate refuses a chunked body (`411`) and a larger one (`413`) without
reading it. The artifact path is the public path **including the bucket name**
(path-style, same shape as the delivered links of §5): `/<bucket>/<key>` — with the
default bucket `artifacts` that is `/artifacts/<key>`; a gate configured with another
`GATE_BUCKET` only accepts that bucket's prefix.

### Response

Always JSON. `200` with a decision, or an error status (§ table below).

```json
{
  "allowed": true,
  "reason": "user",
  "user":     { "id": "alice@example.com", "name": "Alice Example", "anonymous": false },
  "artifact": { "key": "u/run-1/index.html", "expires": "2026-11-16", "ttl": 7 }
}
```

- `user.id` — the UPN (`preferred_username` via the proxy's email claim); `null` for
  anonymous. The identity: ACLs and attribution use it. `user.name` — the visitor's
  **display name**: the OIDC `name` claim of the session's id_token, which oauth2-proxy
  returns in the `Authorization` header of its `/auth` answer (`--set-authorization-header`;
  that endpoint is never routed publicly). Used only when the token is the same identity
  (its `email`/`preferred_username`/`upn` equals `user.id`), trimmed to 128 printable
  characters; otherwise, or without a `name` claim, it is `user.id`. Display only — never
  decide anything on it. `"anonymous"` for anonymous. It is **untrusted text** from the
  identity provider: control, bidi and zero-width characters are removed, but markup and
  quotes pass through (`<img src=x onerror=...>` comes back as is), so escape it wherever
  you render it, like any user input. `user.anonymous` — true when there
  was no session.
- `artifact.key` — the object key (no leading `/artifacts/`), the key the gate decided, already
  decoded once. Act on it as given and never decode it again: a second decode can turn the key
  that was decided into another one.
- `artifact.expires` — ISO date when the artifact dies: the ACL `expires` when present,
  otherwise the `ttl` object tag applied to `Last-Modified`. `null` when neither exists
  (then the bucket ILM catch-all is the only expiry).
- `artifact.ttl` — the `ttl` tag as an integer number of days, or `null`.
- `reason` — informational; only `allowed` is the decision. The exact strings:
  - allowed: `owner`, `user` (listed in `users`), `group` (member of a listed group),
    `pub: no ACL (anonymous read by design)` (a signed-in visitor on a `pub/` key without
    ACL), `pub: anonymous (anonymous-pub enabled)` (an anonymous one);
  - not allowed: `denied` (every deny `decide()` makes: not on the ACL, no ACL outside
    `pub/`, a key with no artifact root, a malformed ACL, an empty groups claim; and a
    refused identity, see below; the detail is written to the gate's log only), `expired` and
    `object-missing` (see below), `unauthenticated` (no session, and not an anonymous `pub/`
    read), `acl-error` (the ACL store could not be read, e.g. an outage: fail closed). An ACL
    object that exists but is not valid JSON, or that sets `owner` to something other than a
    string, `users` / `groups` to something other than a list or `expires` to something that is
    not a date the gate can read, is `denied` like any other unusable ACL, for everyone it
    names too, so a stranger cannot tell a broken ACL file from one that does not list them.
- **Which ACL**: the same lookup as forwardAuth. A key `u/<run>/<path>` answers to
  `u/<run>/.acl.json` and `g/<slug>/<run>/<path>` to `g/<slug>/<run>/.acl.json`, whatever the
  depth of `<path>`; an `.acl.json` below that root is never read. A key with no artifact
  root (directly under `u/` or `g/<slug>/`, `acl/…`, or outside `pub/`, `u/` and `g/`) is
  `denied` for everyone. A `pub/` key answers to its pub root, the same way:
  `pub/<run>/<path>` to `pub/<run>/.acl.json` at any depth, and a single file directly
  under `pub/` to `pub/.acl.json`. No ACL there: open to everyone, anonymous visitors included
  (anonymous read by design; anonymous answers need `GATE_ANONYMOUS_PUB_ENABLED`, see below).
- **Refused identities**: a session whose identity contains `#EXT#` (a directory guest's
  UPN) gets `allowed: false`, `reason: "denied"`, `user.id` and `user.name` null, for every
  key; the gate's other endpoints refuse it with `403` too.
- **No existence leak**: `expired` and `object-missing` — and `artifact.expires`/`ttl` — are
  told only to a visitor who would otherwise be allowed (listed, owner, group member, or
  anonymous on a `pub/` key without ACL). Anyone else gets `denied` with `expires`/`ttl`
  null: the same answer for a live artifact they are not on, an expired one, a missing one,
  and a directory with or without an ACL, so a plugin answering `410` for `expired` and `403`
  for a deny reveals nothing to a stranger. The forwardAuth path already answers all of them
  with the same 403 deny page.

### Status codes

| Status | When |
|---|---|
| `200` | A decision was made (including `allowed: false` — a denial is not an HTTP error) |
| `400` | Body/path malformed: missing `artifact`, not an `/artifacts/` path, or the path is refused outright (traversal, `.acl.json`, `_gate/`, `_plugins/`, `_mcp/`, trailing slash, a key that is not UTF-8 once decoded: `%ef`, `%ff`); or an invalid or repeated `Content-Length` |
| `405` | Any method other than POST |
| `411` | No `Content-Length`, or any `Transfer-Encoding` (chunked): the body is not read |
| `413` | `Content-Length` above 16384: the body is not read |
| `408` | The body did not arrive within 10 s of the headers; the connection is closed |
| `500` | Identity backend (oauth2-proxy) error — fail closed, deny the visitor |
| `404` | Request hit the public listener (the endpoint is not routed there) |

### Anonymous visitors

With no session the answer is `allowed: true` **only** for keys under the pub prefixes
(default `pub/`) **and** only while `GATE_ANONYMOUS_PUB_ENABLED` (helm
`artifactsGate.anonymousPubEnabled`) is true **and** only for a key the gate's anonymous read
decision would also take: a key that, decoded once, contains `..`, `//`, `\`, `;`, `%`, `#`,
`?` or a control character is never allowed anonymously. Otherwise `200` with
`{"allowed": false, "reason": "unauthenticated"}`. The flag must be false before the
host is reachable outside a trusted network, and the chart refuses to render with
`anonymousPubEnabled: true` together with `publicExposure: true`. An anonymous visitor on a
`pub/` key whose pub root has an ACL gets `denied`; the gate's own anonymous read decision
(`/_gate/pub-auth`, used when the chart routes `pub/` through the gate) refuses the same
key, so a plugin and the artifact read agree.

### When to call

On every connect (HTTP request, WebSocket handshake) **and periodically** (recommended:
every few minutes) for long-lived connections, so a revoked user or an expired artifact
drops out of an open session. On any `allowed: false`, `400`, or `500`: drop the
visitor, delete nothing of theirs yet — see §4 for when data must go.

## 2. Routes

A plugin is declared in the chart values and the chart renders its route on the
artifacts host:

```yaml
plugins:
  - name: canvas          # DNS-1123 label ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$; route and storage prefix derive from it
    pathPrefix: /_canvas/ # ^/_[a-z0-9_-]+(/[a-z0-9_-]+)*/$: starts with /_, ends with /
    service: artifact-canvas
    port: 8080
    namespace: sso        # optional, defaults to the gate's namespace
    defaultView: false    # optional boolean, true on at most one plugin: see §6
```

- Routes are matched **above** the artifact routes (higher priority), so a plugin owns
  its whole prefix.
- Reserved prefixes a plugin may not claim: `/_gate/`, `/_plugins/`, `/oauth2-artifacts/`.
  Traefik `PathPrefix` is a plain string prefix, so the chart fails to render both a
  prefix **under** a reserved path (`/_gate/x/`) and one that **covers** it (`/_gate`,
  `/_ga`, `/_`), as well as a prefix without the trailing `/`.
- The prefix is written into the Traefik rule as is, so it may hold only lowercase letters,
  digits, `_` and `-` in `/`-separated segments; the chart refuses anything else (a backtick,
  a space, a dot segment, upper case). The host names the route matches
  (`artifactsHost`, `artifactsExtraHosts`) must be lowercase DNS names for the same reason.
- The route carries the chart's `ingressRouteAnnotations` (for example the ingress class
  your Traefik watches), like the core's own routes.
- The core never proxies plugin traffic itself beyond this route, and never rewrites it.
  WebSockets are the plugin's business (the chart route is plain pass-through).
- A plugin's own pages must not weaken the artifact isolation: artifact content is
  served with `Content-Security-Policy: sandbox allow-scripts` (opaque origin). Plugin
  pages hold the user's session; artifact iframes must not gain access to them.

**Local compose stack.** `deploy/compose/` renders the same route with Caddy: a plugin's
compose file sets `ARTIFACTS_CADDY_PLUGINS="import plugin /_<name>/ <service>:<port>"` (and
`ARTIFACTS_PLUGIN_USERS="<name>:<secret>"` for its S3 user, §3) — see the README, "Plugins in
the compose stack".

## 3. Storage

- Each plugin owns the bucket prefix **`_plugins/<name>/`** and nothing else.
- The bootstrap Job (runs on install/upgrade) creates a least-privilege S3 user per
  plugin: `plugin-<name>` with Get/Put/Delete/GetTagging/PutTagging on
  `_plugins/<name>/*` and ListBucket on the bucket restricted to that prefix. The
  plugin's credentials are a secret the operator supplies (`secretName` in the plugin
  values entry); the Job only (re)creates the policy and attaches it.
- **The core never serves `_plugins/`** — not over the public routes, not through
  forwardAuth, not through the plugin authz endpoint (it answers 400). Same for
  `_gate/` (gate state), `_mcp/` and any `.acl.json`, at an artifact root or below it.
- Plugin objects should carry the artifact's `ttl` tag when they must die with the
  artifact; the bucket ILM catch-all (90 days by default) also covers `_plugins/`, so
  a forgotten object still goes away.

## 4. Expiry

The authz answer carries `artifact.expires` / `artifact.ttl` (§1). Plugins must:

- refuse a room/section whose artifact is gone (authz said `object-missing`, or HEAD
  fails) and **delete their data for it**;
- delete their data when the artifact's `expires` passes (periodic sweep; the authz
  call already gives you the date);
- never let plugin data outlive the artifact.

## 5. Discovery

The publisher CLI (`cli/publish.sh`) and the MCP server (`mcp/server.py`) print, next to
the artifact link, **one link per enabled plugin** so publishers hand out ready-made
"open with <plugin>" links:

```
INDEX (deliver this link): https://artifacts.example.com/artifacts/pub/run-1/index.html
  open with canvas: https://artifacts.example.com/_canvas/artifacts/pub/run-1/index.html
```

Both read the same config: `ARTIFACTS_PLUGINS="canvas=/_canvas/;other=/_other/"`
(name=prefix pairs; the prefix must look like `/_<name>/`). The link shape is
`<read_base><plugin prefix><bucket>/<key>` — the plugin is responsible for what it does
with the path it receives (it must then authorize it via §1).

## 6. Default view

One plugin may be the **default view** of HTML artifacts: a signed-in visitor who opens an
HTML artifact lands on that plugin's page for it (the link of §5, `<prefix><bucket>/<key>`)
instead of the bare file. The canvas uses it so that a report opens with its annotations one
click away; its page shows the artifact itself in a sandboxed iframe.

```yaml
plugins:
  - name: canvas
    pathPrefix: /_canvas/
    service: artifact-canvas
    port: 8080
    defaultView: true     # a boolean, false when absent; true on at most one plugin
```

The chart turns it into the gate's `GATE_DEFAULT_VIEW_PREFIX` and
`GATE_DEFAULT_VIEW_HEALTH_URL` (`http://<service>.<namespace>.svc.cluster.local:<port><prefix>healthz`,
from the same entry; the compose stack: `ARTIFACTS_DEFAULT_VIEW_PREFIX` and
`ARTIFACTS_DEFAULT_VIEW_HEALTH_URL`), and refuses a value that is not a boolean or a second
plugin with `true`. Absent or `false` everywhere, the default: the chart renders as before, and
the gate answers as before with one exception, the opt-out below: an allowed read with exactly
`?raw=1` serves the same bytes as the bare read.

**When the gate redirects.** The gate answers an artifact read with `302` and
`Location: https://<PUBLIC_HOST><prefix><bucket>/<key>`, instead of signing it, only when all
of these hold:

1. the read was **allowed**: the visitor may read the artifact and it exists. The redirect is
   decided after the ACL, never instead of it;
2. the visitor has a valid session. An allowed read on the forwardAuth decision
   (`/_gate/auth`) always has one. On the anonymous `pub/` decision (`/_gate/pub-auth`, when
   `pub/` goes through the gate) the gate asks the login proxy, only once every other
   condition holds and for at most 2 s; without a session, with a refused one, or while the
   proxy fails or is slow, the page is served plain. The `pub/` redirect is best effort;
3. the method is `GET`;
4. the request is a top-level navigation: exactly one `Sec-Fetch-Dest: document` and exactly
   one `Sec-Fetch-Mode: navigate`;
5. the key is under `u/`, `g/` or a pub prefix, inside an artifact root, and its last segment
   ends in `.html` or `.htm` (any case);
6. the request has no query string;
7. the request's host (`X-Forwarded-Host`, else `Host`) is `PUBLIC_HOST`;
8. the plugin answered its health check (below). This is a read of the last result, never a
   request: on `/_gate/auth` it comes after every other condition; on `/_gate/pub-auth` it
   comes before the session, so a plugin that is down costs no login-proxy call.

**Unchanged:** `HEAD`, iframes (`Sec-Fetch-Dest: iframe`, the plugin's own frame of the
artifact), subresources, fetches, clients that send no `Sec-Fetch-*` (curl, scripts), every
other file, every other host, visitors without a session (an anonymous `pub/` read stays the
plain page, since the plugin would ask them to sign in), and every refusal: a denied, missing,
malformed or refused read gets the answer it gets without a default view, status, headers and
body alike. So the redirect never tells anyone that an artifact exists unless they may read it.

**Opt-out: `?raw=1`.** The query string `raw=1`, exactly that text and nothing beside it, is
signed and passed to the store (which ignores it), and the read is served as the plain page.
It is accepted with or without a default view, so a plugin's link to the plain page works in any
rollout order and after the default view is turned off. Every other query is still refused
(`404`). A plugin links to `<artifact link>?raw=1` to offer the original. That the store ignores
`raw` is a property of the store build: check it again when the store changes (bare against
`?raw=1`: same status, headers and body).

**Health check.** Before it redirects, the gate checks that the plugin answers
`GET <prefix>healthz` on its Service (`GATE_DEFAULT_VIEW_HEALTH_URL`, from configuration only):

- a fixed request: `GET`, no cookie, no `Authorization`, no visitor header of any kind;
- 2xx is up; any other status, a redirect (never followed), an error, or no status line within
  1 s in total is down. Only the status is used: the body is never read or logged;
- one background thread per gate probes every 5 s for as long as the gate runs, whatever the
  traffic; a request only reads the last result, so none waits and none sends anything.
  The read is served plain while the last result is down, before the first result (the
  first moments after the gate starts), and when the last result is older than 15 s (a
  probe thread that stopped);
- the gate logs the first result and every change between up and down.

The check proves the plugin is **reachable, not that it is authentic**: a service that answers
2xx there is trusted exactly as much as without the check. After the plugin goes down, up to
about 6 s of redirects to it can still happen (one probe interval plus the deadline).

**The `Location`** is absolute, because Traefik's forwardAuth resolves a relative one against
the gate's own address. Its scheme (`GATE_PUBLIC_SCHEME`, `https`; the compose stack sets
`http`) and host (`PUBLIC_HOST`) are configuration, its prefix is the plugin's route prefix
(the gate refuses to start on anything else, a core path included), and the rest is the
decided key, percent-encoded once with only `/` kept: a single decode by the plugin gives the
key back. Nothing else from the request (its host, its raw path, a query) is written into it.
The `302` carries `Cache-Control: no-store` and no signature.

**Where it does not apply.** With anonymous `pub/` served straight from the store
(`artifactsGate.anonymousPubEnabled` with `anonymousPubThroughGate: false`, the chart's
default) the gate never sees a `pub/` read, so `pub/` artifacts open plain. With
`anonymousPubThroughGate: true`, or with anonymous `pub/` off, they follow the rules above.
Browsers send `Sec-Fetch-*` only to HTTPS and `localhost` origins, and browsers without Fetch
Metadata send none: those visitors get the plain page.

**What the plugin must do.**

- Answer 2xx on `GET <prefix>healthz` only while it can serve its pages, quickly and without
  calling anything slow; never redirect there.
- Serve `<prefix><bucket>/<key>` for every HTML artifact a visitor may read, authorizing it
  through §1 like any other request.
- Show the artifact in an iframe of `/<bucket>/<key>` (never redirected: `Sec-Fetch-Dest:
  iframe`) or through its own frame route. Never send the top-level window to the bare artifact
  link without `?raw=1`: that comes straight back to the plugin.
- A browser that already holds a fresh cached copy of the artifact may show it on a top-level
  navigation without asking (the store's own caching headers); the `302` itself is never
  cached.

## Rules for plugin authors (summary)

1. Never re-implement the decision. Call `POST /_gate/plugin/authz` (§1).
2. Treat `allowed: false`, `400` and `500` as deny.
3. Re-check periodically on long-lived connections.
4. Stay inside `_plugins/<name>/`; tag your data; delete it when the artifact dies.
5. Do not serve artifact content yourself; the core already does, with the CSP sandbox.
6. Do not trust client-supplied identity headers; identity exists only as far as the
   gate's answer says.
7. As the default view (§6), answer `GET <prefix>healthz`, serve the artifact in an iframe or
   your own frame route, and link to `?raw=1` for the plain page; never navigate the top-level
   window to the bare link.
