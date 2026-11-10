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
404 on the public listener. Plugin traffic must reach it cluster-internal only.

### Request

```
POST /_gate/plugin/authz HTTP/1.1
Content-Type: application/json          (or application/x-www-form-urlencoded)
Cookie: <the visitor's Cookie header, forwarded verbatim>
   — or —
Authorization: Bearer <id_token>        (validated by oauth2-proxy, skip-jwt-bearer-tokens)

{"artifact": "/<bucket>/<key>"}         (form field `artifact=` for the form encoding)
```

Forward the visitor's `Cookie` **and** `Authorization` exactly as received; the gate
passes them to oauth2-proxy `/auth` and trusts nothing the client sent as
`X-Auth-Request-*`. The artifact path is the public path **including the bucket name**
(path-style, same shape as the delivered links of §5): `/<bucket>/<key>` — with the
default bucket `artifacts` that is `/artifacts/<key>`; a gate configured with another
`GATE_BUCKET` only accepts that bucket's prefix.

### Response

Always JSON. `200` with a decision, or an error status (§ table below).

```json
{
  "allowed": true,
  "reason": "acl: users",
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
  decide anything on it. `"anonymous"` for anonymous. `user.anonymous` — true when there
  was no session.
- `artifact.key` — the object key (no leading `/artifacts/`).
- `artifact.expires` — ISO date when the artifact dies: the ACL `expires` when present,
  otherwise the `ttl` object tag applied to `Last-Modified`. `null` when neither exists
  (then the bucket ILM catch-all is the only expiry).
- `artifact.ttl` — the `ttl` tag as an integer number of days, or `null`.
- `reason` — the exact string `decide()` produced (e.g. `owner`, `acl: users`,
  `acl: groups`, `pub: any signed-in`, `pub: anonymous (anonymous-pub enabled)`,
  `no-acl`, `expired`, `groups-claim-empty`, `unauthenticated`, `acl-error`,
  `object-missing`). Plugins must treat `reason` as informational; only `allowed` is
  the decision.
- **No existence leak**: `expired` and `object-missing` — and `artifact.expires`/`ttl` — are
  told only to a visitor who would otherwise be allowed (listed, owner, group member, or
  anonymous on a `pub/` key without ACL). Anyone else gets exactly the answer they would get
  for a live artifact they are not on (e.g. `not-listed`, `expires`/`ttl` null), so a plugin
  answering `410` for `expired` and `403` for a deny reveals nothing to a stranger. The
  forwardAuth path already answers both with the same 403 deny page.

### Status codes

| Status | When |
|---|---|
| `200` | A decision was made (including `allowed: false` — a denial is not an HTTP error) |
| `400` | Body/path malformed: missing `artifact`, not an `/artifacts/` path, or the path is refused outright (traversal, `.acl.json`, `_gate/`, `_plugins/`, trailing slash) |
| `405` | Any method other than POST |
| `500` | Identity backend (oauth2-proxy) error — fail closed, deny the visitor |
| `404` | Request hit the public listener (the endpoint is not routed there) |

### Anonymous visitors

With no session the answer is `allowed: true` **only** for keys under the pub prefixes
(default `pub/`) **and** only while `GATE_ANONYMOUS_PUB_ENABLED` (helm
`artifactsGate.anonymousPubEnabled`) is true. Otherwise `200` with
`{"allowed": false, "reason": "unauthenticated"}`. The flag must be false before the
host is reachable outside a trusted network, and the chart refuses to render with
`anonymousPubEnabled: true` together with `publicExposure: true`.

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
    pathPrefix: /_canvas/ # must start with /_ and end with /
    service: artifact-canvas
    port: 8080
    namespace: sso        # optional, defaults to the gate's namespace
```

- Routes are matched **above** the artifact routes (higher priority), so a plugin owns
  its whole prefix.
- Reserved prefixes a plugin may not claim: `/_gate/`, `/_plugins/`, `/oauth2-artifacts/`.
  Traefik `PathPrefix` is a plain string prefix, so the chart fails to render both a
  prefix **under** a reserved path (`/_gate/x/`) and one that **covers** it (`/_gate`,
  `/_ga`, `/_`), as well as a prefix without the trailing `/`.
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
  `_gate/` (gate state) and any `.acl.json`.
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

## Rules for plugin authors (summary)

1. Never re-implement the decision. Call `POST /_gate/plugin/authz` (§1).
2. Treat `allowed: false`, `400` and `500` as deny.
3. Re-check periodically on long-lived connections.
4. Stay inside `_plugins/<name>/`; tag your data; delete it when the artifact dies.
5. Do not serve artifact content yourself; the core already does, with the CSP sandbox.
6. Do not trust client-supplied identity headers; identity exists only as far as the
   gate's answer says.
