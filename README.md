# artifacts

Self-hostable artifact hosting: publish a file (or an HTML report) behind your OIDC
login, hand out a link, and let the **gate** decide who opens it — per-artifact ACLs
(owner / users / groups / expiry), anonymous `pub/` reads while your host is not
publicly exposed, request-access links with one-click approve/deny, and automatic
expiry. Plugins (a live canvas, …) mount on the same host under `/_<name>/` and ask the
gate for every access decision.

No vendor lock-in: everything is config (hostnames, OIDC issuer, bucket, credentials),
the gate is one stdlib-only Python file, and the whole stack runs on plain Kubernetes
(Helm) or on your laptop with Docker Compose.

## How it works

```
 visitor ──HTTPS── reverse proxy (Traefik / Caddy)
                     ├── /artifacts/**  reads ──forwardAuth──> gate :8081 /_gate/auth ──> oauth2-proxy /auth
                     │        │ allowed ──> MinIO, signed by the gate   denied ──> 302 /oauth2/sign_in
                     │        └ every response: CSP `sandbox allow-scripts` (opaque origin)
                     ├── POST /artifacts/** ──> gate :8080  (request-access, approve, deny)
                     ├── /_gate/** (except auth/healthz) ──> gate :8080
                     ├── /oauth2/{sign_in,start,callback,sign_out,static/*} ──> oauth2-proxy (allow-list; rest 404)
                     └── /_<plugin>/** ──> plugin service        (plugin → gate :8081 /_gate/plugin/authz)
```

- **Identity**: oauth2-proxy in front of your OIDC provider. The gate authenticates by
  calling the proxy's `/auth` with the visitor's cookie (or a `Bearer` id_token) and
  never trusts client-supplied `X-Auth-Request-*` headers.
- **Authorization**: one `decide()` in `gate/gate.py` — ACL file `<dir>/.acl.json`
  (`owner`, `users`, `groups`, `expires`); no ACL → any signed-in user for `pub/`,
  deny elsewhere. The same function answers forwardAuth and the plugin authz API.
- **Signed upstream reads**: the bucket has no anonymous read policy outside `pub/`. On
  allow, the gate answers forwardAuth with SigV4 headers (`Authorization`, `X-Amz-Date`,
  `X-Amz-Content-Sha256`) for that exact method, host, path and query, signed with a
  **dedicated read-signing S3 user** (`GATE_READ_ACCESS_KEY`: `s3:GetObject` on the bucket,
  explicit Deny on `_gate/*`, `_plugins/*` and every `.acl.json`, nothing else); the proxy
  copies them onto the MinIO request (Traefik `authResponseHeaders`, Caddy `copy_headers`).
  The gate's other S3 user (`MINIO_ACCESS_KEY`) does the ACL/state work and never signs a
  forwarded read; neither is MinIO root.
- **No query strings, no client S3 headers**: the query allow-list is empty, so any `?` on
  an artifact read (`?acl`, `?lambdaArn=`, `?versionId`, `response-*`, even `?v=2` or a bare
  `?`) answers 404 and is never signed. A forwarded read carrying any `x-amz-*` or
  `x-minio-*` request header is refused with 400 before the gate signs anything.
- **Two listeners, one process**: `:8080` public (request-access pages, approve/deny
  links, health) and `:8081` internal (decision endpoints only: `/_gate/auth`,
  `/_gate/plugin/authz`). The public routes never reach the decision listener.
- **Expiry**: objects carry a `ttl` tag (`1|7|14|30` days), ILM expires by tag, and a
  catch-all (90 days) takes everything untagged — including `_plugins/`.
- **Never served**: directory listings, `.acl.json`, `_gate/` (gate state), `_plugins/`
  (plugin storage), and any path with a `.`/`..` segment.

## Quick start (laptop, Docker Compose)

```bash
git clone https://github.com/pocharlies-org/artifacts.git && cd artifacts
cd deploy/compose
python3 -m venv .venv && .venv/bin/pip install markdown   # publisher renders .md inputs
export PATH="$PWD/.venv/bin:$PATH"   # (a plain `pip install` works too; e2e.sh does this itself)
docker compose up -d          # MinIO + Dex (test user) + oauth2-proxy + gate + Caddy
docker compose up bootstrap   # bucket, ILM rules, anonymous pub/ policy, gate S3 users
./e2e.sh                      # publishes with the real CLI, checks reads and negatives
```

Then open <http://127.0.0.1:8080/artifacts/pub/<run>/index.html> — anonymous `pub/`
reads work; gated reads (`/artifacts/u/...`) redirect to Dex login. Dex has three static
dev users: `test@example.com` / `test-password`, `test2@example.com` / `test2-password` and
`test3@example.com` / `test3-password` (the extra two let plugins test sharing and refusals),
with the display names *Test One*, *Test Two* and *Test Three* (the id_token `name` claim that
the plugin authz answer carries as `user.name`; the ACLs use the e-mails).
Publish your own:

```bash
ARTIFACTS_ACCESS_KEY=minioadmin ARTIFACTS_SECRET_KEY=minioadmin \
ARTIFACTS_WRITE_BASE=http://127.0.0.1:9000 ARTIFACTS_READ_BASE=http://127.0.0.1:8080 \
../../cli/publish.sh -g pub -t 7 -a me -s demo ../../examples/report.html
```

> The compose stack is a **dev/demo** stack with fixed low-entropy dev secrets — never
> expose it beyond localhost (all ports bind `127.0.0.1`). The gate runs with the two
> non-root users `bootstrap.sh` creates (`artifact-gate`, `artifact-reader`); it also creates
> `artifact-publisher` / `artifact-publisher-dev-password` (the chart's publisher policy, no
> `_gate/` or `_plugins/` writes). MinIO root (`minioadmin`) is used only by `bootstrap.sh`
> and by the example publisher commands. MinIO runs from
> `bitnamilegacy/minio` (digest-pinned): a **frozen legacy mirror**, because the
> original `minio/minio`/`minio/mc` RELEASE tags were removed from Docker Hub; it
> bundles the `mc` client at `/opt/bitnami/minio-client/bin/mc`.

### Plugins in the compose stack

A plugin joins this stack **without editing it**: its own compose file `include:`s
`deploy/compose/docker-compose.yml`, adds its service, and sets the stack's plugin
variables (empty by default):

| Variable | Effect |
|---|---|
| `ARTIFACTS_CADDY_PLUGINS` | Caddy lines, one per plugin: `import plugin /_<name>/ <service>:<port>` — routes the whole prefix (WebSockets included) to the plugin, like the chart's plugin routes |
| `ARTIFACTS_PLUGIN_USERS` | `<name>:<secret>[,…]` — `bootstrap.sh` creates S3 user `plugin-<name>` with the policy of docs/plugins.md §3 (`_plugins/<name>/*` only) |
| `GATE_ACL_CACHE_SECONDS` | the gate's ACL cache (default 15 s); lower it to see revocations quickly |

The plugin asks the real gate (`http://gate:8081/_gate/plugin/authz`) and uses the real
MinIO (`http://minio:9000`). `e2e.sh` keeps passing with plugins enabled (run it from this
directory; it finds the running project by name). The canvas plugin ships such a file:
[`pocharlies-org/artifacts-canvas`](https://github.com/pocharlies-org/artifacts-canvas),
`deploy/compose/compose.yml` — with both repos cloned side by side:

```bash
git clone https://github.com/pocharlies-org/artifacts.git
git clone https://github.com/pocharlies-org/artifacts-canvas.git
cd artifacts-canvas/deploy/compose
docker compose up -d --build --wait     # core + canvas (bootstrap included)
# open http://127.0.0.1:8080/_canvas/artifacts/<key> (the CLI prints the link)
```

## Quick start (Kubernetes)

```bash
helm upgrade --install artifacts ./helm/artifacts \
  --namespace sso --create-namespace \
  --set oidcIssuer=https://login.microsoftonline.com/<tenant-id>/v2.0 \
  --set artifactsHost=artifacts.example.com
```

Prerequisites and what the chart does:

- An oauth2-proxy secret (`OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `COOKIE_SECRET`) in
  the `.Values.secretName` secret, and MinIO root credentials in
  `.Values.bootstrap.adminSecretName`.
- The gate code ships in one of two ways (`gate.bakedImage`):
  - **ConfigMap** (default): a stock Python image plus the code mounted from a ConfigMap
    you create from this repo (`kubectl -n sso create configmap artifact-gate-code
    --from-file=gate/gate.py --dry-run=client -o yaml | kubectl apply -f -`), same cadence
    as the chart.
  - **Gate image** (`--set gate.bakedImage=true --set gate.bakedImageDigest=sha256:…`): the
    code is inside the image, referenced by digest; no ConfigMap. See [Gate image](#gate-image).
- The bootstrap Job (helm hook) creates the bucket, the ILM rules, the anonymous `pub/`
  policy, and the least-privilege S3 users: `artifact-gate` (GetObject + GetObjectTagging
  on `artifacts/*`, PutObject only on `*/.acl.json` and `_gate/*`; ACL/state work),
  `artifact-gate-read` (GetObject on `artifacts/*` with an explicit Deny on `_gate/*`,
  `_plugins/*` and every `.acl.json`; signs the forwarded reads only),
  `artifact-publisher` (optional; Put/Get/tagging on `artifacts/*` including `.acl.json`,
  ListBucket, explicit Deny on `_gate/*` and `_plugins/*`), and one `plugin-<name>` per
  declared plugin.
- Gate secrets (`artifact-gate-s3`, `artifact-gate-read-s3`, keys `access-key` /
  `secret-key`, two **different** users; optional `artifact-gate-slack`) are created out of
  band — nothing secret goes through git. The S3 ones are needed in the gate's namespace
  (`namespaces.sso`) and in the bootstrap Job's (`minio.namespace`).

## Gate image

`gate/Dockerfile` puts `gate/gate.py` on a digest-pinned `python:3.12-slim` and nothing else:
stdlib only (no pip install, no added package, no tests; pending Debian updates are applied at
build time, so re-running the publish job at the same commit picks up new base fixes), code at
`/app/gate.py` (the same path and command as
the ConfigMap mode), numeric non-root user `1000:1000`, `PYTHONDONTWRITEBYTECODE=1`, and no
file written at runtime, so it runs with a read-only root filesystem. It carries the labels
`org.opencontainers.image.source` and `org.opencontainers.image.revision` (the commit).

Every commit on `main` is published by `.github/workflows/publish.yml` (and only there:
branches and pull requests build and smoke-test the image in CI, never push it) as
`ghcr.io/pocharlies-org/artifacts-gate:<40-hex commit>` for `linux/amd64`, with a signed
build provenance attestation. The tag is only for finding the image; deploy and verify the
**digest**:

```bash
sha=<40-hex commit on main>
digest=$(docker buildx imagetools inspect "ghcr.io/pocharlies-org/artifacts-gate:$sha" \
           --format '{{json .Manifest}}' | jq -r .digest)        # or: crane digest <image>:<sha>
gh attestation verify "oci://ghcr.io/pocharlies-org/artifacts-gate@$digest" \
  -R pocharlies-org/artifacts \
  --signer-workflow pocharlies-org/artifacts/.github/workflows/publish.yml \
  --source-ref refs/heads/main --source-digest "$sha" --deny-self-hosted-runners
```

`--source-digest` binds the attestation to that commit; without it any commit built by the
workflow would pass.

**Helm**: no ConfigMap to create. If you copy the image into your own registry, copy it by
digest and point `gate.bakedImageRepository` at the copy (the digest stays the same).

```bash
helm upgrade --install artifacts ./helm/artifacts --namespace sso \
  --set gate.bakedImage=true --set gate.bakedImageDigest="$digest"     # plus your other values
# copied into your own registry? add: --set gate.bakedImageRepository=registry.example.com/mirror/artifacts-gate
```

The chart renders `<gate.bakedImageRepository>@<gate.bakedImageDigest>` and refuses a missing
or malformed digest, a repository with a tag, and a non-boolean `gate.bakedImage`.

**Docker** (same settings as the [gate configuration](#gate-gategatepy); the HMAC key file
must be readable by uid 1000):

```bash
docker run --rm --read-only --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges \
  -p 127.0.0.1:8080:8080 -p 127.0.0.1:8081:8081 \
  -e MINIO_ENDPOINT=http://minio:9000 \
  -e MINIO_ACCESS_KEY=… -e MINIO_SECRET_KEY=… \
  -e GATE_READ_ACCESS_KEY=… -e GATE_READ_SECRET_KEY=… \
  -e OAUTH2_AUTH_URL=http://oauth2-proxy:4180/oauth2/auth \
  -v "$PWD/hmac-key:/secrets/hmac-key:ro" \
  "ghcr.io/pocharlies-org/artifacts-gate@$digest"
curl -s http://127.0.0.1:8080/_gate/healthz        # ok
```

**Build and check it yourself** (from the repository root; the root `.dockerignore` lets only
`gate/gate.py` into the build context):

```bash
docker build -f gate/Dockerfile --build-arg REVISION="$(git rev-parse HEAD)" -t artifacts-gate:dev .
tests/gate_image_smoke.sh artifacts-gate:dev "$(git rev-parse HEAD)"
```

The compose stack keeps the stock Python image with `gate/gate.py` mounted, so edits to the
gate show up without a rebuild.

## Publishing

**CLI** — `cli/publish.sh` (bash + curl, SigV4): renders an `index.html` around your
files (audience banner, provenance), writes the ACL **before** the objects for gated
runs, verifies the link anonymously, and prints the artifact link plus one link per
enabled plugin.

```bash
publish.sh -u alice@example.com -t 14 -a build -s 42 examples/report.html   # gated (u/<run>/)
publish.sh -g pub -t 7 examples/report.html                                 # anonymous pub/
publish.sh -g <group-slug> -t 7 examples/report.html                        # group-gated
```

**MCP** — `mcp/server.py` (Python, `mcp` SDK, stdio) for agent sessions:
`publish_html`, `publish_file`, `list_artifacts`, `delete_artifact`. Same ACL-before-
object ordering, same plugin links.

```json
{"mcpServers": {"artifacts": {"command": "python3",
  "args": ["/path/to/artifacts/mcp/server.py"], "env": { "…see below…": "" }}}}
```

## Configuration reference

Everything is environment-driven; nothing is hardcoded.

### Gate (`gate/gate.py`)

| Variable | Default | Meaning |
|---|---|---|
| `GATE_BUCKET` | `artifacts` | bucket served |
| `MINIO_ENDPOINT` | — | S3 endpoint (path-style) |
| `MINIO_ACCESS_KEY` / `MINIO_SECRET_KEY` | required | least-privilege gate user (ACL + `_gate/` state work) |
| `GATE_READ_ACCESS_KEY` / `GATE_READ_SECRET_KEY` | required | read-signing user: signs forwarded reads only; must differ from the gate user (the gate refuses to start otherwise) |
| `OAUTH2_AUTH_URL` | required | oauth2-proxy `/auth` URL |
| `HMAC_KEY_B64` / `HMAC_KEY_FILE` | `/secrets/hmac-key` | signs approve/deny tokens |
| `PUBLIC_HOST` | `artifacts.example.com` | host used in generated links |
| `SLACK_BOT_TOKEN` | empty | optional DM notification on access requests |
| `GATE_PUB_PREFIXES` | `pub/` | comma list treated as "any signed-in user" without ACL |
| `GATE_ANONYMOUS_PUB_ENABLED` | `false` | anonymous reads of `pub/` (plugin authz); must stay false on public hosts |
| `GATE_STATE_PREFIX` | `_gate` | gate state prefix (never served) |
| `GATE_PLUGIN_PREFIX` | `_plugins` | plugin storage prefix (never served) |
| `GATE_RATE_LIMIT_MAX` / `GATE_RATE_LIMIT_WINDOW_SECONDS` | `5` / `86400` | access requests per key |
| `GATE_TOKEN_TTL_SECONDS` / `GATE_CSRF_TTL_SECONDS` | `604800` / `3600` | approve/deny link, CSRF |
| `GATE_ACL_CACHE_SECONDS` | `15` | ACL cache |
| `GATE_PORT` / `GATE_AUTH_PORT` | `8080` / `8081` | public / decision listeners |

### Publisher CLI (`cli/publish.sh`)

`ARTIFACTS_WRITE_BASE` (S3 write host), `ARTIFACTS_READ_BASE` (link host),
`ARTIFACTS_BUCKET` (`artifacts`), `ARTIFACTS_REGION` (`us-east-1`),
`ARTIFACTS_ACCESS_KEY` / `ARTIFACTS_SECRET_KEY` (required), `ARTIFACTS_OWNER`,
`ARTIFACTS_GROUPS` (`slug=<id>;…` for `-g <slug>`), `ARTIFACTS_PLUGINS`
(`canvas=/_canvas/;…`). Env wins over the config file
(`~/.config/artifacts/publish.conf`, `KEY=VALUE` lines, `ARTIFACTS_CONFIG` to relocate).

### MCP (`mcp/server.py`)

`ARTIFACTS_ENDPOINT`, `ARTIFACTS_BUCKET`, `ARTIFACTS_REGION`,
`ARTIFACTS_ACCESS_KEY` / `ARTIFACTS_SECRET_KEY`, `ARTIFACTS_READ_BASE`,
`ARTIFACTS_PLUGINS`, `ARTIFACTS_OWNER`, `ARTIFACTS_PUBLISHER`.

### Helm (`helm/artifacts/values.yaml`)

`oidcIssuer`, `secretName`, `artifactsHost` / `artifactsExtraHosts`, `publicExposure`
(must be `true` only for real public hosts), `artifactsGate.anonymousPubEnabled`
(chart refuses `true` together with `publicExposure`), `minio.*`, `gate.*`,
`bootstrap.*`, and `plugins: []` — see `docs/plugins.md`. `gate.s3SecretName` /
`gate.readS3SecretName` name the gate user and the read-signing user secrets.
`gate.bakedImage` (default `false`) switches from the ConfigMap mode (`gate.image` + ConfigMap
`artifact-gate-code`) to the gate image `gate.bakedImageRepository@gate.bakedImageDigest`
(see [Gate image](#gate-image)). Plugin
names must be DNS-1123 labels (`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`): the chart refuses
anything else.

## Security notes

- **SigV4 replay window**: the headers the gate hands to the proxy are a normal SigV4
  signature over one read (method, Host, path, empty query). MinIO accepts a signature
  for about **15 minutes** around its `X-Amz-Date`, so anyone who captures that header
  set can replay that exact read in that window. They never reach the visitor; keep it
  that way:
  - keep proxy access logs from recording request headers. Traefik's default
    `accessLog.fields.headers.defaultMode: drop` is correct; do not switch it to `keep`
    (or `keep` `Authorization`), and do not log forwardAuth responses at debug level in
    production. Caddy redacts `Authorization` in access logs unless `log_credentials`
    is enabled; leave it off.
  - the read-signing user can only `GetObject` outside `_gate/`, `_plugins/` and the
    ACLs, so a replayed signature reads at most the artifact it was issued for.
- **Edge before MinIO**: query strings and client `x-amz-*` / `x-minio-*` headers never
  reach MinIO on a gated read (see "How it works"). The anonymous `pub/` rule serves
  straight from MinIO without the gate: there the anonymous bucket policy is the only
  authority, and `.acl.json` / trailing-slash paths are refused at the proxy.
- **Never MinIO root at runtime**: the gate uses two least-privilege users; root is
  only for the bootstrap.

## Plugins

The plugin contract (authz API, routes, storage prefixes, expiry, discovery) is the
public API other plugins build against: **[docs/plugins.md](docs/plugins.md)**.

## Tests

```bash
python3 -I -m unittest discover -s tests              # unit (gate + mcp lib)
python3 -I -m unittest discover -s tests -p 'e2e_*.py' # e2e vs fake MinIO + fake proxy
helm lint helm/artifacts && helm template t helm/artifacts -f helm/artifacts/values.yaml
helm template t helm/artifacts -f helm/artifacts/values.yaml | python3 -I tests/check_oauth2_routes.py
python3 -I tests/check_gate_modes.py                   # chart: ConfigMap mode vs gate image mode
docker build -f gate/Dockerfile -t artifacts-gate:dev . && tests/gate_image_smoke.sh artifacts-gate:dev
cd deploy/compose && docker compose up -d && docker compose up bootstrap && ./e2e.sh  # full stack (Docker required)
```

## Layout

```
gate/gate.py          the gate (single stdlib-only file, two listeners)
gate/Dockerfile       the gate image (digest-pinned base, non-root, read-only root filesystem)
helm/artifacts/       chart: gate + oauth2-proxy + routes + plugin routes + bootstrap Job
cli/                  publisher (publish.sh + render.py)
mcp/                  MCP server (server.py + artifacts_lib.py)
deploy/compose/       local dev stack (MinIO + Dex + oauth2-proxy + gate + Caddy) + e2e.sh
tests/                unit + e2e suites
docs/plugins.md       the plugin contract
.github/workflows/    ci.yml (tests, chart checks, image smoke test), publish.yml (gate image, main only)
```

## License

Apache-2.0 — see [LICENSE](LICENSE). Copyright 2026 Daniel Ibáñez (see NOTICE).
