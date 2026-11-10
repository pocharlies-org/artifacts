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
                     │        │ allowed ──> MinIO (path-style)   denied ──> 302 /oauth2/sign_in
                     │        └ every response: CSP `sandbox allow-scripts` (opaque origin)
                     ├── POST /artifacts/** ──> gate :8080  (request-access, approve, deny)
                     ├── /_gate/** (except auth/healthz) ──> gate :8080
                     ├── /oauth2/** ──> oauth2-proxy
                     └── /_<plugin>/** ──> plugin service        (plugin → gate :8081 /_gate/plugin/authz)
```

- **Identity**: oauth2-proxy in front of your OIDC provider. The gate authenticates by
  calling the proxy's `/auth` with the visitor's cookie (or a `Bearer` id_token) and
  never trusts client-supplied `X-Auth-Request-*` headers.
- **Authorization**: one `decide()` in `gate/gate.py` — ACL file `<dir>/.acl.json`
  (`owner`, `users`, `groups`, `expires`); no ACL → any signed-in user for `pub/`,
  deny elsewhere. The same function answers forwardAuth and the plugin authz API.
- **Two listeners, one process**: `:8080` public (request-access pages, approve/deny
  links, health) and `:8081` internal (decision endpoints only: `/_gate/auth`,
  `/_gate/plugin/authz`). The public routes never reach the decision listener.
- **Expiry**: objects carry a `ttl` tag (`1|7|14|30` days), ILM expires by tag, and a
  catch-all (90 days) takes everything untagged — including `_plugins/`.
- **Never served**: directory listings, `.acl.json`, `_gate/` (gate state), `_plugins/`
  (plugin storage), and any path with a `.`/`..` segment.

## Quick start (laptop, Docker Compose)

```bash
cd deploy/compose
python3 -m pip install markdown   # publisher renders .md inputs (not needed for .html)
docker compose up -d          # MinIO + Dex (test user) + oauth2-proxy + gate + Caddy
docker compose up bootstrap   # bucket, ILM rules, anonymous pub/ policy
./e2e.sh                      # publishes with the real CLI, checks reads and negatives
```

Then open <http://127.0.0.1:8080/artifacts/pub/<run>/index.html> — anonymous `pub/`
reads work; gated reads (`/artifacts/u/...`) redirect to Dex login
(`test@example.com` / `test-password`). Publish your own:

```bash
ARTIFACTS_ACCESS_KEY=minioadmin ARTIFACTS_SECRET_KEY=minioadmin \
ARTIFACTS_WRITE_BASE=http://127.0.0.1:9000 ARTIFACTS_READ_BASE=http://127.0.0.1:8080 \
../../cli/publish.sh -g pub -t 7 -a me -s demo report.html
```

> The compose stack is a **dev/demo** stack with fixed low-entropy dev secrets — never
> expose it beyond localhost (all ports bind `127.0.0.1`). MinIO runs from
> `bitnamilegacy/minio` (digest-pinned): a **frozen legacy mirror**, because the
> original `minio/minio`/`minio/mc` RELEASE tags were removed from Docker Hub; it
> bundles the `mc` client at `/opt/bitnami/minio-client/bin/mc`.

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
- The gate code ships as a ConfigMap: create it from this repo
  (`kubectl -n sso create configmap artifact-gate-code --from-file=gate/gate.py
  --dry-run=client -o yaml | kubectl apply -f -`), same cadence as the chart.
- The bootstrap Job (helm hook) creates the bucket, the ILM rules, the anonymous `pub/`
  policy, and the least-privilege S3 users: `artifact-gate` (GetObject + GetObjectTagging
  on `artifacts/*`, PutObject only on `*/.acl.json` and `_gate/*`), `artifact-publisher`
  (optional), and one `plugin-<name>` per declared plugin.
- Gate secrets (`artifact-gate-s3`, optional `artifact-gate-slack`) are created out of
  band — nothing secret goes through git.

## Publishing

**CLI** — `cli/publish.sh` (bash + curl, SigV4): renders an `index.html` around your
files (audience banner, provenance), writes the ACL **before** the objects for gated
runs, verifies the link anonymously, and prints the artifact link plus one link per
enabled plugin.

```bash
publish.sh -u alice@example.com -t 14 -a build -s 42 report.html   # gated (u/<run>/)
publish.sh -g pub -t 7 report.html                                 # anonymous pub/
publish.sh -g <group-slug> -t 7 report.html                        # group-gated
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
| `MINIO_ACCESS_KEY` / `MINIO_SECRET_KEY` | required | least-privilege gate user |
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
`bootstrap.*`, and `plugins: []` — see `docs/plugins.md`.

## Plugins

The plugin contract (authz API, routes, storage prefixes, expiry, discovery) is the
public API other plugins build against: **[docs/plugins.md](docs/plugins.md)**.

## Tests

```bash
python3 -I -m unittest discover -s tests              # unit (gate + mcp lib)
python3 -I -m unittest discover -s tests -p 'e2e_*.py' # e2e vs fake MinIO + fake proxy
helm lint helm/artifacts && helm template t helm/artifacts -f helm/artifacts/values.yaml
cd deploy/compose && docker compose up -d && ./e2e.sh  # full stack (Docker required)
```

## Layout

```
gate/gate.py          the gate (single stdlib-only file, two listeners)
helm/artifacts/       chart: gate + oauth2-proxy + routes + plugin routes + bootstrap Job
cli/                  publisher (publish.sh + render.py)
mcp/                  MCP server (server.py + artifacts_lib.py)
deploy/compose/       local dev stack (MinIO + Dex + oauth2-proxy + gate + Caddy) + e2e.sh
tests/                unit + e2e suites
docs/plugins.md       the plugin contract
```

## License

Apache-2.0 — see [LICENSE](LICENSE). Copyright 2026 Daniel Ibáñez (see NOTICE).
