# Local demo stack (Docker Compose)

Runs the **control plane + dashboard** with nothing but Docker, so you can
click through the UI and exercise the API end-to-end. No Kubernetes.

```bash
./deploy/up.sh          # build + start (streams logs; Ctrl-C to stop)
./deploy/up.sh -d       # detached
./deploy/up.sh down     # tear down
```

- **Dashboard:** http://localhost:8088
- **API:** http://localhost:8484 (`/healthz`, `/api/v1/version`, `/api/v1/clusters`, `/docs`)

## What it is

- `mobula` runs `serve --demo` — a k8s-less **mock provisioner**: creating a
  cluster/service records desired state and the reconcile loop drives it to
  `running` in ~2s. **Nothing is actually provisioned**, and it serves
  **unauthenticated** — demo/testing only.
- `ui` is the dashboard built to static assets and served by nginx, which
  reverse-proxies `/api`, `/healthz`, `/docs` to the `mobula` container.

`up.sh` regenerates `openapi.json` from the Rust source and the typed TS
client (vendored into `mobula-ui/vendor/`) before building, so the UI image
needs no GitHub Packages token. Re-run it after changing the API surface.

**Store backend:** `mobula serve --db` also accepts a `postgres://…` /
`postgresql://…` URL — the store then runs on Postgres 16 (schema is
auto-created on connect) instead of a SQLite file. The store conformance
suite covers it when `MOBULA_TEST_POSTGRES_URL` is set (mobula-controller
tests; skipped otherwise).

## Try it

```bash
curl -s localhost:8484/api/v1/version
curl -s -X POST localhost:8484/api/v1/clusters -H 'content-type: application/json' -d '{
  "id":"demo1","spec":{"name":"demo1","project":"dev","ray_version":"2.57.0",
    "image":"rayproject/ray:2.57.0","head_cpu":"1","head_memory":"2Gi",
    "worker_groups":[],"ttl_seconds":null}}'
curl -s localhost:8484/api/v1/clusters/demo1   # observed_state → "running"
```

Then open the dashboard and you'll see it in the cluster list.

## Authenticated variant (local Keycloak)

To exercise the **auth** path — real OIDC login, per-role RBAC (401/403),
audit events with real subjects — bring up the auth overlay instead:

```bash
./deploy/up.sh auth          # stops the plain demo, starts Keycloak + authed API
./deploy/up.sh auth down     # tear down (add -v to re-import the realm)
```

- **Keycloak:** http://localhost:8090 (admin console `admin`/`admin`), realm
  `mobula`, imported from `deploy/keycloak/mobula-realm.json`
- **Test users** (password = username): `admin` (/platform-admins),
  `operator` (/sre), `developer` (/ml-eng), `viewer` (/observers)
- **Sign in to the dashboard:** http://localhost:8088/login — paste a token:

```bash
curl -s localhost:8090/realms/mobula/protocol/openid-connect/token \
  -d grant_type=password -d client_id=mobula \
  -d username=viewer -d password=viewer | jq -r .access_token
```

- **CLI device flow:** `mobula login --issuer http://localhost:8090/realms/mobula --client-id mobula`
- **Service account:** `mobula token --issuer http://localhost:8090/realms/mobula --client-id mobula-service --client-secret mobula-service-secret`

Expected matrix: no token → 401 everywhere; viewer → reads 200, mutations
403; developer → services/jobs write, cluster lifecycle 403; operator →
cluster lifecycle; admin → pools/registry/audit. Every decision lands in
`GET /api/v1/audit` (Admin) with the caller's Keycloak subject.

How it works: Keycloak's hostname is pinned to `http://localhost:8090` and
the `mobula` container shares Keycloak's network namespace, so the OIDC
issuer string is identical from your shell, the container, and the token's
`iss` claim (see the comment in `docker-compose.auth.yml`). The auth config
is `deploy/keycloak/auth.toml`; cleartext HTTP is accepted because this is a
local demo only (`--allow-insecure-transport`).

## IdP-free variant (local auth, no Keycloak)

To try login with **no IdP container at all** — Mobula's own local auth
(ADR-0011: username/password → opaque token, bcrypt-hashed in the store):

```bash
./deploy/up.sh local         # stops the other variants; admin/admin
./deploy/up.sh local down    # add -v to wipe the data volume (users, tokens, audit)
```

Sign in at http://localhost:8088/login with `admin`/`admin`. CLI:
`mobula login --local --username admin --password-stdin`. The login page
discovers available methods from `GET /api/v1/auth/providers`, so it shows
the local form here, the SSO button under `up.sh auth`, and both when a
deployment runs both. The bootstrap password comes from
`MOBULA_LOCAL_ADMIN_PASSWORD` in `docker-compose.local.yml` — delete that
env var and a random one is generated into `/data/local-admin-password`
instead.

## Real clusters

For **real** KubeRay provisioning (create a cluster → real Ray pods), use the
kind-based dev-stack instead: `./scripts/dev-stack.sh up` then `serve` + `ui`
(see `docs/dev-stack.md`). This compose stack is purely for fast local UI/API
iteration.

**Pools:** pools/Kueue are optional here. Kueue is a Kubernetes component and
this stack has no Kubernetes, so pools run in **in-process quota-only** mode
(ADR-0010's fallback): the pools API, allocations, and usage screens all work,
but nothing is enforced by Kueue ClusterQueues. For the full pool engine
(cohort borrowing, gang admission, queue labels), use the dev-stack — it
installs Kueue by default (`MOBULA_WITH_KUEUE=0` to skip).

> Note: the dashboard's identity, registry, and audit screens are all live
> (registry + audit endpoints landed 2026-08-16; sign in via `/login` when
> using the auth variant). Clusters, services, pools, and usage are fully
> live in demo mode.
