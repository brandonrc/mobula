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

## Real clusters

For **real** KubeRay provisioning (create a cluster → real Ray pods), use the
kind-based dev-stack instead: `./scripts/dev-stack.sh up` then `serve` + `ui`
(see `docs/dev-stack.md`). This compose stack is purely for fast local UI/API
iteration.

> Note: the dashboard's identity and registry screens are "UI-ahead" — their
> endpoints aren't in the API yet, so they render a "not implemented" empty
> state. Clusters, services, version, and health are fully live in demo mode.
