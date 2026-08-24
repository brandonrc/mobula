# Multi-engine spike (Ray OR Dask) — grace deploy + proof

Branch `spike/engine-dask` makes Mobula multi-engine: the same control plane
provisions **either** a KubeRay `RayCluster` **or** a dask-kubernetes-operator
`DaskCluster`, dispatched per-cluster by `spec.engine`. Dask gets the control
path (provision / quota / RBAC / pod-shaping caps / idle-TTL / audit — all
engine-agnostic) and the interactive path (a notebook connects a
`distributed.Client` to the scheduler). Batch (job gateway) and serving (Ray
Serve) stay Ray-only and return a clean `400` for `engine=dask`.

**SPIKE — do not merge.** The image temporarily replaces the running mobula
server on grace; it is a strict superset of `origin/main` (obs/metrics/events +
nodes/jobs + tier-2 + Dask), so it does not regress other work.

## Files
- `mobula-values-spike-dask.yaml` — helm overlay pinning the spike image.
- `mobula-dask-role.yaml` — standalone Role/binding: the `mobula-pack` SA gets
  `daskclusters`/`daskworkergroups` on `kubernetes.dask.org` (pods/netpols are
  already covered by `mobula-pack-kuberay`). Applied out-of-band because Helm's
  3-way merge no-ops additive rule changes on a chart-owned Role.
- `dask-dashboard-nebariapp.yaml` — gated Dask scheduler-dashboard (:8787),
  Keycloak group filter `auth.groups=[team-b]`, same mechanism as the Ray one.
- `notebook-pods.yaml` — bob/alice notebook pods (jupyter ns, `mobula.dev/owner`
  labels) for the live-compute + per-owner isolation proof.
- `scripts/mobula_spike.py` — token/api/grant/quota/create helpers.
- `scripts/engine-auth-matrix.py` — Ray|Dask auth + resource-control matrix.
- `scripts/session_cluster_dask.py` — notebook helper (`mobula token` → POST
  `engine=dask` → poll running → `distributed.Client`).

## Deploy
```sh
# 1. dask-kubernetes operator (its own namespace)
microk8s helm3 repo add dask https://helm.dask.org
microk8s helm3 upgrade --install dask-kubernetes-operator dask/dask-kubernetes-operator -n dask-operator --create-namespace --wait

# 2. RBAC (standalone Role — chart Role won't pick up additive rules)
microk8s kubectl apply -f manifests/mobula-dask-role.yaml

# 3. build the spike image from the branch and push to the local registry
cd ~/build/mobula-dask && sudo docker build -t localhost:32000/mobula:spike-dask . && sudo docker push localhost:32000/mobula:spike-dask

# 4. deploy (base values + spike overlay)
cd ~/deploy && sudo microk8s helm3 upgrade mobula ./mobula-pack/chart -n mobula \
  -f ./mobula-values.yaml -f ~/grace-deploy/mobula-values-spike-dask.yaml --wait
```

## Teardown / revert
```sh
# delete probe clusters + notebooks + dashboard, clear quota, drop the Role
microk8s kubectl -n mobula delete daskcluster,raycluster -l app.kubernetes.io/managed-by=mobula --field-selector # (or by id)
microk8s kubectl -n jupyter delete pod bob-nb alice-nb
microk8s kubectl -n mobula delete nebariapp bobdask1-dashboard
microk8s kubectl -n mobula delete -f manifests/mobula-dask-role.yaml
# roll the server back to origin/main by dropping the overlay:
cd ~/deploy && sudo microk8s helm3 upgrade mobula ./mobula-pack/chart -n mobula -f ./mobula-values.yaml --wait
# (dask operator can stay; it is inert without DaskClusters)
```

## Re-running the API proofs
The proof scripts mint `aud=mobula` tokens via the Keycloak password grant on
the (public) `mobula` client. That requires `directAccessGrantsEnabled=true` on
the client — enable it via kcadm, run the scripts, then revert it. Users
alice/bob are developers (team-a/team-b); grant a scoped operator assignment to
create clusters (the scripts do this via the admin access API).
