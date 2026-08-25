#!/usr/bin/env python3
"""Ray|Dask auth + resource-control proof matrix (multi-engine spike).

Proves the SAME control-plane governance surface applies identically whether
`engine=ray` or `engine=dask`, by running the same checks against both and
printing a side-by-side table. Run from the in-cluster driver pod.

Checks:
  1. UNAUTH BASELINE      no/garbage bearer -> 401 (engine-independent)
  2. ALLOCATION RBAC      developer w/o scoped role -> 403; w/ scoped operator -> 201  (ray & dask)
  3. QUOTA ADMISSION      fit -> 201 ; over -> 409 with accounting  (ray & dask)
  4. POD CAPS HONORED     head/scheduler + worker pod requests/limits == spec  (checked out-of-band via kubectl)

Tokens are minted ONCE per identity and reused (Keycloak login throttle).
"""
import sys, json
sys.path.insert(0, "/tmp")
from mobula_spike import token, api, grant, revoke, set_quota, clear_quota, create, terminate

ALICE = "3c4217b6-8dac-4d7a-adae-05e761ccd6b9"
RAY_IMG = "rayproject/ray:2.56.0-py312"
results = {}  # (check, engine) -> cell

def rec(check, engine, cell):
    results[(check, engine)] = cell
    print(f"  [{check} | {engine}] {cell}")

# mint tokens once
adm = token("admin"); alice = token("alice")
print("tokens minted (admin, alice)")

# ---- 1. UNAUTH BASELINE (engine-independent) ----
print("\n== 1. UNAUTH BASELINE ==")
spec = {"id":"unauth-x","spec":{"name":"x","project":"spikerbac","engine":"ray","ray_version":"2.56.0","image":RAY_IMG,"head_cpu":"1","head_memory":"2Gi","worker_groups":[],"ttl_seconds":600}}
code_none,_ = api("POST","/api/v1/clusters",None,spec)         # no bearer
import urllib.request, urllib.parse, json as J
def raw_post(bearer):
    import urllib.error
    req=urllib.request.Request(api.__globals__["API"]+"/api/v1/clusters",data=J.dumps(spec).encode(),method="POST")
    req.add_header("Authorization","Bearer "+bearer); req.add_header("Content-Type","application/json")
    try:
        import ssl; ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        r=urllib.request.urlopen(req,context=ctx); return r.status
    except urllib.error.HTTPError as e: return e.code
code_garbage = raw_post("garbage.token.value")
rec("unauth","-", f"no-bearer={code_none}, garbage-bearer={code_garbage} (expect 401/401)")

# ---- 2. ALLOCATION RBAC (per engine) ----
print("\n== 2. ALLOCATION RBAC (alice=developer, project=spikerbac) ==")
for eng in ("ray","dask"):
    img = RAY_IMG if eng=="ray" else "ghcr.io/dask/dask:2024.5.0-py3.12"
    cid = f"rbac-{eng}"
    # no scoped role -> 403
    revoke(adm, ALICE, "operator", "project:spikerbac")  # ensure clean
    c1,_ = create(alice, cid, "spikerbac", eng, workers=0, image=img)
    # grant scoped operator -> 201
    grant(adm, ALICE, "operator", "project:spikerbac")
    c2,r2 = create(alice, cid, "spikerbac", eng, workers=0, image=img)
    rec("rbac", eng, f"no-role={c1} (expect 403); scoped-operator={c2} (expect 201/200)")
    # cleanup
    terminate(alice, cid); revoke(adm, ALICE, "operator", "project:spikerbac")

# ---- 3. QUOTA ADMISSION (per engine) ----
print("\n== 3. QUOTA ADMISSION (project=spikeq, quota cpu=5 memory=10GiB) ==")
set_quota(adm, "spikeq", 5, 10)
fit_ids = {}
for eng in ("ray","dask"):
    img = RAY_IMG if eng=="ray" else "ghcr.io/dask/dask:2024.5.0-py3.12"
    cid = f"fit-{eng}"; fit_ids[eng]=cid
    # fit: head 1cpu/2Gi + 1 worker 1cpu/2Gi = 2cpu/4GiB
    c,_ = create(adm, cid, "spikeq", eng, workers=1, cpu="1", memory="2Gi", image=img)
    rec("quota-fit", eng, f"create(2cpu/4GiB) -> {c} (expect 201/200)")
# now spikeq holds 4cpu/8GiB; an over create must 409
for eng in ("ray","dask"):
    img = RAY_IMG if eng=="ray" else "ghcr.io/dask/dask:2024.5.0-py3.12"
    c,body = create(adm, f"over-{eng}", "spikeq", eng, workers=1, cpu="1", memory="2Gi", image=img)
    acct = body if isinstance(body,str) else json.dumps(body)
    rec("quota-over", eng, f"create -> {c} (expect 409); body={acct[:160]}")

print("\n== DONE (fit clusters left running for pod-cap inspection: %s) ==" % fit_ids)
print("MATRIX_JSON=" + json.dumps({f"{k[0]}|{k[1]}":v for k,v in results.items()}))
