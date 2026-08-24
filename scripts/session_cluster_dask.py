#!/usr/bin/env python3
"""Provision a governed Dask session cluster through Mobula and connect to it.

The Dask analog of the Ray interactive session helper: it asks the Mobula
control plane (same auth, same RBAC, same quota, same per-owner isolation) to
provision a `DaskCluster`, waits for it to run, and hands back a live
`distributed.Client` connected to the scheduler.

Flow:
  1. `mobula token`                      -> bearer for the control plane
  2. POST /api/v1/clusters {engine:dask} -> owner is set SERVER-SIDE from the
                                            token identity (never trusted from
                                            the body); ttl bounds its lifetime
  3. poll GET /api/v1/clusters/{id}      -> wait for observed_state == running
  4. Client("tcp://<id>-scheduler.<ns>.svc:8786")

Usage (inside a notebook / singleuser pod):
    from session_cluster_dask import session_cluster
    client = session_cluster(workers=2)
    import dask.array as da
    print(da.ones((10_000, 10_000), chunks=(1000, 1000)).sum().compute())
"""
from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.request
import uuid

MOBULA_SERVER = os.environ.get("MOBULA_SERVER", "http://mobula.mobula.svc:8484")
# The namespace Mobula provisions clusters into (its scheduler Service lives
# here). Matches --kuberay-namespace on the server.
MOBULA_NAMESPACE = os.environ.get("MOBULA_NAMESPACE", "mobula")
# A py3.12 Dask image whose `distributed` matches the notebook's. Pulled via
# the AK pypi proxy / mirror on grace.
DASK_IMAGE = os.environ.get("MOBULA_DASK_IMAGE", "ghcr.io/dask/dask:2024.5.0-py3.12")


def _token() -> str:
    """Bearer token: prefer `mobula token`, fall back to $MOBULA_TOKEN."""
    try:
        out = subprocess.run(
            ["mobula", "token"], capture_output=True, text=True, check=True
        )
        tok = out.stdout.strip()
        if tok:
            return tok
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass
    tok = os.environ.get("MOBULA_TOKEN", "")
    if not tok:
        raise SystemExit("no token: run `mobula login` or set MOBULA_TOKEN")
    return tok


def _api(method: str, path: str, token: str, body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"{MOBULA_SERVER}{path}", data=data, method=method
    )
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, {"error": raw}


def session_cluster(
    project: str = "team-b",
    workers: int = 2,
    cpu: str = "1",
    memory: str = "2Gi",
    ttl_seconds: int = 3600,
    cluster_id: str | None = None,
):
    """Provision (or reuse) a Dask cluster and return a connected Client."""
    from dask.distributed import Client  # deferred: only needed on connect

    token = _token()
    cid = cluster_id or f"sess-dask-{uuid.uuid4().hex[:8]}"
    spec = {
        "id": cid,
        "spec": {
            "name": cid,
            "project": project,
            "engine": "dask",
            # ray_version is unused for engine=dask (image carries the version).
            "ray_version": "",
            "image": DASK_IMAGE,
            "head_cpu": cpu,
            "head_memory": memory,
            "worker_groups": [
                {
                    "name": "default",
                    "cpu": cpu,
                    "memory": memory,
                    "gpu": None,
                    "min_replicas": workers,
                    "max_replicas": workers,
                    "replicas": workers,
                }
            ],
            "ttl_seconds": ttl_seconds,
        },
    }
    code, resp = _api("POST", "/api/v1/clusters", token, spec)
    if code not in (200, 201):
        raise SystemExit(f"create failed ({code}): {resp}")
    print(f"[mobula] requested dask cluster {cid} (project={project}, workers={workers})")

    deadline = time.time() + 300
    while time.time() < deadline:
        code, view = _api("GET", f"/api/v1/clusters/{cid}", token)
        state = view.get("observed_state")
        print(f"[mobula] {cid}: {state}")
        if state == "running":
            break
        time.sleep(5)
    else:
        raise SystemExit(f"cluster {cid} did not reach running in time")

    scheduler = f"tcp://{cid}-scheduler.{MOBULA_NAMESPACE}.svc:8786"
    print(f"[mobula] connecting distributed.Client -> {scheduler}")
    client = Client(scheduler)
    print(client)
    return client


if __name__ == "__main__":
    c = session_cluster()
    import dask.array as da

    total = da.ones((10_000, 10_000), chunks=(1000, 1000)).sum().compute()
    print("dask.array sum:", total)
