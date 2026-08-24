#!/usr/bin/env python3
"""Shared helpers for the multi-engine spike proofs (run from an in-cluster
pod that can reach both the ts.net Keycloak issuer and mobula-pack.svc).

Env:
  MOBULA_ISS    OIDC issuer (default: the grace nebari realm)
  MOBULA_API    mobula control-plane base URL (default: in-cluster svc)
  SPIKE_PW      password for the alice/bob/admin test users
"""
from __future__ import annotations
import json, os, ssl, time, urllib.request, urllib.parse, urllib.error

ISS = os.environ.get("MOBULA_ISS", "https://grace.possum-fujita.ts.net:8443/auth/realms/nebari")
API = os.environ.get("MOBULA_API", "http://mobula-pack.mobula.svc:8484")
PW = os.environ.get("SPIKE_PW", "Spike#123")
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def token(user: str, password: str | None = None) -> str:
    d = urllib.parse.urlencode({
        "grant_type": "password", "client_id": "mobula",
        "scope": "openid profile groups",
        "username": user, "password": password or PW,
    }).encode()
    r = urllib.request.urlopen(ISS + "/protocol/openid-connect/token", data=d, context=_CTX)
    return json.load(r)["access_token"]


def api(method: str, path: str, tok: str | None = None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method)
    if tok is not None:
        req.add_header("Authorization", "Bearer " + tok)
    req.add_header("Content-Type", "application/json")
    try:
        r = urllib.request.urlopen(req, context=_CTX)
        raw = r.read().decode()
        return r.status, (json.loads(raw) if raw.strip() else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, raw


def grant(admin_tok: str, principal: str, role: str, scope: str):
    return api("PUT", f"/api/v1/access/assignments/{principal}", admin_tok,
               {"role": role, "scope": scope})


def revoke(admin_tok: str, principal: str, role: str, scope: str):
    return api("DELETE",
               f"/api/v1/access/assignments/{principal}?role={role}&scope={urllib.parse.quote(scope)}",
               admin_tok)


def set_quota(admin_tok: str, project: str, cpu: float, mem_gib: float):
    return api("PUT", "/api/v1/settings/policy", admin_tok,
               {"quotas": {project: {"cpu": cpu, "memory": mem_gib}}})


def clear_quota(admin_tok: str):
    return api("PUT", "/api/v1/settings/policy", admin_tok, {"quotas": {}})


def cluster_spec(cid, project, engine, workers=1, cpu="1", memory="2Gi",
                 image=None, ttl=3600):
    if image is None:
        image = ("ghcr.io/dask/dask:2024.5.0-py3.12" if engine == "dask"
                 else "rayproject/ray:2.9.3")
    return {
        "id": cid,
        "spec": {
            "name": cid, "project": project, "engine": engine,
            "ray_version": "" if engine == "dask" else "2.9.3",
            "image": image, "head_cpu": cpu, "head_memory": memory,
            "worker_groups": [{
                "name": "default", "cpu": cpu, "memory": memory, "gpu": None,
                "min_replicas": workers, "max_replicas": workers, "replicas": workers,
            }],
            "ttl_seconds": ttl,
        },
    }


def create(tok, cid, project, engine, **kw):
    return api("POST", "/api/v1/clusters", tok, cluster_spec(cid, project, engine, **kw))


def terminate(tok, cid):
    return api("DELETE", f"/api/v1/clusters/{cid}", tok)


def wait_running(tok, cid, timeout=300):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        code, v = api("GET", f"/api/v1/clusters/{cid}", tok)
        last = v.get("observed_state") if isinstance(v, dict) else v
        if last == "running":
            return True, last
        time.sleep(5)
    return False, last
