#!/usr/bin/env python3
"""Backfill the demo DB with history the UI screenshots need: job history
(no public API writes job rows — the gateway records them in real
deployments) and a 48h usage_samples timeseries (the metering loop only
starts sampling at boot). Run against the stack's SQLite file:

    docker run --rm -v mobula-demo_mobula-local-data:/data \\
        -v "$PWD/deploy:/seed:ro" python:3.12-alpine \\
        python3 /seed/seed-backfill.py /data/mobula.db

Idempotent: wipes previously-backfilled rows (submitter/tag marker) first.
"""
import sqlite3
import sys
import time

DB = sys.argv[1] if len(sys.argv) > 1 else "/data/mobula.db"
now = int(time.time())
HOUR = 3600

db = sqlite3.connect(DB)
cur = db.cursor()

# --- jobs ---------------------------------------------------------------
# (id suffix, cluster, submitter, status, duration_secs, age_hours)
JOBS = [
    ("a91f", "vision-train", "admin", "SUCCEEDED", 2 * HOUR + 1473, 4),
    ("b20c", "vision-train", "svc-ci", "SUCCEEDED", 2 * HOUR + 901, 12),
    ("c77e", "llm-finetune", "admin", "FAILED", 41 * 60, 13),
    ("d4aa", "data-pipeline", "svc-ci", "SUCCEEDED", 5 * HOUR + 220, 20),
    ("e5b1", "llm-finetune", "admin", "SUCCEEDED", 3 * HOUR + 88, 26),
    ("f61c", "batch-inference", "svc-ci", "STOPPED", 18 * 60, 30),
    ("07d2", "data-pipeline", "admin", "FAILED", 9 * 60 + 40, 33),
    ("18e3", "vision-train", "admin", "SUCCEEDED", 2 * HOUR + 61, 44),
    ("29f4", "old-experiment", "admin", "FAILED", 3 * 60 + 12, 50),
    ("3a05", "data-pipeline", "svc-ci", "SUCCEEDED", 4 * HOUR + 4000, 62),
    ("4b16", "vision-train", "admin", "SUCCEEDED", 2 * HOUR + 700, 70),
    ("5c27", "llm-finetune", "admin", "SUCCEEDED", 3 * HOUR + 15, 80),
    ("6d38", "batch-inference", "svc-ci", "RUNNING", None, 1),
    ("7e49", "vision-train", "admin", "RUNNING", None, 0),
]
cur.execute("DELETE FROM jobs WHERE id LIKE 'raysubmit_demo_%'")
for suffix, cluster, submitter, status, dur, age_h in JOBS:
    cur.execute(
        "INSERT INTO jobs (id, cluster, submitter, status, duration_secs, submitted_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (f"raysubmit_demo_{suffix}", cluster, submitter, status, dur, now - age_h * HOUR),
    )

# --- usage_samples -------------------------------------------------------
# 48h of 15-min samples per (project, pool, resource). A slow sine plus a
# deterministic wobble gives realistic ramp-up/down; the live metering loop
# appends current values from here on, so the series stays continuous.
SERIES = [
    # project, pool, resource, base, amplitude, phase
    ("ml-team", "gpu-pool", "nvidia.com/gpu", 4.0, 3.0, 0.0),
    ("ml-team", "gpu-pool", "cpu", 36.0, 20.0, 0.6),
    ("ml-team", "gpu-pool", "memory", 150.0, 80.0, 0.6),
    ("genai", "gpu-pool", "nvidia.com/gpu", 2.0, 1.5, 1.9),
    ("genai", "gpu-pool", "cpu", 18.0, 10.0, 2.2),
    ("genai", "gpu-pool", "memory", 70.0, 36.0, 2.2),
    ("research", "cpu-pool", "cpu", 40.0, 26.0, 4.0),
    ("research", "cpu-pool", "memory", 90.0, 50.0, 4.0),
    ("dev", "cpu-pool", "cpu", 5.0, 3.0, 2.8),
    ("dev", "cpu-pool", "memory", 10.0, 6.0, 2.8),
]
import math

cur.execute("DELETE FROM usage_samples WHERE source = 'observed_spec' AND ts < ?", (now - 60,))
step = 900  # 15 min
for project, pool, resource, base, amp, phase in SERIES:
    for i in range(48 * HOUR // step, 0, -1):
        ts = now - i * step
        wobble = math.sin(i / 7.3 + phase) * 0.25
        qty = max(0.0, base + amp * math.sin(i / 11.0 + phase) + base * wobble)
        cur.execute(
            "INSERT INTO usage_samples (ts, project, pool, resource, quantity, source)"
            " VALUES (?, ?, ?, ?, ?, 'observed_spec')",
            (ts, project, pool, resource, round(qty, 3)),
        )

db.commit()
print(f"jobs: {cur.rowcount and len(JOBS)} seeded; usage_samples: {db.execute('SELECT COUNT(*) FROM usage_samples').fetchone()[0]} total")

# --- pool observations ----------------------------------------------------
# The pool detail usage panel reads pools.observed_json (a PoolObservation),
# which only the Kueue-backed pool reconciler writes. Fabricate plausible
# observations so the panel renders in the K8s-less demo.
import json

OBSERVATIONS = {
    "gpu-pool": {
        "admitted_workloads": 3,
        "reserving_workloads": 0,
        "pending_workloads": 1,
        "flavors_usage": {
            "a100": {"cpu": "48", "memory": "192Gi", "nvidia.com/gpu": "6"},
            "mig-slice": {"cpu": "4", "memory": "16Gi", "nvidia.com/mig-1g.10gb": "3"},
        },
        "queues_usage": {
            "ml-team": {"nvidia.com/gpu": "5", "cpu": "40", "memory": "160Gi"},
            "genai": {"nvidia.com/gpu": "1", "cpu": "8", "memory": "32Gi"},
        },
    },
    "cpu-pool": {
        "admitted_workloads": 2,
        "reserving_workloads": 0,
        "pending_workloads": 0,
        "flavors_usage": {"standard": {"cpu": "72", "memory": "160Gi"}},
        "queues_usage": {
            "research": {"cpu": "60", "memory": "140Gi"},
            "dev": {"cpu": "12", "memory": "20Gi"},
        },
    },
}
for pool, obs in OBSERVATIONS.items():
    cur.execute(
        "UPDATE pools SET observed_json = ?, observed_at = ? WHERE name = ?",
        (json.dumps(obs), now, pool),
    )
db.commit()
print(f"pool observations backfilled: {cur.rowcount}")
db.close()
