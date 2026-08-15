"""Contract test: the real Ray JobSubmissionClient against the Mobula gateway.

This is the drift alarm demanded by PLAN.md gate S4: KubeRay's Go client
history shows the Jobs API surface moves, so we replay the genuine Python
client — version negotiation, package upload (GET-then-PUT), submit, status
poll, full logs, and the websocket log tail — through the gateway fronting a
real `ray start --head`.

Environment:
  MOBULA_ADDRESS  gateway base URL as the stock client sees it
                  (default http://demo.ray.test:8484)
"""

import asyncio
import os
import sys
import tempfile
import time
from pathlib import Path

from ray.job_submission import JobStatus, JobSubmissionClient

MARKER = "mobula-contract-ok"
ADDRESS = os.environ.get("MOBULA_ADDRESS", "http://demo.ray.test:8484")
TERMINAL = {JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.STOPPED}


def main() -> int:
    client = JobSubmissionClient(ADDRESS)  # negotiates via GET /api/version
    print(f"connected through gateway: {ADDRESS}")

    # working_dir forces the runtime-env package path through the gateway:
    # GET /api/packages (existence probe) then PUT /api/packages (upload).
    workdir = Path(tempfile.mkdtemp(prefix="mobula-contract-"))
    (workdir / "entry.py").write_text(f'print("{MARKER}")\n')

    submission_id = client.submit_job(
        entrypoint="python entry.py",
        runtime_env={"working_dir": str(workdir)},
    )
    print(f"submitted: {submission_id}")

    deadline = time.time() + 300
    status = None
    while time.time() < deadline:
        status = client.get_job_status(submission_id)
        if status in TERMINAL:
            break
        time.sleep(2)
    assert status == JobStatus.SUCCEEDED, f"job ended {status}"
    print("status: SUCCEEDED")

    logs = client.get_job_logs(submission_id)
    assert MARKER in logs, f"marker missing from logs: {logs!r}"
    print("full logs: marker found")

    jobs = client.list_jobs()
    assert any(j.submission_id == submission_id for j in jobs), "job absent from list"
    print(f"list_jobs: {len(jobs)} job(s), submission present")

    async def tail() -> str:
        chunks = []
        async for lines in client.tail_job_logs(submission_id):
            chunks.append(lines)
        return "".join(chunks)

    tailed = asyncio.run(tail())
    assert MARKER in tailed, f"marker missing from websocket tail: {tailed!r}"
    print("websocket tail: marker found")

    client.stop_job(submission_id)  # no-op on a finished job; exercises POST stop
    client.delete_job(submission_id)
    assert all(
        j.submission_id != submission_id for j in client.list_jobs()
    ), "job still listed after delete"
    print("stop/delete: ok")

    print("CONTRACT OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
