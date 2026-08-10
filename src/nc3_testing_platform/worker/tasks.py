"""Mock scan pipeline: dispatch fans out, modules run, one row persists.

This is the round-trip proof for the compose stack (issue #3), not scan logic:
`scan.dispatch` fans a domain out to mock modules as a chord, each
`scan.run_module` sleeps through its steps and reports progress to the Redis
result backend, and `scan.persist` writes the collected findings to Postgres.

Persistence here is one deliberately disposable table written with bare
psycopg. The ORM models (issue #2) and Alembic (issue #6) replace it; nothing
imports this table's shape.
"""

import json
import os
import time
import uuid

import psycopg
from celery import chord

from nc3_testing_platform.worker.app import app

# Stand-ins for the real engines; each "runs" as its own task on the
# non-intrusive queue, which is the fan-out shape real scans will use.
MOCK_MODULES = ("mock-dns", "mock-mail", "mock-headers")

_STEPS = ("resolve", "probe", "evaluate")


def _database_url() -> str:
    """The task-side DSN, without the SQLAlchemy driver suffix psycopg rejects."""
    url = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg://postgres:postgres@localhost:5432/nc3_testing_platform",
    )
    return url.replace("postgresql+psycopg://", "postgresql://", 1)


@app.task(name="scan.dispatch")
def dispatch(domain: str) -> str:
    """Fan a domain out to every mock module; persist the collected findings.

    Returns the chord callback's task id, so a caller can watch the persist
    step complete in the result backend.
    """
    # Signatures come from the app registry rather than `.s()` on the decorated
    # functions: same object at runtime, but the registry lookup is typed.
    header = [
        app.signature("scan.run_module", args=(domain, module))
        for module in MOCK_MODULES
    ]
    callback = app.signature("scan.persist", args=(domain,))
    job = chord(header)(callback)
    return str(job.id)


@app.task(name="scan.run_module", bind=True)
def run_module(self, domain: str, module: str) -> dict:
    """One mock engine run: sleep across steps, report progress, return findings."""
    for index, step in enumerate(_STEPS, start=1):
        self.update_state(
            state="PROGRESS",
            meta={"module": module, "step": step, "of": len(_STEPS), "at": index},
        )
        time.sleep(1)
    return {
        "module": module,
        "domain": domain,
        "findings": [
            {
                "check": f"{module}.reachable",
                "severity": "info",
                "summary": f"{domain} answered the {module} mock probe.",
            }
        ],
    }


@app.task(name="scan.persist")
def persist(results: list[dict], domain: str) -> str:
    """Write the fanned-out module results to Postgres as one artifact row.

    Returns the row id. The table is created on first use precisely because it
    is throwaway; real tables arrive by migration only (issue #6 wipe rules).
    """
    artifact_id = str(uuid.uuid4())
    with psycopg.connect(_database_url()) as conn:
        # IF NOT EXISTS checks before it locks, so two first-ever persists can
        # still collide on the create; the advisory lock serializes just that.
        conn.execute("SELECT pg_advisory_xact_lock(hashtext('scan_artifacts'))")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_artifacts (
                id uuid PRIMARY KEY,
                domain text NOT NULL,
                findings jsonb NOT NULL,
                created_at timestamptz NOT NULL DEFAULT now()
            )
            """
        )
        conn.execute(
            "INSERT INTO scan_artifacts (id, domain, findings) VALUES (%s, %s, %s)",
            (artifact_id, domain, json.dumps(results)),
        )
    return artifact_id
