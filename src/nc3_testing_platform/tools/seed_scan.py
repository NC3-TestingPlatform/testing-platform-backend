"""Seed one guest scan job and dispatch it — the compose smoke's entry point.

`make scan` runs this inside the platform worker container. It commits a
guest `scan_job` with a single pre-created `web.noop` task and publishes
`scan.dispatch`, exercising the real pipeline end to end — broker delivery,
the registry gate, the killable child runner, row persistence, completion
counting — with zero network egress and no engine packages, because the
no-op reference module is the engine.

The task is pre-created here (instead of letting dispatch build the matrix)
deliberately: `web.noop` is on the roster but not in the executable-test
catalog, so the matrix would never schedule it — and the catalog's real tests
have no engines until B1 provisions the images. Dispatch's idempotent
re-publish path picks up the existing row, which is the same path the reaper
uses for stranded jobs, so the smoke covers it.

`SCAN_MODULE` (e.g. ``dnssec``) switches to a provisioned catalog module for
manual live verification: the job is committed alone and `scan.dispatch`
builds the matrix from the §7.3 catalog — the production shape. CI passes no
`SCAN_MODULE`, so the smoke stays on the zero-egress noop path.
"""

import hashlib
import os
import secrets
import sys
from datetime import UTC, datetime, timedelta

from uuid6 import uuid7

from nc3_testing_platform.core.enums import (
    ScanJobStatus,
    ScanModule,
    ScanSource,
    ScanTaskStatus,
)
from nc3_testing_platform.domains.scans.models import ScanJob, ScanTask
from nc3_testing_platform.modules.registry import discover
from nc3_testing_platform.worker.app import app
from nc3_testing_platform.worker.db import session


def main() -> None:
    """Create the job (and the noop path's task), dispatch, print the job id."""
    domain = os.environ.get("SCAN_DOMAIN") or (
        sys.argv[1] if len(sys.argv) > 1 else "example.com"
    )
    # Empty → the noop path; a ScanModule value → catalog fan-out. A bad value
    # raises ValueError here, loudly, before anything is committed.
    module_value = os.environ.get("SCAN_MODULE", "").strip().lower()
    module = ScanModule(module_value) if module_value else ScanModule.WEB
    now = datetime.now(UTC)
    job_id = uuid7()
    # A real guest launch returns the plaintext once and stores only the
    # hash; the smoke never claims, so the token is discarded outright.
    token_hash = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
    with session() as unit:
        unit.add(
            ScanJob(
                id=job_id,
                source=ScanSource.GUEST,
                target_domain=domain,
                modules=[module],
                status=ScanJobStatus.QUEUED,
                claim_token_hash=token_hash,
                # Unclaimed guest retention: 24 hours from creation (§7.1).
                purge_at=now + timedelta(hours=24),
            )
        )
        if not module_value:
            # The task copies its metadata from the noop's declaration, exactly
            # as plan_task_matrix would — hardcoding the version here would
            # drift. A catalog module gets NO pre-created task: a pre-existing
            # matrix makes dispatch skip plan_task_matrix (idempotency guard).
            noop = discover().by_test_key("web.noop").implementation.descriptor
            declared = next(t for t in noop.tests if t.test_key == "web.noop")
            unit.add(
                ScanTask(
                    id=uuid7(),
                    scan_job_id=job_id,
                    module=noop.name,
                    test_key=declared.test_key,
                    test_version=declared.test_version,
                    classification=noop.classification,
                    target_domain=domain,
                    status=ScanTaskStatus.QUEUED,
                )
            )
        unit.commit()
    # Enqueue only after the creating transaction commits (launch order rule).
    app.send_task("scan.dispatch", args=(str(job_id),), queue="platform")
    print(job_id)


if __name__ == "__main__":
    main()
