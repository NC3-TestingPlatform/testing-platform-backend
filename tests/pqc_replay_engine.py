"""A test-only quantumvalidator stand-in that replays a recorded report.

Kept out of the shipped package: it lets the pqc conformance run exercise
the whole runner path — child process, progress marshalling, asdict-dict
transfer — against a recorded `QuantumReport` dict instead of a live
handshake. The spawn child inherits the parent's ``sys.path`` and
environment, so it finds both this module (by entry string
``pqc_replay_engine:assess``) and the fixture path in
``NC3_PQC_REPLAY_FIXTURE``.
"""

import json
import os
from collections.abc import Callable
from typing import Any

FIXTURE_ENV = "NC3_PQC_REPLAY_FIXTURE"


def assess(
    target: str,
    *,
    port: int | None = None,
    timeout: float = 5.0,
    progress_cb: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Return the recorded report named by ``NC3_PQC_REPLAY_FIXTURE``.

    Signature mirrors ``quantumvalidator.assessor.assess`` so the runner
    drives it unchanged; the arguments are accepted and ignored beyond
    narrating one progress line, since the outcome is fixed by the fixture.
    """
    if progress_cb is not None:
        progress_cb(f"Replaying recorded PQC report for {target}:{port or 443}")
    path = os.environ[FIXTURE_ENV]
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)
