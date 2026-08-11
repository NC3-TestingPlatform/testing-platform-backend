"""A test-only chainvalidator stand-in that replays a recorded report.

Kept out of the shipped package: it lets the dnssec conformance run exercise
the whole runner path — child process, progress marshalling, asdict-dict
transfer — against a recorded `DNSSECReport` dict instead of live DNS. The
spawn child inherits the parent's ``sys.path`` and environment, so it finds
both this module (by entry string ``dnssec_replay_engine:assess``) and the
fixture path in ``NC3_DNSSEC_REPLAY_FIXTURE``.
"""

import json
import os
from collections.abc import Callable
from typing import Any

FIXTURE_ENV = "NC3_DNSSEC_REPLAY_FIXTURE"


def assess(
    domain: str,
    *,
    record_type: str = "A",
    timeout: float = 5.0,
    progress_cb: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Return the recorded report named by ``NC3_DNSSEC_REPLAY_FIXTURE``.

    Signature mirrors ``chainvalidator.assessor.assess`` so the runner drives
    it unchanged; the arguments are accepted and ignored beyond narrating one
    progress line, since the outcome is fixed by the fixture.
    """
    if progress_cb is not None:
        progress_cb(f"Replaying recorded DNSSEC report for {domain} ({record_type})")
    path = os.environ[FIXTURE_ENV]
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)
