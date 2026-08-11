"""Run chainvalidator through the shared child-process runner, then normalize.

The engine call goes through `execution.run_engine`, so chainvalidator runs
in a killable child under a wall-clock budget and its `DNSSECReport` crosses
the pipe as a plain ``asdict()`` dict; this module never imports the engine
in the worker process. The dict is then handed to `mapping` — the same shape
the tests replay from recorded fixtures.
"""

import math
from collections.abc import Mapping
from typing import Any

from nc3_testing_platform.modules.contract import (
    ModuleResult,
    ProgressEmitter,
    ScanInput,
)
from nc3_testing_platform.modules.dnssec import mapping, schema
from nc3_testing_platform.modules.execution import run_engine

# The engine's public entry, resolved inside the child (import-as-library).
CHAINVALIDATOR_ENTRY = "chainvalidator.assessor:assess"

# The wall-clock budget for one chain walk, and the ceiling a caller-supplied
# `options["budget"]` is clamped to — the option comes from the launch
# request's JSONB and must not be able to pin a worker slot.
DEFAULT_BUDGET = 60.0
MAX_BUDGET = 120.0


def _clamp_budget(raw: object) -> float:
    """A caller-supplied ``options["budget"]`` coerced into a safe bound.

    `options` is the launch request's JSONB verbatim, so the value is
    untrusted: a non-number, a non-finite, or a non-positive budget falls
    back to the default, and anything larger than ``MAX_BUDGET`` is capped —
    the clamp bounds it on *both* sides so it can neither fail every scan
    instantly nor pin a worker slot.
    """
    try:
        value = float(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return DEFAULT_BUDGET
    if not math.isfinite(value) or value <= 0:
        return DEFAULT_BUDGET
    return min(value, MAX_BUDGET)


def run_dnssec(
    scan_input: ScanInput,
    *,
    progress: ProgressEmitter,
    engine_entry: str = CHAINVALIDATOR_ENTRY,
) -> ModuleResult:
    """Validate one domain's DNSSEC chain and return a normalized result.

    Honored `options` keys: ``record_type`` (the leaf RR type, default
    ``"A"``) and ``budget`` (the wall-clock engine bound, clamped to
    ``MAX_BUDGET``). `engine_entry` is injectable so tests can point the
    runner at a recorded-replay engine instead of live DNS.
    """
    if scan_input.target_domain is None:
        raise ValueError("dnssec.chainvalidator scans a domain, not a file.")
    budget = _clamp_budget(scan_input.options.get("budget", DEFAULT_BUDGET))
    outcome = run_engine(
        engine_entry,
        args=(scan_input.target_domain,),
        kwargs={
            "record_type": str(scan_input.options.get("record_type", "A")),
            "timeout": scan_input.timeout,
        },
        budget=budget,
        progress=progress,
    )
    report: Mapping[str, Any] = outcome.unwrap()
    return ModuleResult(
        schema_version=schema.SCHEMA_VERSION,
        raw_output=report,
        summary=mapping.summarize(report),
        findings=mapping.normalize(report),
    )
