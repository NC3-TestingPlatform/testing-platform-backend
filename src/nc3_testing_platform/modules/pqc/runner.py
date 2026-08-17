"""Run quantumvalidator through the shared child-process runner, then normalize.

The engine call goes through `execution.run_engine`, so quantumvalidator runs
in a killable child under a wall-clock budget and its `QuantumReport` crosses
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
from nc3_testing_platform.modules.execution import run_engine
from nc3_testing_platform.modules.pqc import mapping, schema

# The engine's public entry, resolved inside the child (import-as-library).
QUANTUMVALIDATOR_ENTRY = "quantumvalidator.assessor:assess"

# The wall-clock budget for one probe (a banner read plus one handshake —
# half the dnssec chain-walk budget is generous), and the ceiling a
# caller-supplied `options["budget"]` is clamped to.
DEFAULT_BUDGET = 30.0
MAX_BUDGET = 60.0


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


def _clamp_port(raw: object) -> int | None:
    """A caller-supplied ``options["port"]`` coerced into a valid TCP port.

    Anything that is not a whole number in 1–65535 falls back to ``None`` —
    the engine's own default (443) — mirroring `_clamp_budget`'s
    silent-fallback treatment of untrusted launch options.
    """
    try:
        value = int(raw)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return None
    if not 1 <= value <= 65535:
        return None
    return value


def run_pqc(
    scan_input: ScanInput,
    *,
    progress: ProgressEmitter,
    engine_entry: str = QUANTUMVALIDATOR_ENTRY,
) -> ModuleResult:
    """Probe one host's PQC key-exchange readiness and return a normalized result.

    Honored `options` keys: ``port`` (the service to probe, default the
    engine's 443 — the engine fingerprints STARTTLS and SSH from the banner)
    and ``budget`` (the wall-clock engine bound, clamped to ``MAX_BUDGET``).
    `engine_entry` is injectable so tests can point the runner at a
    recorded-replay engine instead of a live handshake.
    """
    if scan_input.target_domain is None:
        raise ValueError("pqc.quantumvalidator scans a domain, not a file.")
    budget = _clamp_budget(scan_input.options.get("budget", DEFAULT_BUDGET))
    outcome = run_engine(
        engine_entry,
        args=(scan_input.target_domain,),
        kwargs={
            "port": _clamp_port(scan_input.options.get("port")),
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
