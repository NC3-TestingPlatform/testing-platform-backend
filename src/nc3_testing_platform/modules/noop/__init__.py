"""The no-op reference module: the contract, exercised end to end.

This is the executable companion to `docs/module-contract.md` and the
template an M* module story copies: it declares a descriptor, validates
its input, runs its (miniature) engine through the shared child-process
runner — progress marshalled over the pipe, report crossing as an
``asdict()`` dict — maps a severity, and returns a normalized result. It
registers under `test_key` ``web.noop``, a key that exists nowhere in the
executable-test catalog, so it can stay on the roster without ever being
scheduled.
"""

import math
from dataclasses import dataclass

from nc3_testing_platform.core.enums import (
    FindingSeverity,
    ScanClassification,
    ScanModule,
)
from nc3_testing_platform.modules.contract import (
    QUEUE_BY_CLASSIFICATION,
    ModuleDescriptor,
    ModuleResult,
    NormalizedFinding,
    ProgressEmitter,
    ScanInput,
    TestDeclaration,
)
from nc3_testing_platform.modules.execution import run_engine
from nc3_testing_platform.modules.normalization.severity import map_engine_severity

SCHEMA_VERSION = "noop/1.0"

# The default wall-clock budget for the engine child, and the ceiling a
# caller-supplied `options["budget"]` is clamped to. The clamp matters
# because `options` is the task `configuration` JSONB, which originates in
# the launch request: an unclamped `{"budget": 1e9}` would pin a worker slot
# and a child for the life of the process. A real module sets its ceiling
# from the engine's expected worst case.
DEFAULT_BUDGET = 30.0
MAX_BUDGET = 120.0

_ENGINE_ENTRY = "nc3_testing_platform.modules.noop.engine:assess"


def _clamp_budget(raw: object) -> float:
    """A caller-supplied ``options["budget"]`` coerced into a safe bound.

    Bounds on both sides: a non-number, non-finite, or non-positive value
    falls back to the default, and anything over ``MAX_BUDGET`` is capped, so
    an untrusted launch-request value can neither fail every scan instantly
    nor pin a worker slot.
    """
    try:
        value = float(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return DEFAULT_BUDGET
    if not math.isfinite(value) or value <= 0:
        return DEFAULT_BUDGET
    return min(value, MAX_BUDGET)


@dataclass(frozen=True)
class NoopModule:
    """A complete :class:`~nc3_testing_platform.modules.contract.TestModule`.

    Stateless and frozen: all per-run state arrives in the input and leaves
    in the result, which is the shape the contract expects of every module.
    """

    descriptor: ModuleDescriptor = ModuleDescriptor(
        name=ScanModule.WEB,
        classification=ScanClassification.NON_INTRUSIVE,
        queue=QUEUE_BY_CLASSIFICATION[ScanClassification.NON_INTRUSIVE],
        engine="builtin",
        engine_version="0",
        tests=(TestDeclaration(test_key="web.noop", test_version="1.0.0"),),
    )

    def run(self, scan_input: ScanInput, *, progress: ProgressEmitter) -> ModuleResult:
        """Run the no-op engine in a child and report one INFO finding.

        Honored `options` keys, all demonstration knobs: ``budget`` (float,
        the wall-clock engine bound; default ``DEFAULT_BUDGET``), ``delay``
        and ``fail`` (passed to the engine to stall or fail on request).
        """
        if scan_input.target_domain is None:
            raise ValueError("web.noop scans a domain, not a file.")
        budget = _clamp_budget(scan_input.options.get("budget", DEFAULT_BUDGET))
        outcome = run_engine(
            _ENGINE_ENTRY,
            args=(scan_input.target_domain,),
            kwargs={
                "timeout": scan_input.timeout,
                "delay": float(scan_input.options.get("delay", 0.0)),
                "fail": bool(scan_input.options.get("fail", False)),
            },
            budget=budget,
            progress=progress,
        )
        report = outcome.unwrap()
        finding = NormalizedFinding(
            check_id="web.noop.ran",
            severity=self.map_severity("INFO"),
            title="The no-op check ran",
            description=(
                f"web.noop inspected {scan_input.target_domain} in a child "
                "process and, by design, concluded nothing."
            ),
            affected_resource=scan_input.target_domain,
            evidence={"steps": list(report["steps"])},
        )
        return ModuleResult(
            schema_version=SCHEMA_VERSION,
            raw_output=report,
            summary={"findings": 1, "verdict": report["verdict"]},
            findings=(finding,),
        )

    def map_severity(self, engine_severity: str) -> FindingSeverity:
        """Delegate to the default 1:1 mapping; the noop has nothing to re-rank."""
        return map_engine_severity(engine_severity)


MODULE = NoopModule()
