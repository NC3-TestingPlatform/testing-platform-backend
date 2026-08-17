"""The PQC module: quantumvalidator wrapped as a contract module.

Second real engine behind the contract, wired exactly like the dnssec
exemplar: declaration, child-process execution with progress marshalled back,
and a `QuantumReport` normalized into platform findings. Its severity table
(status/verdict → FindingSeverity) is declared through the IDR-018 registry
because the engine speaks its own PASS/FAIL/INFO/ERROR + SAFE/UNSAFE
vocabulary, not the shared `VerdictSeverity`.
"""

from dataclasses import dataclass, field

from nc3_testing_platform.core.enums import (
    FindingSeverity,
    ScanClassification,
    ScanModule,
)
from nc3_testing_platform.modules.contract import (
    QUEUE_BY_CLASSIFICATION,
    ModuleDescriptor,
    ModuleResult,
    ProgressEmitter,
    ScanInput,
    TestDeclaration,
)
from nc3_testing_platform.modules.pqc import mapping, runner, schema

_DESCRIPTOR = ModuleDescriptor(
    name=ScanModule.PQC,
    classification=ScanClassification.NON_INTRUSIVE,
    queue=QUEUE_BY_CLASSIFICATION[ScanClassification.NON_INTRUSIVE],
    engine=schema.ENGINE,
    engine_version=schema.ENGINE_VERSION,
    tests=(TestDeclaration(test_key=schema.TEST_KEY, test_version=schema.TEST_VERSION),),
)


@dataclass(frozen=True)
class PqcModule:
    """A :class:`~nc3_testing_platform.modules.contract.TestModule` over quantumvalidator.

    `engine_entry` is a field, not a constant, so a test can bind the runner
    to a recorded-replay engine and exercise the whole run path offline; in
    production it stays quantumvalidator's real entry.
    """

    engine_entry: str = runner.QUANTUMVALIDATOR_ENTRY
    descriptor: ModuleDescriptor = field(default=_DESCRIPTOR)

    def run(self, scan_input: ScanInput, *, progress: ProgressEmitter) -> ModuleResult:
        """Probe the host's PQC readiness in a child process and normalize it."""
        return runner.run_pqc(
            scan_input, progress=progress, engine_entry=self.engine_entry
        )

    def map_severity(self, engine_severity: str) -> FindingSeverity:
        """Map a quantumvalidator status/verdict onto the platform vocabulary."""
        return mapping.map_status_severity(engine_severity)


MODULE = PqcModule()
