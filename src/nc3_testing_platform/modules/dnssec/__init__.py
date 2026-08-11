"""The DNSSEC module: chainvalidator wrapped as the contract's exemplar.

This is the first module to wrap a real engine, and the worked example the
`docs/module-contract.md` exemplar section walks through. It proves the
contract end to end against `chainvalidator.assessor.assess` — declaration,
child-process execution with progress marshalled back, and a `DNSSECReport`
normalized into platform findings — while its own severity table
(status→FindingSeverity) shows the per-module hook doing real work rather
than delegating to the 1:1 default.
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
from nc3_testing_platform.modules.dnssec import mapping, runner, schema

_DESCRIPTOR = ModuleDescriptor(
    name=ScanModule.DNSSEC,
    classification=ScanClassification.NON_INTRUSIVE,
    queue=QUEUE_BY_CLASSIFICATION[ScanClassification.NON_INTRUSIVE],
    engine=schema.ENGINE,
    engine_version=schema.ENGINE_VERSION,
    tests=(TestDeclaration(test_key=schema.TEST_KEY, test_version=schema.TEST_VERSION),),
)


@dataclass(frozen=True)
class DnssecModule:
    """A :class:`~nc3_testing_platform.modules.contract.TestModule` over chainvalidator.

    `engine_entry` is a field, not a constant, so a test can bind the runner
    to a recorded-replay engine and exercise the whole run path offline; in
    production it stays chainvalidator's real entry.
    """

    engine_entry: str = runner.CHAINVALIDATOR_ENTRY
    descriptor: ModuleDescriptor = field(default=_DESCRIPTOR)

    def run(self, scan_input: ScanInput, *, progress: ProgressEmitter) -> ModuleResult:
        """Walk the domain's DNSSEC chain in a child process and normalize it."""
        return runner.run_dnssec(
            scan_input, progress=progress, engine_entry=self.engine_entry
        )

    def map_severity(self, engine_severity: str) -> FindingSeverity:
        """Map a chainvalidator ``Status`` value onto the platform vocabulary."""
        return mapping.map_status_severity(engine_severity)


MODULE = DnssecModule()
