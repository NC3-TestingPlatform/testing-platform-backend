"""Shared module-contract conformance checks (not a test module).

Every scan module must pass these, so they live in a neutral module rather
than inside a ``test_*.py`` — importing helpers from a collected test module
works only because pytest prepends ``tests/`` to ``sys.path``, and would
break the day a ``tests/__init__.py`` appears. Both `test_module_contract.py`
(no-op) and `test_dnssec_module.py` (the replay-driven exemplar) call these
against the same assertions.
"""

import json

from nc3_testing_platform.core.enums import (
    FindingSeverity,
    ScanClassification,
    ScanModule,
)
from nc3_testing_platform.modules import contract


class RecordingSink:
    """Collects emitted progress events for assertions."""

    def __init__(self) -> None:
        self.events: list[contract.ProgressEvent] = []

    def __call__(self, event: contract.ProgressEvent) -> None:
        """Record one emitted event."""
        self.events.append(event)


def assert_protocol_and_descriptor(module: contract.TestModule) -> None:
    """The module satisfies the protocol and declares platform vocabulary."""
    assert isinstance(module, contract.TestModule)
    descriptor = module.descriptor
    assert isinstance(descriptor.name, ScanModule)
    assert isinstance(descriptor.classification, ScanClassification)
    assert descriptor.queue in contract.MODULE_QUEUES


def assert_severity_hook_rejects_garbage(module: contract.TestModule) -> None:
    """The hook refuses an input outside its vocabulary rather than guessing.

    The *positive* mappings are module-specific — a VerdictSeverity-based
    engine and chainvalidator's four-value status vocabulary map different
    inputs — so each module asserts its own in its own test; the shared
    guarantee is that garbage raises.
    """
    try:
        module.map_severity("definitely-not-a-severity")
    except ValueError:
        return
    raise AssertionError("map_severity must reject an unknown severity")


def assert_run_end_to_end(
    module: contract.TestModule, scan_input: contract.ScanInput
) -> None:
    """One full run: child process, marshalled progress, normalized result.

    The JSON round trip of `raw_output` is the marshalling test: the report
    crossed the process boundary as plain data, not as a pickled object.
    """
    sink = RecordingSink()
    test_key = module.descriptor.tests[0].test_key
    result = module.run(
        scan_input, progress=contract.ProgressEmitter(test_key=test_key, sink=sink)
    )
    assert isinstance(result, contract.ModuleResult)
    assert result.schema_version
    assert json.loads(json.dumps(dict(result.raw_output))) == dict(result.raw_output)
    assert result.findings
    for finding in result.findings:
        assert isinstance(finding.severity, FindingSeverity)
        assert finding.check_id
    assert sink.events, "a run must narrate at least one progress step"
