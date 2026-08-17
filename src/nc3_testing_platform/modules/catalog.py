"""The v4.0 executable-test catalog (data-model §7.3), owned by application code.

The catalog is the platform's answer to "what does a scan of module X run?" —
the roster (`modules.registry`) answers the different question "what is
installed?". The two deliberately diverge in both directions: `web.noop` is on
the roster but not in the catalog (a reference module must never be scheduled
by a real launch), and most catalog rows have no installed module until B1
provisions the engines — a launch that requests one still creates its task,
`blocked`, so the gap is visible instead of silent.

`test_key` is namespaced text, not an enum (data-model §1): this mapping
extends without a migration. Classification is recorded here — not read from
the module — because a task for an *uninstalled* module still needs its
`classification` column populated at creation (§7.2).
"""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from nc3_testing_platform.core.enums import ScanClassification, ScanModule


@dataclass(frozen=True)
class CatalogEntry:
    """One executable test of the v4.0 catalog (§7.3)."""

    test_key: str
    module: ScanModule
    classification: ScanClassification


def _entry(
    test_key: str, module: ScanModule, classification: ScanClassification
) -> tuple[str, CatalogEntry]:
    """One catalog item, keyed by its `test_key`."""
    return test_key, CatalogEntry(test_key, module, classification)


# §7.3 verbatim. No v4.0 executable test is intrusive, and `not_applicable`
# is used only by the File module — both pinned by tests/test_catalog.py.
EXECUTABLE_TESTS: Mapping[str, CatalogEntry] = MappingProxyType(
    dict(
        (
            _entry(
                "email.mailvalidator",
                ScanModule.EMAIL,
                ScanClassification.NON_INTRUSIVE,
            ),
            _entry("web.headers", ScanModule.WEB, ScanClassification.NON_INTRUSIVE),
            _entry("web.tls", ScanModule.WEB, ScanClassification.NON_INTRUSIVE),
            _entry(
                "web.subdomain_enumeration",
                ScanModule.WEB,
                ScanClassification.NON_INTRUSIVE,
            ),
            _entry(
                "file.hashlookup", ScanModule.FILE, ScanClassification.NOT_APPLICABLE
            ),
            _entry("file.pandora", ScanModule.FILE, ScanClassification.NOT_APPLICABLE),
            _entry("file.metadata", ScanModule.FILE, ScanClassification.NOT_APPLICABLE),
            _entry(
                "file.mime_check", ScanModule.FILE, ScanClassification.NOT_APPLICABLE
            ),
            _entry(
                "pqc.quantumvalidator",
                ScanModule.PQC,
                ScanClassification.NON_INTRUSIVE,
            ),
            _entry(
                "dnssec.chainvalidator",
                ScanModule.DNSSEC,
                ScanClassification.NON_INTRUSIVE,
            ),
        )
    )
)


def tests_for_module(module: ScanModule) -> tuple[CatalogEntry, ...]:
    """The catalog rows one requested module fans out into, in catalog order.

    :param module: A module named in `scan_job.modules`.
    :return: Every executable test the module comprises; never empty for a
        `ScanModule` member, which tests/test_catalog.py pins.
    """
    return tuple(
        entry for entry in EXECUTABLE_TESTS.values() if entry.module is module
    )
