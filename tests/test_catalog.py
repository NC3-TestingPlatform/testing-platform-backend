"""The executable-test catalog against data-model §7.3 and the contract docs.

Drift tests: the catalog (`modules/catalog.py`), the contract documentation
(`V4_TEST_KEYS` in `domains/scans/schemas.py`), and the §7.3 invariants must
name the same tests, or a launch and its documentation quietly diverge.
"""

from nc3_testing_platform.core.enums import ScanClassification, ScanModule
from nc3_testing_platform.domains.scans.schemas import V4_TEST_KEYS
from nc3_testing_platform.modules import catalog
from nc3_testing_platform.modules.catalog import EXECUTABLE_TESTS


def test_catalog_matches_the_documented_contract() -> None:
    """One catalog row per documented test key, in the same order."""
    assert tuple(EXECUTABLE_TESTS) == V4_TEST_KEYS


def test_no_v4_test_is_intrusive() -> None:
    """§7.3: no v4.0 executable test has classification = intrusive."""
    assert all(
        entry.classification is not ScanClassification.INTRUSIVE
        for entry in EXECUTABLE_TESTS.values()
    )


def test_not_applicable_is_file_only() -> None:
    """The `not_applicable` classification is used exactly by File tests (§14)."""
    for entry in EXECUTABLE_TESTS.values():
        assert (entry.module is ScanModule.FILE) == (
            entry.classification is ScanClassification.NOT_APPLICABLE
        )


def test_keys_carry_their_module_namespace() -> None:
    """`test_key` extends its module's namespace, catalog convention."""
    for entry in EXECUTABLE_TESTS.values():
        assert entry.test_key.startswith(f"{entry.module.value}.")


def test_every_module_fans_out_to_something() -> None:
    """Each `ScanModule` member has at least one executable test to run."""
    for module in ScanModule:
        assert catalog.tests_for_module(module), f"{module.value} has no catalog entry"


def test_noop_is_not_schedulable() -> None:
    """The reference module stays off the catalog.

    Rosters may carry `web.noop`; launches must never fan out to it.
    """
    assert "web.noop" not in EXECUTABLE_TESTS
