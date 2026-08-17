"""The single owner of engine severity → :class:`FindingSeverity` (IDR-018).

A module does not write mapping logic; it **declares a table** as an
:class:`EngineVocabulary` and the platform owns everything around it — how a
value is canonicalized before lookup, and what happens when the lookup misses.
That is the hybrid ownership IDR-018 settles on: centralizing the *policy*
without centralizing the *tables*, because chainvalidator's four-value
``Status`` genuinely is not the engines' five-tier ``VerdictSeverity`` and no
one table can hold both.

`VOCABULARIES` registers the vocabularies of the engines that ship in-tree. It
is an immutable snapshot, not a mutable registry modules write into at import
time: an out-of-tree module package constructs its own `EngineVocabulary` and
holds it as a module-level constant, so nothing here depends on import order.

This module imports platform vocabulary only. It must not import
`modules.contract` — the contract imports *it*, to keep US #76's public
`contract.map_engine_severity` name working.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from nc3_testing_platform.core.enums import FindingSeverity


def _canonical(engine_severity: str) -> str:
    """One engine value folded to its lookup key: stripped and lowercased.

    Matching is case- and space-insensitive because engines are inconsistent
    about both — ``"HIGH"``, ``"High"`` and ``" high "`` are the same value —
    while everything else about the lookup stays strict.
    """
    return engine_severity.strip().lower()


@dataclass(frozen=True)
class EngineVocabulary:
    """One engine's severity vocabulary, declared as a table rather than code.

    Construction canonicalizes and validates the table once, so a typo in a
    module's declaration fails at import time rather than mid-scan. The
    resulting `table` is a read-only view keyed by canonical value.

    :param name: How the vocabulary is identified in errors and in
        `VOCABULARIES` — the engine and the vocabulary it emits, e.g.
        ``"chainvalidator-status"``.
    :param table: Engine value → platform severity. Keys are matched case- and
        space-insensitively, so two keys that fold together are a declaration
        error, not a silent last-one-wins.

    A vocabulary is identified by its `name` — that is the key `VOCABULARIES`
    registers it under, and names are unique. `table` is therefore excluded
    from equality and hashing: `frozen=True` advertises that instances are
    usable as dict keys and set members, but the auto-generated `__hash__`
    would include the `MappingProxyType` and raise `TypeError` on every call.
    Excluding it keeps the promise the decorator makes.
    """

    name: str
    table: Mapping[str, FindingSeverity] = field(compare=False)

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("An engine vocabulary must be named.")
        if not self.table:
            raise ValueError(f"engine vocabulary {self.name!r} declares no values.")
        canonical: dict[str, FindingSeverity] = {}
        for value, severity in self.table.items():
            # `FindingSeverity` is a StrEnum, so a bare "high" slips past a
            # static check at any untyped call site and would then leak out of
            # `map_severity` as a plain str — whose `.value` access fails far
            # from the declaration. Reject it here, at import time.
            if not isinstance(severity, FindingSeverity):
                raise ValueError(
                    f"engine vocabulary {self.name!r} maps {value!r} to "
                    f"{severity!r}, which is not a FindingSeverity member."
                )
            key = _canonical(value)
            if not key:
                raise ValueError(
                    f"engine vocabulary {self.name!r} declares an empty value."
                )
            if key in canonical:
                raise ValueError(
                    f"engine vocabulary {self.name!r} declares {key!r} twice; "
                    "values are matched case- and space-insensitively."
                )
            canonical[key] = severity
        object.__setattr__(self, "table", MappingProxyType(canonical))

    def map_severity(self, engine_severity: str) -> FindingSeverity:
        """One engine value → the platform severity this table declares for it.

        :param engine_severity: The engine's own severity string,
            case-insensitive and tolerant of surrounding whitespace.
        :raises ValueError: If the value is not in the declared table. The
            layer never guesses a severity: an unknown value is a module bug,
            and a wrong severity is worse than a failed task (IDR-018).
        """
        try:
            return self.table[_canonical(engine_severity)]
        except KeyError:
            raise ValueError(
                f"{engine_severity!r} has no severity mapping in the "
                f"{self.name!r} vocabulary; the module must map it explicitly."
            ) from None


# The engines' shared five-tier `VerdictSeverity`, which maps 1:1 onto the
# platform vocabulary — mailvalidator, headersvalidator and tlsvalidator all
# emit it. Built from `FindingSeverity` itself so the 1:1 cannot drift: a new
# platform tier joins this table automatically, and a test pins the domain.
VERDICT_SEVERITY = EngineVocabulary(
    name="verdict-severity",
    table={severity.value: severity for severity in FindingSeverity},
)

# chainvalidator reports chain state, not severity, so the platform decides
# what each state *means*: a bogus link is an active cryptographic failure, an
# insecure delegation is a posture gap, an operational error could not
# validate, and a secure chain is recorded for the evidence trail.
CHAINVALIDATOR_STATUS = EngineVocabulary(
    name="chainvalidator-status",
    table={
        "secure": FindingSeverity.INFO,
        "insecure": FindingSeverity.MEDIUM,
        "bogus": FindingSeverity.HIGH,
        "error": FindingSeverity.LOW,
    },
)

# quantumvalidator reports a per-check Status (pass/fail/info/error) and an
# overall Verdict (safe/unsafe), not severity: a failed PQC-readiness check is
# a CNSA 2.0 / BSI TR-02102 posture gap (harvest-now-decrypt-later exposure,
# the same tier as an unsigned delegation), an operational error could not
# assess, and pass/safe are recorded for the evidence trail.
QUANTUMVALIDATOR_STATUS = EngineVocabulary(
    name="quantumvalidator-status",
    table={
        "pass": FindingSeverity.INFO,
        "info": FindingSeverity.INFO,
        "safe": FindingSeverity.INFO,
        "fail": FindingSeverity.MEDIUM,
        "unsafe": FindingSeverity.MEDIUM,
        "error": FindingSeverity.LOW,
    },
)

# The registry: every vocabulary that ships in-tree, keyed by name. Immutable
# and built here rather than populated by import side effects, so what the
# platform knows does not depend on which modules happen to be imported.
VOCABULARIES: Mapping[str, EngineVocabulary] = MappingProxyType(
    {
        vocabulary.name: vocabulary
        for vocabulary in (
            VERDICT_SEVERITY,
            CHAINVALIDATOR_STATUS,
            QUANTUMVALIDATOR_STATUS,
        )
    }
)


def map_engine_severity(engine_severity: str) -> FindingSeverity:
    """The default severity hook: engine `VerdictSeverity` name → platform value.

    Re-exported as `contract.map_engine_severity`, which is the name US #76
    published and modules import. It stays a per-module *hook* because the 1:1
    is an observation about today's engines, not a law — a module whose engine
    speaks a different vocabulary declares its own `EngineVocabulary` instead.

    :param engine_severity: One of CRITICAL, HIGH, MEDIUM, LOW, INFO, in any
        case.
    :raises ValueError: If the value is outside that five-tier vocabulary.
    """
    return VERDICT_SEVERITY.map_severity(engine_severity)
