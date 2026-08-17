"""Engine letter grade → :class:`ScanGrade`, as a strict parse (IDR-018).

Reconciliation, not conversion. The three grading engines — mailvalidator,
headersvalidator and tlsvalidator — each emit exactly ``A+ A B C D`` with an
``F`` fallback, which is precisely the six `ScanGrade` members, so the letter
crosses the boundary unchanged. What does *not* cross is the meaning: the
engines' penalty thresholds differ (mail ``0/10/20/30/40``; headers and tls
``0/5/20/40/60``), so a ``B`` from one engine is not a ``B`` from another.

That is why this module offers a parse and nothing else. There is deliberately
no rescaling, no averaging, and no cross-module composite — a grade is
comparable only against the same test's own history (data-model §8.1, "No
cross-module composite score is stored").

No v4.0 module populates `ModuleResult.grade` yet: the dnssec exemplar and the
noop reference do not grade. The first consumers are the M-stories for
`email.mailvalidator`, `web.headers` and `web.tls`.
"""

from nc3_testing_platform.core.enums import ScanGrade


def map_engine_grade(engine_grade: str) -> ScanGrade:
    """One engine letter grade → the platform :class:`ScanGrade` member.

    Case-insensitive and tolerant of surrounding whitespace, matching the
    severity mapper's canonicalization. Nothing else is accepted: the enum
    *member* spellings (``"A_PLUS"``, ``"aplus"``) are rejected rather than
    aliased, because they are Python names for the value and no engine emits
    them — accepting them would invite a module to pass a name where the
    contract wants a grade.

    :param engine_grade: The engine's letter, e.g. ``"A+"``, ``"b"``, ``" C "``.
    :raises ValueError: If the letter is outside ``A+ A B C D F``. There is no
        ``F`` fallback for an unparseable grade: silently grading a scan the
        worst possible letter is a data-integrity bug, not a safe default
        (IDR-018).
    """
    try:
        return ScanGrade(engine_grade.strip().upper())
    except ValueError:
        raise ValueError(
            f"engine grade {engine_grade!r} is not one of "
            f"{', '.join(grade.value for grade in ScanGrade)}; the module must "
            "map it explicitly."
        ) from None
