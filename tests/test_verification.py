"""Unit tests for the pure verification primitives (B6a / US #82).

`covers` decides authorization — scheduling and branded reports in v4.0, and
from v4.1 whether an intrusive scan may touch a name — so it gets more than
worked examples: the invariant tests below quantify over a generated name
space and assert the properties that must hold for *every* pair, in particular
that coverage never breaks anywhere but a label boundary.
"""

import itertools

import pytest

from nc3_testing_platform.core.enums import VerificationScope
from nc3_testing_platform.domains.assets import verification

EXACT = VerificationScope.EXACT
ZONE = VerificationScope.ZONE


# --- covers: worked examples -------------------------------------------------


@pytest.mark.parametrize(
    ("proof", "scope", "target", "expected"),
    [
        # The bug this function exists to prevent: a string suffix that is not
        # a label suffix. `evil-example.lu`.endswith(`example.lu`) is True.
        ("example.lu", ZONE, "evil-example.lu", False),
        ("example.lu", EXACT, "evil-example.lu", False),
        # Zone covers the apex and everything beneath it.
        ("example.lu", ZONE, "example.lu", True),
        ("example.lu", ZONE, "sub.example.lu", True),
        ("example.lu", ZONE, "deep.sub.example.lu", True),
        # Exact covers one name only.
        ("example.lu", EXACT, "example.lu", True),
        ("example.lu", EXACT, "sub.example.lu", False),
        # A shorter target cannot be covered by a longer proof.
        ("sub.example.lu", ZONE, "example.lu", False),
        ("sub.example.lu", ZONE, "lu", False),
        # Sibling zones never cover each other.
        ("a.example.lu", ZONE, "b.example.lu", False),
        # Presentation differences are not semantic differences.
        ("Example.LU", ZONE, "SUB.example.lu", True),
        ("example.lu.", ZONE, "sub.example.lu", True),
        ("example.lu", ZONE, "sub.example.lu.", True),
        ("  example.lu  ", EXACT, "example.lu", True),
        # A-label form compares as the ASCII it is.
        ("xn--mgbh0fb.lu", ZONE, "sub.xn--mgbh0fb.lu", True),
        ("xn--mgbh0fb.lu", ZONE, "xn--other.lu", False),
    ],
)
def test_covers_worked_examples(
    proof: str, scope: VerificationScope, target: str, expected: bool
) -> None:
    """The cases a reviewer would ask about, pinned."""
    assert verification.covers(proof, scope, target) is expected


@pytest.mark.parametrize(
    "malformed",
    ["", ".", "..", "a..b", ".example.lu", "   ", "a...b", "example.lu.."],
)
def test_covers_refuses_malformed_names_on_either_side(malformed: str) -> None:
    """An empty label is not a name — it covers, and is covered by, nothing.

    Refusing both ways matters: a permissive reading of an empty label would
    make the malformed value a suffix of everything.
    """
    assert verification.covers(malformed, ZONE, "example.lu") is False
    assert verification.covers("example.lu", ZONE, malformed) is False
    assert verification.covers(malformed, EXACT, malformed) is False


# --- covers: invariants over a generated name space --------------------------

_LABELS = ("a", "ab", "b", "example", "evil-example")
_NAMES = tuple(
    ".".join(combo)
    for depth in (1, 2, 3)
    for combo in itertools.product(_LABELS, repeat=depth)
)


def _label_list(name: str) -> list[str]:
    return name.split(".")


@pytest.mark.parametrize("scope", [EXACT, ZONE])
def test_covers_is_reflexive(scope: VerificationScope) -> None:
    """Every proof covers its own name, at either scope."""
    for name in _NAMES:
        assert verification.covers(name, scope, name) is True


def test_exact_covers_exactly_the_same_labels() -> None:
    """Exact scope is label equality and nothing else."""
    for proof, target in itertools.product(_NAMES, _NAMES):
        expected = _label_list(proof) == _label_list(target)
        assert verification.covers(proof, EXACT, target) is expected


def test_zone_coverage_only_breaks_on_a_label_boundary() -> None:
    """The load-bearing invariant.

    Whenever zone coverage holds, the target is the proof itself or ends with
    a dot followed by the proof. An implementation that string-matched would
    admit `evil-example.lu` under `example.lu` and fail here.
    """
    for proof, target in itertools.product(_NAMES, _NAMES):
        if verification.covers(proof, ZONE, target):
            assert target == proof or target.endswith(f".{proof}")


def test_zone_coverage_is_closed_under_adding_subdomains() -> None:
    """If a zone covers a name it covers every name beneath that one."""
    for proof, target in itertools.product(_NAMES, _NAMES):
        if verification.covers(proof, ZONE, target):
            assert verification.covers(proof, ZONE, f"deeper.{target}") is True


def test_zone_is_at_least_as_permissive_as_exact() -> None:
    """Widening the scope never removes coverage — the basis of re-verification."""
    for proof, target in itertools.product(_NAMES, _NAMES):
        if verification.covers(proof, EXACT, target):
            assert verification.covers(proof, ZONE, target) is True


# --- tokens ------------------------------------------------------------------


def test_generate_token_is_unpredictable_and_url_safe() -> None:
    """Fresh every call, and safe to render in a DNS TXT value."""
    tokens = {verification.generate_token() for _ in range(100)}
    assert len(tokens) == 100
    for token in tokens:
        assert token.isascii()
        assert " " not in token and '"' not in token
        # 32 bytes base64url-encoded, unpadded, is exactly 43 characters. Pinned
        # rather than lower-bounded so a reduction in entropy fails the test.
        assert len(token) == 43


# --- token_matches -----------------------------------------------------------


def test_token_matches_a_single_record() -> None:
    """The ordinary case: our record alone at the name."""
    token = verification.generate_token()
    assert verification.token_matches(token, [[token.encode()]]) is True


def test_token_matches_alongside_other_providers() -> None:
    """Other verification records at the same name are routine, not a failure."""
    token = verification.generate_token()
    rrset = [
        [b"google-site-verification=abc"],
        [token.encode()],
        [b"v=spf1 -all"],
    ]
    assert verification.token_matches(token, rrset) is True


def test_token_matches_joins_character_strings_within_one_record() -> None:
    """DNS splits a long TXT value at 255 bytes; the RR is still one value."""
    token = verification.generate_token()
    raw = token.encode()
    assert verification.token_matches(token, [[raw[:10], raw[10:]]]) is True


def test_token_does_not_match_across_separate_records() -> None:
    """Two unrelated records must never concatenate into a match."""
    token = verification.generate_token()
    raw = token.encode()
    assert verification.token_matches(token, [[raw[:10]], [raw[10:]]]) is False


def test_token_does_not_match_as_a_substring() -> None:
    """Whole-value match only.

    Otherwise anyone able to add a TXT record at the name passes by embedding
    the token inside a longer string.
    """
    token = verification.generate_token()
    assert verification.token_matches(token, [[b"prefix" + token.encode()]]) is False
    assert verification.token_matches(token, [[token.encode() + b"suffix"]]) is False


def test_token_does_not_match_an_empty_or_absent_rrset() -> None:
    """Nothing published is not a match."""
    token = verification.generate_token()
    assert verification.token_matches(token, []) is False
    assert verification.token_matches(token, [[b""]]) is False


def test_token_does_not_match_a_different_token() -> None:
    """A neighbouring organization's challenge at the same name is not ours."""
    ours = verification.generate_token()
    theirs = verification.generate_token()
    assert verification.token_matches(ours, [[theirs.encode()]]) is False


def test_token_matches_refuses_a_non_ascii_token_without_raising() -> None:
    """No token this platform issues is non-ASCII; degrade, do not explode.

    A corrupted or hand-edited stored value must answer "no match" rather than
    raising UnicodeEncodeError out of whatever call site handed it over.
    """
    assert verification.token_matches("tökén", [[b"t\xc3\xb6k\xc3\xa9n"]]) is False


# --- fail-closed dispatch ----------------------------------------------------


def test_covers_refuses_an_unhandled_scope() -> None:
    """An unknown scope raises rather than falling through to the wider arm.

    The dispatch is exhaustive on purpose: an `else` would map any future scope
    onto zone coverage, granting rights over names nobody proved. Same rule the
    normalization layer states for unknown vocabulary (IDR-018).
    """
    with pytest.raises(ValueError, match="unhandled verification scope"):
        verification.covers("example.lu", "not-a-scope", "sub.example.lu")  # type: ignore[arg-type]
