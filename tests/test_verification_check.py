"""The check: acceptance rules, and the shape of `run_check`'s three outcomes.

`evaluate` decides whether an organization acquires a **terminal, platform-wide**
claim on a domain, so it is tested as the authorization function it is rather than
as a formatting helper. `run_check`'s tests are about ordering and failure
handling: what is written, in which transaction, and what is refused.

The claim adjudication itself, being a database constraint, is asserted against a
real PostgreSQL in `test_verification_postgres.py`. Compiled-SQL assertions cannot
see it.
"""

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy.exc import IntegrityError

from nc3_testing_platform.core.dns_utils import DnsOutcome, ResolverOutcome
from nc3_testing_platform.core.enums import AssetType, VerificationScope
from nc3_testing_platform.domains.assets import service, verification
from nc3_testing_platform.domains.assets.verification import VerificationFailureCode

EXACT = VerificationScope.EXACT
ZONE = VerificationScope.ZONE
TOKEN = "nc3-verify-abc"


def _answered(
    resolver_id: str, *, ad: bool = False, token: str | None = TOKEN
) -> ResolverOutcome:
    strings = ((token.encode(),),) if token is not None else ()
    return ResolverOutcome(
        resolver_id, DnsOutcome.ANSWERED, authenticated=ad, strings=strings
    )


# --- evaluate: the acceptance rules -----------------------------------------


def test_one_validated_answer_is_enough_for_exact_however_high_the_quorum() -> None:
    """A checked signature is strictly stronger than agreement between caches."""
    verdict = verification.evaluate(
        [_answered("a", ad=True)], token=TOKEN, requested_scope=EXACT, quorum=3
    )
    assert verdict.verified is True
    assert verdict.dnssec_validated is True
    assert verdict.corroborating_answers == 1


def test_unsigned_exact_needs_the_quorum() -> None:
    """Most of `.lu` is unsigned, so corroboration is the control that carries it."""
    one = verification.evaluate(
        [_answered("a")], token=TOKEN, requested_scope=EXACT, quorum=3
    )
    assert one.verified is False
    assert one.failure_code is VerificationFailureCode.CORROBORATION_NOT_REACHED

    three = verification.evaluate(
        [_answered("a"), _answered("b"), _answered("c")],
        token=TOKEN,
        requested_scope=EXACT,
        quorum=3,
    )
    assert three.verified is True
    assert three.dnssec_validated is False
    assert three.resolvers == ("a", "b", "c")


def test_zone_requires_validation_and_requires_it_of_every_answer() -> None:
    """Zone is the widest grant in the system, so it demands the strong proof.

    "Every" rather than "any": one unvalidated answer alongside a validated one
    must not satisfy the stronger bar.
    """
    unsigned = verification.evaluate(
        [_answered("a"), _answered("b"), _answered("c")],
        token=TOKEN,
        requested_scope=ZONE,
        quorum=2,
    )
    assert unsigned.failure_code is VerificationFailureCode.ZONE_REQUIRES_DNSSEC

    mixed = verification.evaluate(
        [_answered("a", ad=True), _answered("b")],
        token=TOKEN,
        requested_scope=ZONE,
        quorum=1,
    )
    assert mixed.failure_code is VerificationFailureCode.ZONE_REQUIRES_DNSSEC

    signed = verification.evaluate(
        [_answered("a", ad=True), _answered("b", ad=True)],
        token=TOKEN,
        requested_scope=ZONE,
        quorum=2,
    )
    assert signed.verified is True


def test_a_partial_propagation_lowers_the_count_rather_than_failing_distinctly() -> None:
    """Absence is "not yet", not disagreement — it is the ordinary retry path."""
    verdict = verification.evaluate(
        [_answered("a"), _answered("b"), ResolverOutcome("c", DnsOutcome.NO_RECORD)],
        token=TOKEN,
        requested_scope=EXACT,
        quorum=2,
    )
    assert verdict.verified is True
    assert verdict.corroborating_answers == 2


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        (DnsOutcome.NO_RECORD, VerificationFailureCode.RECORD_NOT_FOUND),
        (DnsOutcome.NAME_NOT_FOUND, VerificationFailureCode.NAME_NOT_FOUND),
        (DnsOutcome.TIMEOUT, VerificationFailureCode.RESOLVER_TIMEOUT),
        (DnsOutcome.SERVER_FAILURE, VerificationFailureCode.RESOLVER_FAILURE),
        (DnsOutcome.TRANSPORT_FAILURE, VerificationFailureCode.RESOLVER_FAILURE),
        (DnsOutcome.NOT_ATTEMPTED, VerificationFailureCode.RESOLVER_FAILURE),
    ],
)
def test_every_no_answer_case_names_a_reason(
    outcome: DnsOutcome, expected: VerificationFailureCode
) -> None:
    """No outcome may leave the user without a reason, including "never asked"."""
    verdict = verification.evaluate(
        [ResolverOutcome("a", outcome)], token=TOKEN, requested_scope=EXACT, quorum=1
    )
    assert verdict.verified is False
    assert verdict.failure_code is expected


def test_a_definite_answer_about_the_name_beats_a_transport_problem() -> None:
    """The user can act on "no record"; they cannot act on our timeout."""
    verdict = verification.evaluate(
        [ResolverOutcome("a", DnsOutcome.TIMEOUT), ResolverOutcome("b", DnsOutcome.NO_RECORD)],
        token=TOKEN,
        requested_scope=EXACT,
        quorum=1,
    )
    assert verdict.failure_code is VerificationFailureCode.RECORD_NOT_FOUND


def test_a_record_that_is_not_ours_is_distinguished_from_no_record() -> None:
    """Several providers publish at the challenge name; that is not a fault."""
    mismatch = verification.evaluate(
        [_answered("a", token="somebody-elses-value")],
        token=TOKEN,
        requested_scope=EXACT,
        quorum=1,
    )
    assert mismatch.failure_code is VerificationFailureCode.TOKEN_MISMATCH

    empty = verification.evaluate(
        [_answered("a", token=None)], token=TOKEN, requested_scope=EXACT, quorum=1
    )
    assert empty.failure_code is VerificationFailureCode.RECORD_NOT_FOUND


def test_a_verified_verdict_never_carries_a_failure_code() -> None:
    """The two are mutually exclusive, and the response echoes both fields."""
    verdict = verification.evaluate(
        [_answered("a", ad=True)], token=TOKEN, requested_scope=ZONE, quorum=1
    )
    assert (verdict.verified, verdict.failure_code) == (True, None)


# --- run_check: ordering and refusals ---------------------------------------


class _Violation(Exception):
    """A DBAPI error shaped like psycopg's, which carries the constraint name.

    Constructed through `IntegrityError`'s `orig` argument rather than assigned
    afterwards, because `orig` is typed as an exception and the service reads
    `orig.diag.constraint_name` off it.
    """

    def __init__(self, constraint_name: str) -> None:
        super().__init__(constraint_name)
        self.diag = SimpleNamespace(constraint_name=constraint_name)


class _FakeSession:
    """Records the sequence of transaction boundaries, which is what matters here."""

    def __init__(self) -> None:
        self.events: list[str] = []
        self.nested_failure: Exception | None = None

    def commit(self) -> None:
        self.events.append("commit")

    def begin_nested(self):  # noqa: ANN202 - context manager stand-in
        session = self

        class _Savepoint:
            def __enter__(self) -> None:
                session.events.append("savepoint")

            def __exit__(self, *exc: object) -> bool:
                session.events.append("savepoint-exit")
                return False

        return _Savepoint()


@pytest.fixture
def wired(monkeypatch: pytest.MonkeyPatch):
    """Stand every collaborator up so only ordering and branching are under test."""
    asset_id, org_id, user_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    asset = SimpleNamespace(
        id=asset_id, asset_type=AssetType.DOMAIN, value="example.lu"
    )
    challenge = SimpleNamespace(
        record_name="_nc3-verify.example.lu",
        verification_token=TOKEN,
        requested_scope=EXACT,
        token_expires_at=datetime.now(UTC) + timedelta(days=3),
    )
    state = {"stamped": [], "proof": None, "named": False}

    monkeypatch.setattr(service.repository, "asset_for", lambda db, aid: asset)
    monkeypatch.setattr(service.repository, "challenge_for", lambda db, aid: challenge)
    monkeypatch.setattr(service.repository, "proof_for", lambda db, aid: state["proof"])
    monkeypatch.setattr(
        service.repository,
        "stamp_check",
        lambda db, aid, *, code: state["stamped"].append(code) or 1,
    )
    monkeypatch.setattr(service, "_db_now", lambda db: datetime.now(UTC))
    monkeypatch.setattr(service.rls, "set_org_context", lambda *a, **k: None)
    monkeypatch.setattr(
        service.org_service,
        "name_organization_if_unnamed",
        lambda db, **kw: state.__setitem__("named", True) or True,
    )
    monkeypatch.setattr(
        service.verification,
        "compute_status",
        lambda **kw: verification.VerificationStatus.PENDING,
    )
    return SimpleNamespace(
        db=_FakeSession(),
        asset_id=asset_id,
        org_id=org_id,
        user_id=user_id,
        asset=asset,
        challenge=challenge,
        state=state,
        monkeypatch=monkeypatch,
    )


def _run(wired) -> object:
    return service.run_check(
        wired.db,
        asset_id=wired.asset_id,
        organization_id=wired.org_id,
        user_id=wired.user_id,
    )


def test_an_expired_token_refuses_without_resolving(wired) -> None:
    """The lifetime is enforced, so a stale record cannot win a claim later."""
    wired.challenge.token_expires_at = datetime.now(UTC) - timedelta(seconds=1)

    def explode(*a: object, **k: object) -> None:
        raise AssertionError("an expired challenge must not reach the network")

    wired.monkeypatch.setattr(service.dns_utils, "resolve_txt", explode)
    with pytest.raises(service.ChallengeExpiredError):
        _run(wired)


def test_the_transaction_ends_before_the_lookup(wired) -> None:
    """The pooled connection must not be held across a network wait."""
    seen: list[str] = []

    def resolve(name: str) -> list[ResolverOutcome]:
        seen.append(name)
        assert wired.db.events == ["commit"], (
            "the read transaction must be closed before resolving"
        )
        return [_answered("a", ad=True)]

    wired.monkeypatch.setattr(service.dns_utils, "resolve_txt", resolve)
    monkey = wired.monkeypatch
    monkey.setattr(service.repository, "upsert_proof", lambda db, **kw: SimpleNamespace(**kw))
    _run(wired)
    assert seen == ["_nc3-verify.example.lu"]


def test_an_unavailable_resolver_records_nothing(wired) -> None:
    """A platform fault must not be reported as the user's DNS being wrong."""
    wired.monkeypatch.setattr(
        service.dns_utils,
        "resolve_txt",
        lambda name: (_ for _ in ()).throw(service.dns_utils.DnsCapacityError()),
    )
    with pytest.raises(service.ResolverUnavailableError):
        _run(wired)
    assert wired.state["stamped"] == []


def test_a_failed_check_stamps_a_reason_and_keeps_the_challenge(wired) -> None:
    """A check that ran and found nothing is a result, not a fault: 200 + a code."""
    wired.monkeypatch.setattr(
        service.dns_utils,
        "resolve_txt",
        lambda name: [ResolverOutcome("a", DnsOutcome.NO_RECORD)],
    )
    _run(wired)
    assert wired.state["stamped"] == [VerificationFailureCode.RECORD_NOT_FOUND.value]


def test_success_clears_a_previous_failure(wired) -> None:
    """A verified asset must not report yesterday's reason alongside its proof."""
    wired.monkeypatch.setattr(
        service.dns_utils, "resolve_txt", lambda name: [_answered("a", ad=True)]
    )
    wired.monkeypatch.setattr(
        service.repository, "upsert_proof", lambda db, **kw: SimpleNamespace(**kw)
    )
    _run(wired)
    assert wired.state["stamped"] == [None]
    assert wired.state["named"] is True


def test_a_regenerated_token_is_not_proved_against_the_stale_value(wired) -> None:
    """The challenge is re-read after the lookup, so a mid-flight replace wins."""
    wired.monkeypatch.setattr(
        service.dns_utils, "resolve_txt", lambda name: [_answered("a", ad=True)]
    )

    reads = {"n": 0}

    def replaced(db: object, aid: object) -> object:
        # Only the re-read sees the new token: the first read is what the check
        # captured and resolved against.
        reads["n"] += 1
        if reads["n"] > 1:
            wired.challenge.verification_token = "a-different-token"
        return wired.challenge

    wired.monkeypatch.setattr(service.repository, "challenge_for", replaced)

    def explode(*a: object, **k: object) -> None:
        raise AssertionError("a superseded token must not write a proof")

    wired.monkeypatch.setattr(service.repository, "upsert_proof", explode)
    _run(wired)
    # Not RECORD_NOT_FOUND: the new token was never looked for, so saying the
    # record is missing would be false about DNS the user may have got right.
    assert wired.state["stamped"] == [VerificationFailureCode.CHALLENGE_SUPERSEDED.value]


def test_a_lost_claim_is_refused_and_the_reason_is_recorded(wired) -> None:
    """The 409 is stamped, so the user can see why, and only this constraint counts."""
    wired.monkeypatch.setattr(
        service.dns_utils, "resolve_txt", lambda name: [_answered("a", ad=True)]
    )
    conflict = IntegrityError("stmt", {}, _Violation("uq_domain_verification_value"))

    def raise_conflict(db: object, **kw: object) -> None:
        raise conflict

    wired.monkeypatch.setattr(service.repository, "upsert_proof", raise_conflict)
    with pytest.raises(service.DomainClaimLostError):
        _run(wired)
    assert wired.state["stamped"] == [VerificationFailureCode.CLAIM_LOST.value]


def test_another_integrity_error_is_not_reported_as_a_lost_claim(wired) -> None:
    """A referential or denormalisation bug of ours must not blame the user."""
    wired.monkeypatch.setattr(
        service.dns_utils, "resolve_txt", lambda name: [_answered("a", ad=True)]
    )
    other = IntegrityError("stmt", {}, _Violation("fk_domain_verification_asset_value"))

    def raise_other(db: object, **kw: object) -> None:
        raise other

    wired.monkeypatch.setattr(service.repository, "upsert_proof", raise_other)
    with pytest.raises(IntegrityError):
        _run(wired)
    assert wired.state["stamped"] == []


def test_a_vanished_stamp_raises_instead_of_reporting_success(wired) -> None:
    """A lost RLS context makes the write match nothing, silently. Rowcount catches it."""
    wired.monkeypatch.setattr(
        service.dns_utils,
        "resolve_txt",
        lambda name: [ResolverOutcome("a", DnsOutcome.NO_RECORD)],
    )
    wired.monkeypatch.setattr(service.repository, "stamp_check", lambda db, aid, *, code: 0)
    with pytest.raises(RuntimeError, match="organization context"):
        _run(wired)
