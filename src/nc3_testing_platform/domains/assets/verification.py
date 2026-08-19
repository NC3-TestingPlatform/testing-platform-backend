"""Pure domain-verification primitives: coverage, tokens, TXT matching.

No session, no network, no clock — everything here is a function of its
arguments, so the parts that decide *authorization* can be tested exhaustively
without a database. The I/O half lives in the service and, from B6b, in the
DNS boundary.

:func:`covers` is the security-critical one. It answers "does this proof cover
that name", which gates scheduling and branded reports in v4.0 and, from v4.1,
intrusive scanning of every name it returns ``True`` for. Suffix-matching bugs
on a label boundary are the classic failure of this shape — `evil-example.lu`
must never be part of `example.lu` — so the comparison is on label lists, never
on strings.
"""

import hmac
import secrets
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from nc3_testing_platform.core.dns_utils import DnsOutcome, ResolverOutcome
from nc3_testing_platform.core.enums import VerificationScope, VerificationStatus


class VerificationFailureCode(StrEnum):
    """Why the last check did not succeed, as stable namespaced text.

    Deliberately **not** in `core/enums.py`: that module holds the closed
    enumerations of the contract, each mirroring a PostgreSQL enum type, and its
    docstring reserves namespaced text (`test_key`, `check_id`, `status_reason`,
    `notification.type`) for the application layer to own. `failure_code` is that
    family — the column and the API schema are both `str` because the contract
    calls it a "stable namespaced reason" — so the vocabulary belongs here, in
    the pure layer that is already exhaustively tested.

    Members are either **stamped** on the challenge and returned with `200`
    (`dns.*`, `challenge.superseded`, `policy.*`), or they travel as a `503` and
    are never written (`platform.*`) — a platform fault must not leave a reason on
    the user's record suggesting their DNS is at fault.

    The namespace prefix carries the one distinction a client needs to act on:
    `dns.` and `challenge.` and `policy.` are outcomes of a check that ran and
    that the user can do something about, so they arrive with `200`. `platform.`
    means the check could not run and nothing was recorded, so it arrives with
    `503`. `claim.` is the refusal, `409`.
    """

    # The check ran. The user can act on all of these.
    RECORD_NOT_FOUND = "dns.record-not-found"
    NAME_NOT_FOUND = "dns.name-not-found"
    TOKEN_MISMATCH = "dns.token-mismatch"
    RESOLVER_FAILURE = "dns.resolver-failure"
    CORROBORATION_NOT_REACHED = "dns.corroboration-not-reached"
    CHALLENGE_EXPIRED = "challenge.expired"
    # The token was replaced while the lookup was in flight, so this check proves
    # nothing about the token that now stands. Distinct from "not found": the new
    # value was never looked for, and telling the user their record is missing
    # would be a false statement about DNS they may have published correctly.
    CHALLENGE_SUPERSEDED = "challenge.superseded"
    ZONE_REQUIRES_DNSSEC = "policy.zone-requires-dnssec"
    # The check could not run. Nothing was recorded.
    RESOLVER_UNAVAILABLE = "platform.resolver-unavailable"
    CAPACITY_EXHAUSTED = "platform.capacity-exhausted"
    # Another organization already holds the claim.
    CLAIM_LOST = "claim.lost"


# 32 bytes of entropy, URL-safe. The token is published in public DNS, so the
# requirement is unpredictability and exact matching, not secrecy: it is stored
# unhashed precisely because the user must be able to read it back to paste it
# into their zone.
_TOKEN_BYTES = 32


def generate_token() -> str:
    """A fresh, unguessable challenge token."""
    return secrets.token_urlsafe(_TOKEN_BYTES)


def _labels(name: str) -> tuple[str, ...]:
    """The name's DNS labels, or ``()`` when it is not a usable name.

    Callers pass canonical A-label values (`core/schemas.py` guarantees it for
    `asset.value`), but this must not depend on that: an empty label — `a..b`,
    a leading dot — is not a name, and returning ``()`` makes every comparison
    below refuse it rather than silently treating it as a suffix of everything.
    """
    cleaned = name.strip()
    # One trailing dot is the root label and is presentation, not content;
    # more than one is a malformed name and must fall through to the empty-label
    # refusal below rather than being quietly normalised away by `rstrip`.
    if cleaned.endswith("."):
        cleaned = cleaned[:-1]
    cleaned = cleaned.lower()
    if not cleaned:
        return ()
    parts = tuple(cleaned.split("."))
    if any(not part for part in parts):
        return ()
    return parts


def covers(proof_value: str, proof_scope: VerificationScope, target: str) -> bool:
    """Whether a proof over `proof_value` at `proof_scope` covers `target`.

    ``exact`` covers that one name. ``zone`` covers the name and everything
    beneath it, including its own apex — "the whole DNS zone (`example.lu` and
    all its subdomains)".

    The zone test compares label *lists* from the right, so coverage can only
    break on a label boundary. A string ``endswith`` would make
    `evil-example.lu` a member of `example.lu`, which is the whole bug this
    exists to avoid.

    :raises ValueError: On a scope this function does not handle. The dispatch
        is exhaustive on purpose: an ``else`` falling through to the zone arm
        would map any future scope — or a caller bug — onto the *more*
        permissive answer. Refusing loudly follows the same rule the
        normalization layer states for unknown vocabulary (IDR-018): a guessed
        answer is worse than a failed request, and here a guess grants scanning
        rights over a domain nobody proved.
    """
    proof_labels = _labels(proof_value)
    target_labels = _labels(target)
    if not proof_labels or not target_labels:
        return False
    if proof_scope is VerificationScope.EXACT:
        return proof_labels == target_labels
    if proof_scope is VerificationScope.ZONE:
        return target_labels[-len(proof_labels) :] == proof_labels
    raise ValueError(f"unhandled verification scope: {proof_scope!r}")


def token_matches(token: str, rrset: Iterable[Sequence[bytes]]) -> bool:
    """Whether any RR in the TXT RRset carries exactly this token.

    Each RR is a sequence of character-strings, which DNS splits at 255 bytes,
    so an RR's strings are joined before comparing — but never across RRs: two
    unrelated records at the same name must not concatenate into a match. The
    comparison is exact and whole-value; a substring match would let an
    attacker who can add any TXT record at the name pass by embedding the
    token inside a longer string.

    Several providers legitimately publish at `_nc3-verify.<domain>`, so the
    RRset routinely holds records that are not ours and a non-match is the
    ordinary case, not a fault.

    A non-ASCII token cannot be one this platform issued — `generate_token`
    emits base64url — so it degrades to "no match" rather than raising
    `UnicodeEncodeError` at whatever call site handed it over.
    """
    if not token.isascii():
        return False
    expected = token.encode("ascii")
    # `compare_digest` over `==` is convention here rather than necessity: the
    # token is published in public DNS, so there is no secret whose comparison
    # timing could leak. Short-circuiting is fine for the same reason.
    return any(
        hmac.compare_digest(b"".join(strings), expected) for strings in rrset
    )


def compute_status(
    *, has_proof: bool, token_expires_at: datetime | None, now: datetime
) -> VerificationStatus:
    """The API status, derived from the two stored rows.

    There is no status column (§4.2-4.3): a proof row means verified, an
    unexpired challenge means pending, anything else is expired. Deriving it
    rather than storing it is what keeps the two rows from disagreeing with a
    third field about the same fact.

    A proof wins over a challenge, because a verified asset that is re-proving
    or widening carries both and must keep reporting the coverage it holds.

    `now` is the caller's — the database clock, so the comparison matches the
    stamp `token_expires_at` was written from rather than the API host's clock.
    """
    if has_proof:
        return VerificationStatus.VERIFIED
    if token_expires_at is not None and token_expires_at > now:
        return VerificationStatus.PENDING
    return VerificationStatus.EXPIRED


@dataclass(frozen=True)
class CheckVerdict:
    """What a set of resolver answers means, decided without touching a database.

    Pure so the acceptance rules — which decide whether an organization acquires a
    terminal claim on a domain — can be tested exhaustively.
    """

    verified: bool
    failure_code: VerificationFailureCode | None
    dnssec_validated: bool = False
    resolvers: tuple[str, ...] = ()
    corroborating_answers: int = 0


# Which failure a caller is told about when no resolver produced an answer. The
# order is deliberate: a definite answer about the name beats a transport problem,
# because it is the one the user can act on.
# Outcomes in which no resolver said anything about the name. All of them mean the
# platform could not perform the check.
_PLATFORM_OUTCOMES = frozenset(
    {DnsOutcome.TIMEOUT, DnsOutcome.TRANSPORT_FAILURE, DnsOutcome.NOT_ATTEMPTED}
)

_NO_ANSWER_CODES: tuple[tuple[DnsOutcome, VerificationFailureCode], ...] = (
    (DnsOutcome.NO_RECORD, VerificationFailureCode.RECORD_NOT_FOUND),
    (DnsOutcome.NAME_NOT_FOUND, VerificationFailureCode.NAME_NOT_FOUND),
    (DnsOutcome.SERVER_FAILURE, VerificationFailureCode.RESOLVER_FAILURE),
    (DnsOutcome.TRANSPORT_FAILURE, VerificationFailureCode.RESOLVER_FAILURE),
)


def evaluate(
    outcomes: Sequence[ResolverOutcome],
    *,
    token: str,
    requested_scope: VerificationScope,
    quorum: int,
) -> CheckVerdict:
    """Decide whether these answers prove control of the name, and record how.

    Two independent bars, either of which is enough for `exact` coverage:

    * **every answer carrying the token was DNSSEC-validated**, which is strictly
      stronger than corroboration because the signature is checked rather than
      compared. "Every" rather than "any": if resolvers disagree about validation
      for one name, one of them is not validating, and treating that as a checked
      signature would be wrong; or
    * **`quorum` resolvers** independently carrying it, which is what defends the
      unsigned zones that are most of `.lu`.

    `zone` coverage additionally **requires** validation, and requires it of every
    answer that carried the token rather than any one of them. Zone is the widest
    grant in the system — in v4.1 it authorizes intrusive scanning of names that
    may be delegated to different legal entities — so it demands the strong proof,
    while `exact` must stay usable by the ~90% of `.lu` domains that are unsigned
    (9.76% signed, dns.lu, 2026-07-27). See IDR-019.

    Absence is not disagreement: a resolver that has not yet seen a freshly
    published record lowers the corroboration count and never produces a distinct
    failure, because it is the ordinary state during propagation.
    """
    answered = [o for o in outcomes if o.outcome is DnsOutcome.ANSWERED]
    if not answered:
        seen = {o.outcome for o in outcomes}
        if seen and seen <= _PLATFORM_OUTCOMES:
            # Nothing answered and nothing even made a DNS-level statement about
            # the name: the fault is ours, so the caller must refuse rather than
            # report a result. `SERVER_FAILURE` deliberately stays out of this set
            # — a validating resolver's SERVFAIL is indistinguishable from a bogus
            # signature, which *is* a statement about the name.
            return CheckVerdict(
                verified=False,
                failure_code=VerificationFailureCode.RESOLVER_UNAVAILABLE,
            )
        code = next(
            (code for outcome, code in _NO_ANSWER_CODES if outcome in seen),
            VerificationFailureCode.RESOLVER_FAILURE,
        )
        return CheckVerdict(verified=False, failure_code=code)

    carrying = [o for o in answered if token_matches(token, o.strings)]
    if not carrying:
        # The name answered, but not with our token. Either nothing is published
        # yet or what is published is somebody else's record at the same name,
        # which is common and not a fault.
        empty = all(not o.strings for o in answered)
        return CheckVerdict(
            verified=False,
            failure_code=(
                VerificationFailureCode.RECORD_NOT_FOUND
                if empty
                else VerificationFailureCode.TOKEN_MISMATCH
            ),
        )

    resolvers = tuple(o.resolver_id for o in carrying)
    # Every answer that carried the token had to be validated, not merely one of
    # them: "any" would let a single unvalidated answer satisfy the strong bar.
    validated = all(o.authenticated for o in carrying)
    verdict = CheckVerdict(
        verified=True,
        failure_code=None,
        dnssec_validated=validated,
        resolvers=resolvers,
        corroborating_answers=len(carrying),
    )

    if requested_scope is VerificationScope.ZONE:
        if not validated:
            return CheckVerdict(
                verified=False,
                failure_code=VerificationFailureCode.ZONE_REQUIRES_DNSSEC,
                resolvers=resolvers,
                corroborating_answers=len(carrying),
            )
    elif requested_scope is not VerificationScope.EXACT:
        # Exhaustive on purpose, for the same reason `covers` refuses loudly: a
        # scope added later would otherwise fall through to the *more* permissive
        # arm and grant coverage nobody decided to grant.
        raise ValueError(f"unhandled verification scope: {requested_scope!r}")
    if validated or len(carrying) >= quorum:
        return verdict
    return CheckVerdict(
        verified=False,
        failure_code=VerificationFailureCode.CORROBORATION_NOT_REACHED,
        resolvers=resolvers,
        corroborating_answers=len(carrying),
    )
