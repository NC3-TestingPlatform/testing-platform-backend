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
from datetime import datetime

from nc3_testing_platform.core.enums import VerificationScope, VerificationStatus

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
