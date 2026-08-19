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

from nc3_testing_platform.core.enums import VerificationScope

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
    cleaned = name.strip().rstrip(".").lower()
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
    """
    proof_labels = _labels(proof_value)
    target_labels = _labels(target)
    if not proof_labels or not target_labels:
        return False
    if proof_scope is VerificationScope.EXACT:
        return proof_labels == target_labels
    return target_labels[-len(proof_labels) :] == proof_labels


def token_matches(token: str, rrset: Iterable[Sequence[bytes]]) -> bool:
    """Whether any RR in the TXT RRset carries exactly this token.

    Each RR is a sequence of character-strings, which DNS splits at 255 bytes,
    so an RR's strings are joined before comparing — but never across RRs: two
    unrelated records at the same name must not concatenate into a match. The
    comparison is exact and whole-value; a substring match would let an
    attacker who can add any TXT record at the name pass by embedding the
    token inside a longer string.

    Several providers legitimately publish at `_nc3-verify.<domain>`, so the
    RRset routinely holds records that are not ours. Every RR is examined
    rather than stopping at the first hit, keeping the work independent of
    where in the set the match sits.
    """
    expected = token.encode("ascii")
    matched = False
    for strings in rrset:
        if hmac.compare_digest(b"".join(strings), expected):
            matched = True
    return matched
