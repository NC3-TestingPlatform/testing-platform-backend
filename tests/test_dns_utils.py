"""The DNS boundary: every failure mode, and the two properties that must hold.

Mocked at the dnspython seam, so these assert the mapping and the invariants
rather than the network. The live behaviour of the configured resolvers is pinned
by the PostgreSQL-marked suite and by the story's live-verification step.

Two invariants here are security properties rather than tidiness: no code path
can construct a plaintext resolver, and ``authenticated`` is never reported
without an accompanying answer.
"""

import ssl
import threading
from types import SimpleNamespace

import dns.exception
import dns.flags
import dns.nameserver
import dns.resolver
import pytest

from nc3_testing_platform.core import dns_utils
from nc3_testing_platform.core.settings import DnsResolverConfig

_DOT = DnsResolverConfig(
    address="158.64.1.29", transport="dot", port=853, tls_hostname="dnspub.restena.lu"
)
_DOT2 = DnsResolverConfig(
    address="86.54.11.100",
    transport="dot",
    port=853,
    tls_hostname="unfiltered.joindns4.eu",
)


def _answer(*, ad: bool, strings: tuple[tuple[bytes, ...], ...]) -> SimpleNamespace:
    """A stand-in for dnspython's Answer, in the shape the boundary reads."""
    flags = dns.flags.QR | dns.flags.RD | dns.flags.RA
    if ad:
        flags |= dns.flags.AD
    return SimpleNamespace(
        response=SimpleNamespace(flags=flags),
        rrset=[SimpleNamespace(strings=s) for s in strings],
    )


@pytest.fixture(autouse=True)
def _fresh_outbound_window():
    """The budget is process-wide state; no test may inherit another's spend."""
    dns_utils._outbound_budget.reset()
    yield
    dns_utils._outbound_budget.reset()


@pytest.fixture
def resolve(monkeypatch: pytest.MonkeyPatch):
    """Replace `Resolver.resolve` with a callable the test controls."""

    def install(outcome):
        def fake(self, name, rdtype):  # noqa: ANN001, ANN202 - test double
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome

        monkeypatch.setattr(dns.resolver.Resolver, "resolve", fake)

    return install


def test_no_configured_resolver_refuses_rather_than_guessing() -> None:
    """An unconfigured deployment loses this operation, and never falls back."""
    with pytest.raises(dns_utils.DnsNotConfiguredError):
        dns_utils.resolve_txt("_nc3-verify.example.lu", resolvers=[])


def test_an_answer_carries_its_strings_and_ad_bit(resolve) -> None:
    """A successful lookup reports the RRset, the AD bit and which resolver spoke."""
    resolve(_answer(ad=True, strings=((b"nc3-verify=abc",),)))
    (outcome,) = dns_utils.resolve_txt("_nc3-verify.example.lu", resolvers=[_DOT])
    assert outcome.outcome is dns_utils.DnsOutcome.ANSWERED
    assert outcome.authenticated is True
    assert outcome.strings == ((b"nc3-verify=abc",),)
    assert outcome.resolver_id == "dnspub.restena.lu"


def test_rr_strings_are_not_flattened_across_records(resolve) -> None:
    """Two RRs must stay separate, or unrelated records concatenate into a match."""
    resolve(_answer(ad=False, strings=((b"nc3-ver",), (b"ify=abc",))))
    (outcome,) = dns_utils.resolve_txt("_nc3-verify.example.lu", resolvers=[_DOT])
    assert outcome.strings == ((b"nc3-ver",), (b"ify=abc",))


@pytest.mark.parametrize(
    ("raised", "expected"),
    [
        (dns.resolver.NXDOMAIN(), dns_utils.DnsOutcome.NAME_NOT_FOUND),
        (dns.resolver.NoAnswer(), dns_utils.DnsOutcome.NO_RECORD),
        (dns.resolver.NoNameservers(), dns_utils.DnsOutcome.SERVER_FAILURE),
        (dns.exception.Timeout(), dns_utils.DnsOutcome.TIMEOUT),
        (dns.exception.SyntaxError(), dns_utils.DnsOutcome.TRANSPORT_FAILURE),
        (ssl.SSLCertVerificationError("bad cert"), dns_utils.DnsOutcome.TRANSPORT_FAILURE),
        (OSError("connection refused"), dns_utils.DnsOutcome.TRANSPORT_FAILURE),
    ],
)
def test_every_failure_maps_to_an_outcome_and_never_raises(
    resolve, raised: BaseException, expected: dns_utils.DnsOutcome
) -> None:
    """A resolver that fails is a result, not an exception the caller must catch.

    `NoNameservers` is how a validating resolver's SERVFAIL arrives, so a bogus
    signature lands here rather than as a returned rcode.
    """
    resolve(raised)
    (outcome,) = dns_utils.resolve_txt("_nc3-verify.example.lu", resolvers=[_DOT])
    assert outcome.outcome is expected
    assert outcome.authenticated is False
    assert outcome.strings == ()


def test_a_denial_never_reports_itself_as_authenticated(resolve) -> None:
    """The AD-on-authenticated-denial trap is structurally unreachable.

    A signed zone with no record answers NOERROR + AD + zero answers, and AD there
    attests the denial. Only the answering path can set `authenticated`, so no
    caller can mistake a denial for a validated proof.
    """
    resolve(dns.resolver.NoAnswer())
    (outcome,) = dns_utils.resolve_txt("_nc3-verify.example.lu", resolvers=[_DOT])
    assert outcome.outcome is dns_utils.DnsOutcome.NO_RECORD
    assert outcome.authenticated is False


def test_a_tls_failure_is_not_retried_in_the_clear(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every constructed nameserver is an authenticated transport, always."""
    built: list[object] = []
    original = dns_utils._nameserver

    def spy(resolver: DnsResolverConfig):  # noqa: ANN202 - test double
        server = original(resolver)
        built.append(server)
        return server

    monkeypatch.setattr(dns_utils, "_nameserver", spy)
    monkeypatch.setattr(
        dns.resolver.Resolver,
        "resolve",
        lambda self, name, rdtype: (_ for _ in ()).throw(ssl.SSLError("handshake")),
    )
    (outcome,) = dns_utils.resolve_txt("_nc3-verify.example.lu", resolvers=[_DOT])
    assert outcome.outcome is dns_utils.DnsOutcome.TRANSPORT_FAILURE
    assert len(built) == 1, "a failed TLS handshake must not be retried"
    assert isinstance(built[0], dns.nameserver.DoTNameserver)


def test_a_dot_entry_only_ever_builds_a_dot_nameserver() -> None:
    """There is no branch that yields a plaintext resolver."""
    server = dns_utils._nameserver(_DOT)
    assert isinstance(server, dns.nameserver.DoTNameserver)
    # The name the certificate is verified against; an entry that reached the
    # wire without it would be encrypted but unauthenticated.
    assert server.hostname == _DOT.tls_hostname


def test_capacity_exhaustion_refuses_instead_of_queueing(
    monkeypatch: pytest.MonkeyPatch, resolve
) -> None:
    """The bulkhead fails closed: saturation is a refusal, not unbounded latency."""
    resolve(_answer(ad=True, strings=((b"x",),)))
    full = threading.BoundedSemaphore(1)
    full.acquire()
    monkeypatch.setattr(dns_utils, "_admission", full)
    with pytest.raises(dns_utils.DnsCapacityError):
        dns_utils.resolve_txt("_nc3-verify.example.lu", resolvers=[_DOT])


def test_the_bulkhead_is_released_after_a_failure(resolve) -> None:
    """A failing query must not leak a permit, or the boundary wedges shut."""
    resolve(dns.exception.Timeout())
    for _ in range(3):
        dns_utils.resolve_txt("_nc3-verify.example.lu", resolvers=[_DOT])
    resolve(_answer(ad=True, strings=((b"x",),)))
    (outcome,) = dns_utils.resolve_txt("_nc3-verify.example.lu", resolvers=[_DOT])
    assert outcome.outcome is dns_utils.DnsOutcome.ANSWERED


def test_every_configured_resolver_is_asked(resolve) -> None:
    """Provenance records the whole set, so all of them are queried."""
    resolve(_answer(ad=False, strings=((b"x",),)))
    outcomes = dns_utils.resolve_txt(
        "_nc3-verify.example.lu", resolvers=[_DOT, _DOT2], timeout=1.0
    )
    assert [o.resolver_id for o in outcomes] == [
        "dnspub.restena.lu",
        "unfiltered.joindns4.eu",
    ]


def test_an_expired_deadline_reports_not_attempted(resolve) -> None:
    """"Never asked" must be distinguishable from "disagreed"."""
    resolve(_answer(ad=False, strings=((b"x",),)))
    outcomes = dns_utils.resolve_txt(
        "_nc3-verify.example.lu", resolvers=[_DOT, _DOT2], timeout=1.0, deadline=0.0
    )
    assert [o.outcome for o in outcomes] == [dns_utils.DnsOutcome.NOT_ATTEMPTED] * 2


def test_a_doh_entry_refuses_when_the_transport_is_not_built(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DoH needs extras that are not in the lock; say so instead of failing oddly."""
    doh = DnsResolverConfig(
        address="86.54.11.100", transport="doh", doh_url="https://example.invalid/dns-query"
    )

    def unavailable(*args: object, **kwargs: object) -> None:
        raise ImportError("no httpx")

    monkeypatch.setattr(dns.nameserver, "DoHNameserver", unavailable)
    with pytest.raises(dns_utils.DnsTransportUnavailableError):
        dns_utils._nameserver(doh)


def test_an_unbuildable_transport_reaches_the_caller_as_a_configuration_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """It escapes `resolve_txt`, so it must be what the one consumer already catches.

    `_nameserver` is called outside `_query_one`'s `try`, so this is never mapped
    to a `ResolverOutcome`. `domains/assets/service.run_check` catches
    `DnsNotConfiguredError` and `DnsCapacityError`; as its own base class this
    would have surfaced as a `500` with a traceback instead of the
    `resolver-unavailable` refusal.
    """
    doh = DnsResolverConfig(
        address="86.54.11.100",
        transport="doh",
        doh_url="https://example.invalid/dns-query",
    )

    def unavailable(*args: object, **kwargs: object) -> None:
        raise ImportError("no httpx")

    monkeypatch.setattr(dns.nameserver, "DoHNameserver", unavailable)
    with pytest.raises(dns_utils.DnsNotConfiguredError):
        dns_utils.resolve_txt("_nc3-verify.example.lu", resolvers=[doh])


def test_the_outbound_budget_refuses_once_the_window_is_spent(
    monkeypatch: pytest.MonkeyPatch, resolve
) -> None:
    """A concurrency cap bounds no rate; this is what holds when Redis is gone."""
    resolve(_answer(ad=True, strings=((b"x",),)))
    # Two queries per window: one two-resolver check, and no more.
    monkeypatch.setattr(dns_utils.settings, "verification_global_rate_limit", 2)
    monkeypatch.setattr(dns_utils.settings, "verification_global_rate_window_seconds", 60)
    dns_utils._outbound_budget.reset()

    dns_utils.resolve_txt("_nc3-verify.example.lu", resolvers=[_DOT, _DOT2], timeout=1.0)
    with pytest.raises(dns_utils.DnsCapacityError):
        dns_utils.resolve_txt(
            "_nc3-verify.example.lu", resolvers=[_DOT, _DOT2], timeout=1.0
        )


def test_a_refused_budget_does_not_leak_a_bulkhead_permit(
    monkeypatch: pytest.MonkeyPatch, resolve
) -> None:
    """The two controls are independent; spending one must not wedge the other."""
    resolve(_answer(ad=True, strings=((b"x",),)))
    monkeypatch.setattr(dns_utils.settings, "verification_global_rate_limit", 1)
    monkeypatch.setattr(dns_utils.settings, "verification_global_rate_window_seconds", 60)
    dns_utils._outbound_budget.reset()

    dns_utils.resolve_txt("_nc3-verify.example.lu", resolvers=[_DOT], timeout=1.0)
    for _ in range(3):
        with pytest.raises(dns_utils.DnsCapacityError):
            dns_utils.resolve_txt("_nc3-verify.example.lu", resolvers=[_DOT], timeout=1.0)
    # Every permit is back: a fresh window resolves again rather than wedging.
    dns_utils._outbound_budget.reset()
    (outcome,) = dns_utils.resolve_txt(
        "_nc3-verify.example.lu", resolvers=[_DOT], timeout=1.0
    )
    assert outcome.outcome is dns_utils.DnsOutcome.ANSWERED


def test_the_outbound_window_rolls_over(monkeypatch: pytest.MonkeyPatch, resolve) -> None:
    """The budget is a window, not a lifetime quota."""
    resolve(_answer(ad=True, strings=((b"x",),)))
    monkeypatch.setattr(dns_utils.settings, "verification_global_rate_limit", 1)
    monkeypatch.setattr(dns_utils.settings, "verification_global_rate_window_seconds", 0)
    dns_utils._outbound_budget.reset()
    for _ in range(3):
        dns_utils.resolve_txt("_nc3-verify.example.lu", resolvers=[_DOT], timeout=1.0)
