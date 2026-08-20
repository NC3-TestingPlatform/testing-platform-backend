"""The application's sole DNS I/O boundary: TXT lookups over authenticated transport.

Everything that speaks DNS lives here, in the same style as `core/redis_utils.py`,
so tests mock exactly one module. The intended consumer is domain verification
(`domains/assets/service.run_check`, B6b / US #263); nothing else resolves names.

This module is **transport only**. It reports what each configured resolver said
and whether the answer was DNSSEC-validated, and it deliberately knows nothing
about assets, tokens, scopes or the platform's failure-code vocabulary: those are
policy, and policy lives in the assets domain. In particular it does not know
what a quorum is — it queries every configured resolver and lets the caller
count.

Three properties are load-bearing rather than stylistic (IDR-019):

* **Authenticated, encrypted transport, and never a downgrade.** Each resolver is
  reached over DoT with certificate and hostname verification, or over DoH. A TLS
  or certificate failure is a failed check, never a retry in the clear: a silent
  fallback to port 53 would hand an on-path attacker exactly what the transport
  exists to prevent. Nothing here can construct a plaintext resolver.
* **AD is never reported without an answer, structurally.** A signed zone with no
  record answers `NOERROR` + AD + zero answers, where AD attests the authenticated
  *denial* rather than the existence of anything — read naively that becomes a
  "DNSSEC-validated" proof of a record nobody published. Here the only path that
  can set ``authenticated`` is the one that carries an RRset, so the confusion is
  unreachable rather than something each caller has to remember.
* **Admission is bounded and fails closed.** A non-blocking semaphore caps
  concurrent queries. It is not a worker pool: the calling handler is
  synchronous, so it already occupies an AnyIO thread, and a queue would turn
  saturation into unbounded latency instead of a refusal the caller can report.
  Beside it, a process-local fixed window caps the outbound query *rate*, which a
  concurrency cap does not: it is what still holds when Redis, and with it every
  fail-open rate window above, is gone.

Queries run sequentially across resolvers under one total deadline. All of them
are asked, even once the caller's quorum could already be met, because a fixed
`len(resolvers)` amplification factor is easier to reason about and to bound than
an early exit whose cost depends on which answers happened to arrive first, and
because a complete set of outcomes is what the proof's provenance columns record.
"""

import logging
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from time import monotonic

import dns.exception
import dns.flags
import dns.nameserver
import dns.rdatatype
import dns.resolver

from nc3_testing_platform.core.settings import DnsResolverConfig, settings

logger = logging.getLogger("nc3_testing_platform.core.dns")

# EDNS payload size for the DO bit. 1232 is the widely deployed safe ceiling that
# avoids IP fragmentation on paths with a 1280-byte MTU.
_EDNS_PAYLOAD = 1232


class DnsOutcome(StrEnum):
    """What one resolver did, in transport terms only.

    Deliberately not the platform's `failure_code` vocabulary: the mapping from
    "this resolver timed out" to "what the user is told" is a domain decision.
    """

    ANSWERED = "answered"
    NO_RECORD = "no_record"
    NAME_NOT_FOUND = "name_not_found"
    TIMEOUT = "timeout"
    SERVER_FAILURE = "server_failure"
    TRANSPORT_FAILURE = "transport_failure"
    NOT_ATTEMPTED = "not_attempted"


@dataclass(frozen=True)
class ResolverOutcome:
    """One resolver's answer, or its way of not answering.

    :param resolver_id: Stable identifier for provenance — the configured TLS
        hostname or DoH URL where there is one, so a stored proof says which
        operator answered rather than an address that may be re-homed.
    :param authenticated: The AD bit as returned. **Not** proof the token exists;
        see the module docstring.
    """

    resolver_id: str
    outcome: DnsOutcome
    authenticated: bool = False
    # Each entry is one RR's character-strings, matching the shape
    # `domains/assets/verification.token_matches` consumes. Never flattened
    # across RRs: two unrelated records must not concatenate into a match.
    strings: tuple[tuple[bytes, ...], ...] = field(default_factory=tuple)


class DnsNotConfiguredError(Exception):
    """No resolver is configured, so verification cannot run.

    Deliberately raised here rather than refused at startup: `settings` is built
    at import and both the test suite and `make dev` run with no environment, so
    an unconfigured deployment must lose this one operation instead of failing to
    boot.
    """


class DnsCapacityError(Exception):
    """Admission refused; the caller should refuse the request, not queue.

    Either the concurrent-query bulkhead is full, or this process has spent its
    outbound-query budget for the current window.
    """


class DnsTransportUnavailableError(DnsNotConfiguredError):
    """A configured transport is not installed in this build.

    A subclass on purpose. `_nameserver` is called outside `_query_one`'s `try`,
    so this escapes `resolve_txt` rather than becoming a `ResolverOutcome`; to the
    caller it says exactly what the parent says — this deployment has no usable
    resolver — and it must reach the `resolver-unavailable` refusal instead of
    surfacing as a `500` with a traceback.
    """


_admission = threading.BoundedSemaphore(settings.verification_dns_max_concurrent_queries)


class _OutboundBudget:
    """A fixed window over queries actually put on the wire, local to this process.

    The semaphore above bounds *concurrency*, not rate: four slots turned over
    every 20 ms is 200 queries a second, so with fast resolvers the outbound load
    is bounded by nothing but their latency. The Redis-backed windows in
    `domains/assets/dependencies.py` are the rate bound in ordinary operation and
    they are deliberately fail-open, which means the moment Redis goes the only
    surviving control is a concurrency cap. That is exactly when a retry storm
    happens, and what it is aimed at is somebody else's infrastructure — Restena
    and DNS4EU — so the platform must not be able to inflict an unbounded rate on
    them because its own cache is down.

    Sized off the platform-wide check budget rather than a knob of its own, so the
    two cannot drift: one process alone may emit no more than every check the
    global limiter would admit, times the number of configured resolvers a check
    queries. In steady state it is the floor under the Redis window rather than a
    second policy — only a burst straddling both windows' boundaries can reach it
    first, at twice the rate anyone meant to allow, and a `503` is the right answer
    to that. With several worker processes the effective ceiling is this value
    times the worker count: worse than the Redis bound, but a bound, and one that
    does not depend on how fast a resolver answers.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._window_started = monotonic()
        self._spent = 0

    def _limit(self) -> int:
        return settings.verification_global_rate_limit * max(
            1, len(settings.verification_resolvers)
        )

    def try_spend(self, queries: int) -> bool:
        """Reserve `queries` units, or refuse. The whole check, never a part of it.

        Partial admission would leave the unreached resolvers reported as
        NOT_ATTEMPTED, which the assets domain reads as "the quorum disagreed" and
        turns into a `dns.*` code blaming the user for a budget the platform spent.
        """
        window = settings.verification_global_rate_window_seconds
        with self._lock:
            now = monotonic()
            if now - self._window_started >= window:
                self._window_started = now
                self._spent = 0
            if self._spent + queries > self._limit():
                return False
            self._spent += queries
            return True

    def reset(self) -> None:
        """Start a fresh window. For tests, and for nothing else."""
        with self._lock:
            self._window_started = monotonic()
            self._spent = 0


_outbound_budget = _OutboundBudget()


def _nameserver(resolver: DnsResolverConfig) -> dns.nameserver.Nameserver:
    """Build the dnspython nameserver for one configured entry.

    Only authenticated transports are constructible: there is no branch that
    yields a plaintext resolver, so no future edit can reintroduce one by
    omission.
    """
    if resolver.transport == "dot":
        return dns.nameserver.DoTNameserver(
            resolver.address, port=resolver.port, hostname=resolver.tls_hostname
        )
    try:
        return dns.nameserver.DoHNameserver(resolver.doh_url or "")
    except Exception as exc:  # pragma: no cover - depends on optional extras
        # dnspython needs httpx and h2 for DoH and neither is in the lock, so a
        # DoH entry is a configuration error in this build rather than a runtime
        # failure to paper over.
        raise DnsTransportUnavailableError(
            "DNS-over-HTTPS is configured but not available in this build; "
            "install the DoH extras or configure a DoT resolver."
        ) from exc


def _query_one(
    resolver: DnsResolverConfig, name: str, *, timeout: float
) -> ResolverOutcome:
    """Ask one resolver for the TXT RRset at `name`, mapping every failure mode.

    `search` is disabled and the name is used as given, so a relative name can
    never be silently completed against a local suffix.
    """
    resolver_id = resolver.tls_hostname or resolver.doh_url or resolver.address
    client = dns.resolver.Resolver(configure=False)
    client.nameservers = [_nameserver(resolver)]
    client.use_edns(0, dns.flags.DO, _EDNS_PAYLOAD)
    client.search = []
    # Both budgets, deliberately. `lifetime` alone leaves dnspython's per-attempt
    # `timeout` at its 2.0s default, so a silently dropping resolver is retried
    # until the lifetime is spent — three DoT connections and three TLS handshakes
    # per resolver per check. That triples the outbound load the global cap exists
    # to bound, and triples what the platform inflicts on somebody else's
    # infrastructure.
    client.timeout = timeout
    client.lifetime = timeout
    try:
        answer = client.resolve(name, dns.rdatatype.TXT)
    except dns.resolver.NXDOMAIN:
        return ResolverOutcome(resolver_id, DnsOutcome.NAME_NOT_FOUND)
    except dns.resolver.NoAnswer:
        # The name exists but carries no TXT. The ordinary "not published yet"
        # case, distinct from the name being absent, because the remedies differ.
        #
        # `authenticated` stays False on purpose, even though a signed zone's
        # NODATA answer does carry AD (attesting the denial via NSEC). Do not
        # "fix" this by plumbing the flag through: a denial never becomes a proof,
        # so the only thing that could consume it is the mistake of treating AD
        # alone as validation.
        return ResolverOutcome(resolver_id, DnsOutcome.NO_RECORD)
    except dns.resolver.NoNameservers:
        # How a validating resolver's SERVFAIL arrives: a bogus signature, and
        # also a genuinely unreachable upstream. The two are indistinguishable
        # from here, so they share an outcome and neither is treated as a proof.
        return ResolverOutcome(resolver_id, DnsOutcome.SERVER_FAILURE)
    except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
        return ResolverOutcome(resolver_id, DnsOutcome.TIMEOUT)
    except dns.exception.DNSException:
        return ResolverOutcome(resolver_id, DnsOutcome.TRANSPORT_FAILURE)
    except Exception as exc:
        # TLS and certificate failures surface as ssl/OSError rather than a
        # DNSException. They are a failed check like any other: there is no
        # plaintext retry, deliberately.
        # The class only: an exception string is the one place in this module
        # where a queried name could reach shared logs, and domains are personal
        # data that must not leak into telemetry.
        logger.warning(
            "resolver %s failed on transport (%s)",
            resolver_id,
            exc.__class__.__name__,
        )
        return ResolverOutcome(resolver_id, DnsOutcome.TRANSPORT_FAILURE)
    return ResolverOutcome(
        resolver_id,
        DnsOutcome.ANSWERED,
        authenticated=bool(answer.response.flags & dns.flags.AD),
        strings=tuple(tuple(rr.strings) for rr in answer.rrset or ()),
    )


def resolve_txt(
    name: str,
    *,
    resolvers: Sequence[DnsResolverConfig] | None = None,
    timeout: float | None = None,
    deadline: float | None = None,
) -> list[ResolverOutcome]:
    """Ask every configured resolver for the TXT RRset at `name`.

    :param name: The absolute name to query, used verbatim.
    :param resolvers: Override the configured list; for tests.
    :param timeout: Per-query budget. Defaults to the configured value.
    :param deadline: Total budget across all resolvers. Resolvers not reached
        before it expires are reported as :attr:`DnsOutcome.NOT_ATTEMPTED`, so the
        caller can tell "disagreed" from "never asked".
    :raises DnsNotConfiguredError: When no resolver is configured.
    :raises DnsTransportUnavailableError: When a configured entry names a
        transport this build cannot construct. A subclass of the above, so a
        caller that refuses on one refuses on both.
    :raises DnsCapacityError: When the concurrent-query bulkhead is full, or the
        process has spent its outbound-query budget for the window.
    """
    configured = list(resolvers if resolvers is not None else settings.verification_resolvers)
    if not configured:
        raise DnsNotConfiguredError(
            "No verification resolver is configured (VERIFICATION_RESOLVERS)."
        )
    # Explicit None checks, not `or`: a caller passing 0 means zero budget, and
    # `timeout or default` would silently hand it the default instead.
    per_query = (
        settings.verification_query_timeout_seconds if timeout is None else timeout
    )
    total = (
        settings.verification_dns_total_deadline_seconds
        if deadline is None
        else deadline
    )

    if not _admission.acquire(blocking=False):
        raise DnsCapacityError("DNS query capacity exhausted.")
    try:
        # Charged inside the permit and before the first query: the whole check is
        # admitted or none of it is. The charge is the worst case — a deadline that
        # expires part-way leaves some resolvers NOT_ATTEMPTED and unsent — which
        # errs towards sending less, the right direction for a backstop.
        if not _outbound_budget.try_spend(len(configured)):
            raise DnsCapacityError(
                "Outbound DNS query budget exhausted for this window."
            )
        started = monotonic()
        outcomes: list[ResolverOutcome] = []
        for resolver in configured:
            remaining = total - (monotonic() - started)
            if remaining <= 0:
                outcomes.append(
                    ResolverOutcome(
                        resolver.tls_hostname or resolver.doh_url or resolver.address,
                        DnsOutcome.NOT_ATTEMPTED,
                    )
                )
                continue
            outcomes.append(
                _query_one(resolver, name, timeout=min(per_query, remaining))
            )
        return outcomes
    finally:
        _admission.release()
