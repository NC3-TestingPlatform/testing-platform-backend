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
    """The concurrent-query bulkhead is full; the caller should refuse, not queue."""


class DnsTransportUnavailableError(Exception):
    """A configured transport is not installed in this build."""


_admission = threading.BoundedSemaphore(settings.verification_dns_max_concurrent_queries)


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
    except Exception:
        # TLS and certificate failures surface as ssl/OSError rather than a
        # DNSException. They are a failed check like any other: there is no
        # plaintext retry, deliberately.
        logger.warning("resolver %s failed on transport", resolver_id, exc_info=True)
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
    :raises DnsCapacityError: When the concurrent-query bulkhead is full.
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
