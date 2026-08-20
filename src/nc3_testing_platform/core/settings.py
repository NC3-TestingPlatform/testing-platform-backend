"""The one place the application reads its environment.

Every value a deployment can change without a code change is a field here,
parsed and bounded once at import — which is process start — so a misconfigured
deployment fails immediately with a readable error naming the variable, instead
of crashing on first use.

Two ways to supply a value, per 12-factor:

* ``NAME=value`` — the plain environment variable.
* ``NAME_FILE=/path`` — the value is read from the named file, stripped of
  surrounding whitespace: editors append trailing newlines, and a leading
  space in a mounted secret is an accident (indentation, copy-paste), never
  part of the value. This is the secrets-manager convention: an orchestrator
  mounts the secret as a file (e.g. ``/run/secrets/app_encryption_master_key``,
  data-model §1.2) and the environment carries only the path. When both are
  set, the file wins — a mounted secret must not lose to a stale variable.

``migrations/env.py`` deliberately keeps its own ``DATABASE_URL`` read with no
default: a downgrade against a silently-defaulted database drops every table.
"""

import os
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from pydantic.fields import FieldInfo
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)


class _FileIndirectionSource(PydanticBaseSettingsSource):
    """Resolves ``NAME_FILE`` indirection for every field.

    Placed before the plain environment source, so a file-provided value wins
    over a plain variable of the same name.
    """

    def get_field_value(
        self, field: FieldInfo, field_name: str
    ) -> tuple[Any, str, bool]:
        pointer = f"{field_name.upper()}_FILE"
        path = os.environ.get(pointer)
        if path is None or not path.strip():
            return None, field_name, False
        try:
            value = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError(
                f"{pointer} points at {path!r}, which cannot be read: {exc}."
            ) from None
        return value.strip(), field_name, False

    def prepare_field_value(
        self, field_name: str, field: FieldInfo, value: Any, value_is_complex: bool
    ) -> Any:
        return value

    def __call__(self) -> dict[str, Any]:
        values: dict[str, Any] = {}
        for field_name, field in self.settings_cls.model_fields.items():
            value, key, _ = self.get_field_value(field, field_name)
            if value is not None:
                values[key] = value
        return values

# `core/api_db.py` builds both engines with `create_engine(url, pool_pre_ping=True)`
# and no explicit sizing, so SQLAlchemy's defaults apply: `pool_size=5` plus
# `max_overflow=10`. The DNS bulkhead has to stay under that, because a check
# that outlived its connection would starve every other operation on the same
# role. If pool sizing ever becomes configurable, this constant moves with it.
_APP_POOL_CEILING = 15


class DnsResolverConfig(BaseModel):
    """One configured recursive resolver, carrying the transport it speaks.

    Transport is per entry rather than global because the two operators NC3
    configures speak different ones: Restena answers DoT on 853 and filters
    plaintext 53, while CIRCL answers DoH on 443 and refuses 853. A single
    global transport field could not express the real deployment.

    Both transports authenticate the resolver, so each carries the material that
    makes that possible: a DoT entry needs the hostname its certificate is
    checked against, a DoH entry needs its URL. An entry without that would be
    encryption with the on-path attacker still in place (IDR-019).
    """

    model_config = ConfigDict(frozen=True)

    address: str
    transport: Literal["dot", "doh"] = "dot"
    port: int = Field(default=853, ge=1, le=65535)
    tls_hostname: str | None = None
    doh_url: str | None = None

    @model_validator(mode="after")
    def _transport_carries_its_authentication(self) -> "DnsResolverConfig":
        """Refuse an entry that could only be used unauthenticated."""
        if self.transport == "dot" and not (self.tls_hostname or "").strip():
            raise ValueError(
                "a 'dot' resolver entry requires tls_hostname, the name its "
                "certificate is verified against"
            )
        if self.transport == "doh":
            url = (self.doh_url or "").strip()
            if not url:
                raise ValueError("a 'doh' resolver entry requires doh_url")
            # Same rule as the DoT branch, stated in the other transport's terms:
            # the queried name is the customer's domain, and `http://` or a
            # scheme-less URL would put it on the wire in clear for anyone on the
            # path. There is no plaintext branch in `dns_utils._nameserver` either,
            # deliberately; this refuses the configuration that would ask for one.
            parts = urlsplit(url)
            if parts.scheme != "https":
                raise ValueError(
                    "a 'doh' resolver entry requires an https:// doh_url; "
                    "cleartext would expose the queried domain in transit"
                )
            # `https:resolver.example/dns-query` parses with the right scheme and
            # no authority at all, so the scheme check alone would admit a URL
            # that has nowhere to send the query. Refusing it at startup beats
            # discovering it when the first customer runs a check.
            if not parts.hostname:
                raise ValueError(
                    "a 'doh' resolver entry requires a host in doh_url "
                    "(https://host/path)"
                )
        return self



class Settings(BaseSettings):
    """Deployment-changeable values, one field per environment variable.

    Field names map to their uppercase environment names
    (``verification_token_ttl_days`` ⇔ ``VERIFICATION_TOKEN_TTL_DAYS``).
    An empty or whitespace variable means the default, matching how the
    pre-consolidation readers behaved.
    """

    model_config = SettingsConfigDict(env_ignore_empty=True)

    @model_validator(mode="before")
    @classmethod
    def _blank_means_unset(cls, data: dict[str, Any]) -> dict[str, Any]:
        """Treat whitespace-only values as unset, like the pre-consolidation readers.

        ``env_ignore_empty`` only covers the truly empty string, and only for
        the environment source; this covers ``"  "`` and file contents too.
        """
        return {
            key: value
            for key, value in data.items()
            if not (isinstance(value, str) and not value.strip())
        }

    # OpenAPI security scheme discovery (core/security.py). The default is a
    # reserved-invalid host so the exported contract never names a real IdP.
    oidc_discovery_url: str = (
        "https://idp.example.invalid/.well-known/openid-configuration"
    )

    # Domain verification and retention (core/config.py). The day caps keep
    # every value well inside timedelta's range, so an absurd setting fails
    # with a readable message rather than an OverflowError.
    verification_token_ttl_days: int = Field(default=7, ge=1, le=36500)
    verification_record_prefix: str = "nc3"
    retention_extension_days: int = Field(default=365, ge=1, le=36500)

    # Challenge anti-abuse (B6a / US #82). Enforced by
    # `domains/assets/dependencies.challenge_rate_limit` on both
    # challenge-writing operations, keyed per (organization, asset).
    #
    # Bounds a cheap operation — one upsert, no network — and bounds it per
    # organization, which bounds one account rather than one attacker:
    # registration is free and instant. The load-bearing global cap belongs with
    # the DNS check (B6b / US #263), where the expensive operation is.
    verification_challenge_rate_limit: int = Field(default=10, ge=1)
    verification_challenge_rate_window_seconds: int = Field(default=300, ge=1)

    # DNS resolution for the verification check (B6b / US #263, IDR-019).
    #
    # There is deliberately **no built-in default**. A self-hoster who inherited
    # one would ship every customer domain they verify to a resolver operator in
    # another jurisdiction without ever choosing to, and the domains are exactly
    # the data Non-functional says must not leak. An empty list therefore means
    # "verification is not configured", and the check refuses `503`.
    #
    # That refusal is at **use** time, not import time: `settings` is built when
    # this module is imported, and both the test suite and `make dev` run with no
    # environment at all, so refusing here would take the whole application down
    # instead of the one unconfigured operation. NC3 configures two operators with
    # two DoT endpoints each (Restena and DNS4EU unfiltered) and quorum 3, so a
    # quorum exceeds any single operator's endpoint count and no one operator can
    # forge a proof alone; see `.env.example`.
    verification_resolvers: list[DnsResolverConfig] = Field(default_factory=list)
    # How many configured resolvers must independently carry the token before an
    # answer without a DNSSEC-validated signature is accepted. 1 disables
    # corroboration, which is the dev and single-resolver case.
    verification_resolver_quorum: int = Field(default=1, ge=1)
    verification_query_timeout_seconds: float = Field(default=5.0, gt=0)
    verification_dns_total_deadline_seconds: float = Field(default=20.0, gt=0)
    # The bulkhead. Admission is a non-blocking semaphore rather than a worker
    # pool: the handler is synchronous, so it already occupies an AnyIO thread,
    # and a queue would turn saturation into latency instead of a refusal.
    verification_dns_max_concurrent_queries: int = Field(default=4, ge=1)
    # Three windows, narrowest last. The global one is the only bound that does
    # not divide by the number of organizations an attacker registers, and
    # registration is free; the per-organization one keeps a single tenant from
    # consuming that whole global budget and denying verification to everyone.
    verification_global_rate_limit: int = Field(default=600, ge=1)
    verification_global_rate_window_seconds: int = Field(default=60, ge=1)
    verification_org_rate_limit: int = Field(default=60, ge=1)
    verification_org_rate_window_seconds: int = Field(default=60, ge=1)
    verification_check_rate_limit: int = Field(default=10, ge=1)
    verification_check_rate_window_seconds: int = Field(default=300, ge=1)

    # Service endpoints (worker/app.py, worker/tasks.py; Redis primitives in
    # core/redis_utils.py once task #157 lands). Defaults match the compose
    # stack's loopback ports so a fresh clone works without a .env.
    database_url: str = (
        "postgresql+psycopg://postgres:postgres@localhost:5432/nc3_testing_platform"
    )
    # The runtime connection (worker/db.py; the API session dependency when B3
    # lands). Which role the credential carries is deployment topology, not
    # code: api and the scan workers get `nc3_app`, worker-platform and beat
    # get `app_platform` (IDR-012; docs/database-roles.md). `database_url`
    # above stays the owning role, for Alembic and `make db-*` only.
    app_database_url: str = (
        "postgresql+psycopg://nc3_app:nc3_app@localhost:5432/nc3_testing_platform"
    )
    # The credential-surface connection (core/api_db.py): the `nc3_auth` role,
    # held by the API service alone so the scan workers sharing `nc3_app`
    # never gain a privilege on the auth tables (docs/database-roles.md,
    # US #79). Same raw-interpolation caveat as `app_database_url`.
    auth_database_url: str = (
        "postgresql+psycopg://nc3_auth:nc3_auth@localhost:5432/nc3_testing_platform"
    )
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "amqp://rabbitmq:rabbitmq@localhost:5672//"

    # Scan execution limits (worker/app.py, US #78 ADR).
    scan_task_timeout_seconds: int = Field(default=120, ge=1)
    celery_max_tasks_per_child: int = Field(default=100, ge=1)

    # Job-level lifecycle sweeps (worker/tasks.py, B8 / US #84). The compose
    # stack has exported these since the queue topology landed; the reaper and
    # heartbeat tasks are their first consumers. `scan_job_timeout_seconds`
    # bounds a whole job (all its tasks), so it sits above the per-task limit;
    # `scan_stale_after_seconds` is how long a job may sit `queued` before the
    # reaper re-publishes it as stranded.
    scan_job_timeout_seconds: int = Field(default=900, ge=1)
    scan_heartbeat_interval_seconds: int = Field(default=5, ge=1)
    scan_stale_after_seconds: int = Field(default=30, ge=1)
    scan_sweep_interval_seconds: int = Field(default=15, ge=1)

    @model_validator(mode="after")
    def _job_timeout_covers_the_task_limit(self) -> "Settings":
        """The reaper must not fire before Celery's hard task limit.

        The hard limit is the task timeout + 30 (worker/app.py); a job
        timeout below that lets the sweep fail a task Celery would still
        have let finish, so the misconfiguration is refused at startup.
        """
        floor = self.scan_task_timeout_seconds + 30
        if self.scan_job_timeout_seconds < floor:
            raise ValueError(
                "SCAN_JOB_TIMEOUT_SECONDS must be at least "
                f"SCAN_TASK_TIMEOUT_SECONDS + 30 ({floor}); got "
                f"{self.scan_job_timeout_seconds}."
            )
        return self

    # The worker process's own egress queue (worker/app.py preflight). Empty
    # everywhere except in a worker container, where compose pins it; preflight
    # rejects a worker that cannot name its queue.
    worker_queue: str = ""

    # Authentication (domains/auth, B3 / US #79). The master key is the
    # deployment secret at the root of the envelope hierarchy (data-model
    # §1.2): 64 hex characters (256 bits), normally supplied as
    # APP_ENCRYPTION_MASTER_KEY_FILE=/run/secrets/app_encryption_master_key
    # and mounted into the api service only. Empty means the operations that
    # need it refuse loudly (core/crypto.py) — never a plaintext fallback.
    # Only the version string is ever stored in PostgreSQL.
    app_encryption_master_key: str = ""
    app_encryption_master_key_version: str = "1"

    # Browser origin allowed to make cookie-bearing state changes
    # (core/csrf.py, IDR-010's origin-validation arm). Empty disables the
    # check, for non-browser and development use.
    auth_public_origin: str = ""

    # Server-side session policy (Non-functional v0.11: idle 30 min,
    # absolute 8 h) and the login lockout + rate limits of the brute-force
    # requirement. Windows and thresholds are per IP for the Redis limits;
    # the lockout is per account and lives on the credential row.
    auth_session_idle_seconds: int = Field(default=1800, ge=60)
    auth_session_absolute_seconds: int = Field(default=28800, ge=300)
    auth_lockout_threshold: int = Field(default=10, ge=1)
    auth_lockout_seconds: int = Field(default=900, ge=60)
    auth_login_rate_limit: int = Field(default=10, ge=1)
    auth_login_rate_window_seconds: int = Field(default=60, ge=1)
    auth_register_rate_limit: int = Field(default=10, ge=1)
    auth_register_rate_window_seconds: int = Field(default=3600, ge=1)

    # MFA policy (B4 / US #80). The verify lockout is deliberately stricter
    # than the password lockout and escalates (doubling per consecutive
    # lockout, capped): a 6-digit TOTP at the login numbers — 10 guesses per
    # 15 minutes forever — would concede ~8.6% compromise odds per targeted
    # account over 30 days.
    auth_totp_issuer: str = "NC3 Testing Platform"
    auth_mfa_assurance_max_age_seconds: int = Field(default=900, ge=60)
    auth_mfa_failed_threshold: int = Field(default=5, ge=1)
    auth_mfa_lockout_base_seconds: int = Field(default=900, ge=60)
    auth_mfa_lockout_cap_seconds: int = Field(default=86400, ge=60)
    auth_mfa_verify_rate_limit: int = Field(default=5, ge=1)
    auth_mfa_verify_rate_window_seconds: int = Field(default=60, ge=1)

    @model_validator(mode="after")
    def _auth_settings_are_coherent(self) -> "Settings":
        """Refuse a key that is not 256-bit hex and an absolute cap under idle.

        The key check runs at startup so a truncated or re-encoded secret
        fails before the first registration, not during it.
        """
        if self.app_encryption_master_key:
            try:
                raw = bytes.fromhex(self.app_encryption_master_key)
            except ValueError:
                raise ValueError(
                    "APP_ENCRYPTION_MASTER_KEY must be hexadecimal."
                ) from None
            if len(raw) != 32:
                raise ValueError(
                    "APP_ENCRYPTION_MASTER_KEY must be 64 hex characters "
                    "(256 bits)."
                )
        if self.auth_session_absolute_seconds < self.auth_session_idle_seconds:
            raise ValueError(
                "AUTH_SESSION_ABSOLUTE_SECONDS must be at least "
                "AUTH_SESSION_IDLE_SECONDS."
            )
        if (
            self.auth_mfa_assurance_max_age_seconds
            > self.auth_session_absolute_seconds
        ):
            raise ValueError(
                "AUTH_MFA_ASSURANCE_MAX_AGE_SECONDS must not exceed "
                "AUTH_SESSION_ABSOLUTE_SECONDS."
            )
        if self.auth_mfa_lockout_cap_seconds < self.auth_mfa_lockout_base_seconds:
            raise ValueError(
                "AUTH_MFA_LOCKOUT_CAP_SECONDS must be at least "
                "AUTH_MFA_LOCKOUT_BASE_SECONDS."
            )
        return self

    @model_validator(mode="after")
    def _verification_dns_settings_are_coherent(self) -> "Settings":
        """Refuse a quorum nothing can satisfy and a bulkhead wider than the pool.

        The quorum check is skipped when no resolver is configured: an empty list
        is a legal "not configured yet" state, refused at use time rather than at
        import (see the field comment).
        """
        resolvers = self.verification_resolvers
        if resolvers and self.verification_resolver_quorum > len(resolvers):
            raise ValueError(
                "VERIFICATION_RESOLVER_QUORUM must not exceed the number of "
                f"configured resolvers ({len(resolvers)})."
            )
        if self.verification_dns_max_concurrent_queries >= _APP_POOL_CEILING:
            raise ValueError(
                "VERIFICATION_DNS_MAX_CONCURRENT_QUERIES must stay below the "
                f"application connection-pool ceiling ({_APP_POOL_CEILING}); a "
                "check that outlives its connection starves every other "
                "operation on the same role."
            )
        if (
            self.verification_dns_total_deadline_seconds
            < self.verification_query_timeout_seconds
        ):
            raise ValueError(
                "VERIFICATION_DNS_TOTAL_DEADLINE_SECONDS must be at least "
                "VERIFICATION_QUERY_TIMEOUT_SECONDS."
            )
        # `resolve_txt` queries resolvers one after another under the single total
        # budget and reports the ones it never reached as NOT_ATTEMPTED. A deadline
        # that cannot fit `quorum` worst-case queries therefore makes corroboration
        # unsatisfiable exactly when resolvers are slow, which is when corroboration
        # matters — and the deployment would not find out until a check failed. Same
        # defect class as a quorum larger than the resolver list, refused above.
        needed = (
            self.verification_resolver_quorum * self.verification_query_timeout_seconds
        )
        if resolvers and self.verification_dns_total_deadline_seconds < needed:
            raise ValueError(
                "VERIFICATION_DNS_TOTAL_DEADLINE_SECONDS must cover "
                "VERIFICATION_RESOLVER_QUORUM worst-case queries "
                f"({needed}); resolvers are queried sequentially."
            )
        return self

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Init kwargs, then ``NAME_FILE`` indirection, then the environment.

        No dotenv source: the environment is the only channel (12-factor).
        ``make dev`` and Compose both load `.env` into the environment
        themselves, so honouring the file here would read it twice.
        """
        return init_settings, _FileIndirectionSource(settings_cls), env_settings


def load_settings() -> Settings:
    """Build a :class:`Settings`, translating validation failures to one readable error.

    :raises RuntimeError: naming each offending variable and what it should be.
    """
    try:
        return Settings()
    except ValidationError as exc:
        problems = "; ".join(
            f"{'_'.join(str(loc) for loc in error['loc']).upper()}: "
            f"{error['msg']} (got {error.get('input')!r})"
            for error in exc.errors()
        )
        raise RuntimeError(f"Invalid environment configuration — {problems}.") from None


settings = load_settings()
