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
from typing import Any

from pydantic import Field, ValidationError, model_validator
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
