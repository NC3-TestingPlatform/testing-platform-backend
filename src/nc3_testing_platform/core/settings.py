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

    # The worker process's own egress queue (worker/app.py preflight). Empty
    # everywhere except in a worker container, where compose pins it; preflight
    # rejects a worker that cannot name its queue.
    worker_queue: str = ""

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
