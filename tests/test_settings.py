"""The settings module is the application's sole environment boundary.

Fresh :class:`Settings` instances are built against a scrubbed environment;
the module-level singleton is import-time state shared with the rest of the
suite and stays untouched. The shim tests pin the re-exported names in
`core/config.py` / `core/security.py` / `worker/app.py` to the singleton, so
the compatibility layer cannot drift from the values it mirrors.
"""

from datetime import timedelta
from pathlib import Path

import pytest

from nc3_testing_platform.core import config, security
from nc3_testing_platform.core.settings import Settings, load_settings, settings
from nc3_testing_platform.worker.app import app as celery_app

_ENV_NAMES = tuple(name.upper() for name in Settings.model_fields)


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """Scrub every settings variable (and its `_FILE` pointer) from the environment."""
    for name in _ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(f"{name}_FILE", raising=False)
    return monkeypatch


def test_defaults_load_from_an_empty_environment(clean_env: pytest.MonkeyPatch) -> None:
    """A fresh clone with no environment gets the documented defaults."""
    loaded = load_settings()
    assert loaded.verification_token_ttl_days == 7
    assert loaded.verification_record_prefix == "nc3"
    assert loaded.retention_extension_days == 365
    assert loaded.scan_task_timeout_seconds == 120
    assert loaded.celery_max_tasks_per_child == 100
    assert loaded.worker_queue == ""
    assert loaded.oidc_discovery_url.startswith("https://idp.example.invalid/")


def test_empty_value_means_default(clean_env: pytest.MonkeyPatch) -> None:
    """An empty or whitespace variable behaves as if unset, like the old readers."""
    clean_env.setenv("VERIFICATION_TOKEN_TTL_DAYS", "")
    clean_env.setenv("RETENTION_EXTENSION_DAYS", "  ")
    loaded = load_settings()
    assert loaded.verification_token_ttl_days == 7
    assert loaded.retention_extension_days == 365


def test_non_integer_value_refuses_to_start(clean_env: pytest.MonkeyPatch) -> None:
    """A value that cannot parse fails with an error naming the variable."""
    clean_env.setenv("VERIFICATION_TOKEN_TTL_DAYS", "zebra")
    with pytest.raises(RuntimeError, match="VERIFICATION_TOKEN_TTL_DAYS"):
        load_settings()


def test_out_of_bounds_value_refuses_to_start(clean_env: pytest.MonkeyPatch) -> None:
    """A parseable but absurd value fails the bound, not a later OverflowError."""
    clean_env.setenv("RETENTION_EXTENSION_DAYS", "0")
    with pytest.raises(RuntimeError, match="RETENTION_EXTENSION_DAYS"):
        load_settings()


def test_job_timeout_below_the_task_hard_limit_refuses_to_start(
    clean_env: pytest.MonkeyPatch,
) -> None:
    """The reaper must not fire before Celery's hard task limit (timeout + 30)."""
    clean_env.setenv("SCAN_JOB_TIMEOUT_SECONDS", "60")
    with pytest.raises(RuntimeError, match="SCAN_JOB_TIMEOUT_SECONDS"):
        load_settings()
    clean_env.setenv("SCAN_JOB_TIMEOUT_SECONDS", "150")
    assert load_settings().scan_job_timeout_seconds == 150


def test_file_indirection_supplies_the_value(
    clean_env: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`NAME_FILE` reads the value from the file, stripping trailing whitespace."""
    secret = tmp_path / "oidc_url"
    secret.write_text("https://idp.internal/.well-known/openid-configuration\n")
    clean_env.setenv("OIDC_DISCOVERY_URL_FILE", str(secret))
    loaded = load_settings()
    assert (
        loaded.oidc_discovery_url
        == "https://idp.internal/.well-known/openid-configuration"
    )


def test_file_indirection_wins_over_plain_env(
    clean_env: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A mounted secret must not lose to a stale plain variable."""
    secret = tmp_path / "prefix"
    secret.write_text("fromfile")
    clean_env.setenv("VERIFICATION_RECORD_PREFIX", "fromenv")
    clean_env.setenv("VERIFICATION_RECORD_PREFIX_FILE", str(secret))
    assert load_settings().verification_record_prefix == "fromfile"


def test_file_indirection_validates_like_plain_env(
    clean_env: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A file-provided value passes through the same parsing and bounds."""
    bad = tmp_path / "days"
    bad.write_text("not-a-number")
    clean_env.setenv("VERIFICATION_TOKEN_TTL_DAYS_FILE", str(bad))
    with pytest.raises(RuntimeError, match="VERIFICATION_TOKEN_TTL_DAYS"):
        load_settings()


def test_unreadable_file_pointer_refuses_to_start(
    clean_env: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A pointer at a missing file fails naming the pointer variable."""
    clean_env.setenv("REDIS_URL_FILE", str(tmp_path / "does-not-exist"))
    with pytest.raises(RuntimeError, match="REDIS_URL_FILE"):
        load_settings()


def test_config_shims_follow_settings() -> None:
    """The re-exported config names equal what the singleton holds."""
    assert config.VERIFICATION_TOKEN_TTL == timedelta(
        days=settings.verification_token_ttl_days
    )
    assert config.VERIFICATION_RECORD_PREFIX == settings.verification_record_prefix
    assert config.RETENTION_EXTENSION == timedelta(
        days=settings.retention_extension_days
    )


def test_security_shim_follows_settings() -> None:
    """The OIDC discovery URL published into the contract comes from settings."""
    assert security.OIDC_DISCOVERY_URL == settings.oidc_discovery_url


def test_worker_limits_follow_settings() -> None:
    """The Celery limits are the settings values, gap preserved (US #78 ADR)."""
    assert celery_app.conf.task_soft_time_limit == settings.scan_task_timeout_seconds
    assert celery_app.conf.task_time_limit == settings.scan_task_timeout_seconds + 30
    assert (
        celery_app.conf.worker_max_tasks_per_child
        == settings.celery_max_tasks_per_child
    )
