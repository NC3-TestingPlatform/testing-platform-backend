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


# --- DNS resolver configuration (B6b / US #263) -----------------------------
#
# The resolver list is the platform's first structured setting, so these pin
# both its validation and the one convention it cannot honour.

_DNSPUB_ENTRY = (
    '{"address":"158.64.1.29","transport":"dot","port":853,'
    '"tls_hostname":"dnspub.restena.lu"}'
)
_DNS4EU_ENTRY = (
    '{"address":"86.54.11.100","transport":"dot","port":853,'
    '"tls_hostname":"unfiltered.joindns4.eu"}'
)
_DNSPUB = f"[{_DNSPUB_ENTRY}]"


def test_no_resolver_is_configured_by_default(clean_env: pytest.MonkeyPatch) -> None:
    """An empty list is legal at import: refusing here would kill the whole API.

    `settings` is built when the module is imported, and both the test suite and
    `make dev` run with no environment, so an unconfigured deployment must lose
    the one operation that needs a resolver rather than failing to start.
    """
    loaded = load_settings()
    assert loaded.verification_resolvers == []
    assert loaded.verification_resolver_quorum == 1


def test_resolvers_parse_from_the_environment(clean_env: pytest.MonkeyPatch) -> None:
    """The JSON list reaches the typed model with its transport intact."""
    clean_env.setenv("VERIFICATION_RESOLVERS", _DNSPUB)
    resolver = load_settings().verification_resolvers[0]
    assert (resolver.address, resolver.port) == ("158.64.1.29", 853)
    assert resolver.transport == "dot"
    assert resolver.tls_hostname == "dnspub.restena.lu"


def test_a_dot_resolver_without_its_hostname_refuses_to_start(
    clean_env: pytest.MonkeyPatch,
) -> None:
    """DoT without a verified hostname is encryption with the attacker still there."""
    clean_env.setenv(
        "VERIFICATION_RESOLVERS", '[{"address":"158.64.1.29","transport":"dot"}]'
    )
    with pytest.raises(RuntimeError, match="tls_hostname"):
        load_settings()


def test_a_doh_resolver_without_its_url_refuses_to_start(
    clean_env: pytest.MonkeyPatch,
) -> None:
    """A DoH entry with no URL has no endpoint to authenticate against."""
    clean_env.setenv(
        "VERIFICATION_RESOLVERS",
        '[{"address":"185.194.94.71","transport":"doh","port":443}]',
    )
    with pytest.raises(RuntimeError, match="doh_url"):
        load_settings()


def test_a_doh_resolver_over_cleartext_refuses_to_start(
    clean_env: pytest.MonkeyPatch,
) -> None:
    """`http://` would put the customer's domain on the wire in clear."""
    clean_env.setenv(
        "VERIFICATION_RESOLVERS",
        '[{"address":"185.194.94.71","transport":"doh","port":443,'
        '"doh_url":"http://resolver.example/dns-query"}]',
    )
    with pytest.raises(RuntimeError, match="https"):
        load_settings()


def test_a_doh_url_without_a_scheme_refuses_to_start(
    clean_env: pytest.MonkeyPatch,
) -> None:
    """A scheme-less URL is not an https URL, however much it looks like one."""
    clean_env.setenv(
        "VERIFICATION_RESOLVERS",
        '[{"address":"185.194.94.71","transport":"doh","port":443,'
        '"doh_url":"resolver.example/dns-query"}]',
    )
    with pytest.raises(RuntimeError, match="https"):
        load_settings()


def test_a_doh_url_without_a_host_refuses_to_start(
    clean_env: pytest.MonkeyPatch,
) -> None:
    """`https:` with no authority has the right scheme and nowhere to send the query."""
    clean_env.setenv(
        "VERIFICATION_RESOLVERS",
        '[{"address":"185.194.94.71","transport":"doh","port":443,'
        '"doh_url":"https:resolver.example/dns-query"}]',
    )
    with pytest.raises(RuntimeError, match="host in doh_url"):
        load_settings()


def test_a_deadline_too_short_for_the_quorum_refuses_to_start(
    clean_env: pytest.MonkeyPatch,
) -> None:
    """Resolvers are queried sequentially, so a quorum needs quorum-many budgets.

    Otherwise corroboration is unsatisfiable exactly when resolvers are slow,
    which is when corroboration is the point, and nothing says so until a check
    fails in production.
    """
    clean_env.setenv("VERIFICATION_RESOLVERS", f"[{_DNSPUB_ENTRY},{_DNS4EU_ENTRY}]")
    clean_env.setenv("VERIFICATION_RESOLVER_QUORUM", "2")
    clean_env.setenv("VERIFICATION_QUERY_TIMEOUT_SECONDS", "5.0")
    clean_env.setenv("VERIFICATION_DNS_TOTAL_DEADLINE_SECONDS", "6.0")
    with pytest.raises(RuntimeError, match="VERIFICATION_DNS_TOTAL_DEADLINE_SECONDS"):
        load_settings()


def test_a_deadline_that_covers_the_quorum_starts(
    clean_env: pytest.MonkeyPatch,
) -> None:
    """The guard bounds the worst case; it must not refuse the shape NC3 runs."""
    clean_env.setenv("VERIFICATION_RESOLVERS", f"[{_DNSPUB_ENTRY},{_DNS4EU_ENTRY}]")
    clean_env.setenv("VERIFICATION_RESOLVER_QUORUM", "2")
    clean_env.setenv("VERIFICATION_QUERY_TIMEOUT_SECONDS", "5.0")
    clean_env.setenv("VERIFICATION_DNS_TOTAL_DEADLINE_SECONDS", "20.0")
    assert load_settings().verification_dns_total_deadline_seconds == 20.0


def test_a_quorum_no_configuration_can_satisfy_refuses_to_start(
    clean_env: pytest.MonkeyPatch,
) -> None:
    """Corroboration across two resolvers cannot be met by one."""
    clean_env.setenv("VERIFICATION_RESOLVERS", _DNSPUB)
    clean_env.setenv("VERIFICATION_RESOLVER_QUORUM", "2")
    with pytest.raises(RuntimeError, match="VERIFICATION_RESOLVER_QUORUM"):
        load_settings()


def test_a_bulkhead_wider_than_the_connection_pool_refuses_to_start(
    clean_env: pytest.MonkeyPatch,
) -> None:
    """A check that outlives its connection starves the whole `nc3_app` role.

    `core/api_db` builds the engine on SQLAlchemy's defaults, so the ceiling is
    `pool_size=5` plus `max_overflow=10`.
    """
    clean_env.setenv("VERIFICATION_DNS_MAX_CONCURRENT_QUERIES", "15")
    with pytest.raises(RuntimeError, match="connection-pool ceiling"):
        load_settings()


def test_a_total_deadline_under_one_query_refuses_to_start(
    clean_env: pytest.MonkeyPatch,
) -> None:
    """A budget that cannot fit one query would fail every check on the deadline."""
    clean_env.setenv("VERIFICATION_QUERY_TIMEOUT_SECONDS", "10")
    clean_env.setenv("VERIFICATION_DNS_TOTAL_DEADLINE_SECONDS", "5")
    with pytest.raises(RuntimeError, match="VERIFICATION_DNS_TOTAL_DEADLINE_SECONDS"):
        load_settings()


def test_the_resolver_list_is_environment_only(
    clean_env: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`VERIFICATION_RESOLVERS_FILE` does not work, and that is pinned deliberately.

    `_FileIndirectionSource` reports every field as non-complex and passes the
    file's text through unchanged, so a JSON list arrives as a string and fails
    validation. Every scalar variable still honours `_FILE`; this one cannot, and
    a silent half-working indirection would be worse than a refusal.
    """
    pointer = tmp_path / "resolvers.json"
    pointer.write_text(_DNSPUB, encoding="utf-8")
    clean_env.setenv("VERIFICATION_RESOLVERS_FILE", str(pointer))
    with pytest.raises(RuntimeError, match="VERIFICATION_RESOLVERS"):
        load_settings()
