"""Domain-verification and retention values, projected from the settings module.

The names here predate `core/settings.py` and stay because routers and tests
import them; the environment parsing and bounds now live on
:class:`~nc3_testing_platform.core.settings.Settings`.
"""

from datetime import timedelta

from nc3_testing_platform.core.settings import settings

# How long a domain-verification challenge stays answerable; a verification that already succeeded is unaffected.
# Seven days: long enough for a DNS change to clear a ticketing process, short enough that an abandoned challenge does not sit open forever.
VERIFICATION_TOKEN_TTL = timedelta(days=settings.verification_token_ttl_days)

# Vendor prefix in the DNS challenge record name, giving `_<prefix>-verify.<domain>`.
# A generic name like `_verify` would collide when a domain owner verifies with two providers that both chose it.
# Set before issuing the first challenge: a later change breaks every challenge in flight and every record already-verified domains have published.
VERIFICATION_RECORD_PREFIX = settings.verification_record_prefix

# How far one retention extension moves a scan's `purge_at`.
# Data-protection policy varies by jurisdiction, so it stays out of the contract.
RETENTION_EXTENSION = timedelta(days=settings.retention_extension_days)


def verification_record_name(domain: str) -> str:
    """The DNS name at which a domain's challenge token must be published."""
    return f"_{VERIFICATION_RECORD_PREFIX}-verify.{domain}"
