"""Values that a deployment can change without a code change."""

import os
from datetime import timedelta

# How long a domain-verification challenge stays answerable; a verification that already succeeded is unaffected.
# Seven days: long enough for a DNS change to clear a ticketing process, short enough that an abandoned challenge does not sit open forever.
VERIFICATION_TOKEN_TTL = timedelta(
    days=int(os.getenv("VERIFICATION_TOKEN_TTL_DAYS", "7"))
)

# Vendor prefix in the DNS challenge record name, giving `_<prefix>-verify.<domain>`.
# A generic name like `_verify` would collide when a domain owner verifies with two providers that both chose it.
# Set before issuing the first challenge: a later change breaks every challenge in flight and every record already-verified domains have published.
VERIFICATION_RECORD_PREFIX = os.getenv("VERIFICATION_RECORD_PREFIX", "nc3")

# How far one retention extension moves a scan's `purge_at`.
# Data-protection policy varies by jurisdiction, so it stays out of the contract.
RETENTION_EXTENSION = timedelta(days=int(os.getenv("RETENTION_EXTENSION_DAYS", "365")))


def verification_record_name(domain: str) -> str:
    """The DNS name at which a domain's challenge token must be published."""
    return f"_{VERIFICATION_RECORD_PREFIX}-verify.{domain}"
