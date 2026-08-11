"""Version pins and the stable check-id vocabulary for the DNSSEC module.

Kept in one place so a change to the result shape or a rule identity is a
visible, reviewable edit — `schema_version` is stored on every `scan_result`
row and `check_id`s are the anchors regression matching keys on, so neither
moves casually.
"""

# The engine this module wraps, and the tag it is pinned to in the `modules`
# optional-dependency extra. Bump both together with the dependency pin.
ENGINE = "chainvalidator"
ENGINE_VERSION = "0.1.6"

# The module's result schema. Bump when `raw_output`'s shape or the check-id
# vocabulary below changes meaning — not when the engine version changes.
SCHEMA_VERSION = "dnssec/1.0"

# The executable test this module implements (catalog key `dnssec.chainvalidator`).
TEST_KEY = "dnssec.chainvalidator"
TEST_VERSION = "1.0.0"

# Stable check ids. The delegation and leaf ids carry the engine's status as a
# suffix — one rule per outcome — and pair with `affected_resource` (the zone
# or queried name) when a scan raises several.
CHECK_CHAIN = "dnssec.chain_of_trust"
CHECK_DELEGATION = "dnssec.delegation"
CHECK_LEAF = "dnssec.leaf"
