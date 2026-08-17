"""Version pins and the stable check-id vocabulary for the PQC module.

Kept in one place so a change to the result shape or a rule identity is a
visible, reviewable edit — `schema_version` is stored on every `scan_result`
row and `check_id`s are the anchors regression matching keys on, so neither
moves casually.
"""

# The engine this module wraps, and the tag it is pinned to in the `modules`
# optional-dependency extra. Bump both together with the dependency pin.
ENGINE = "quantumvalidator"
ENGINE_VERSION = "0.7.0"

# The module's result schema. Bump when `raw_output`'s shape or the check-id
# vocabulary below changes meaning — not when the engine version changes.
SCHEMA_VERSION = "pqc/1.0"

# The executable test this module implements (catalog key `pqc.quantumvalidator`).
TEST_KEY = "pqc.quantumvalidator"
TEST_VERSION = "1.0.0"

# Stable check ids. The readiness id carries the overall verdict; per-check
# findings carry the engine's check name as a suffix (`pqc.check.key_exchange`,
# `pqc.check.kex_algorithm`, …) so a new engine check is a new rule identity
# without a module edit.
CHECK_READINESS = "pqc.readiness"
CHECK_PREFIX = "pqc.check"
