"""SQLAlchemy models for scan execution.

Tables owned by this domain are specified in `docs/reference/data-model-v4_0_1.md`:
`scan_job` (§7.1), `scan_task` (§7.2), and `scan_result` (§8.1).

Nothing here is implemented yet.
SQLAlchemy is not a project dependency, and no migration tooling is configured.
"""

# TODO: declare ScanJob per data-model §7.1, including the exactly-one-target
#   constraint over asset_id, target_domain, and file_upload_id.
# TODO: declare ScanTask per data-model §7.2. Test key, version, and
#   classification are copied at creation and immutable thereafter.
# TODO: declare ScanResult per data-model §8.1, at most one per task.
# TODO: decide where the declarative base lives once a second domain needs it.