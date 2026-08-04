"""Business logic for scan execution.

Owns the launch sequence, the gates that run before a ScanJob exists, and the
transaction boundary around creation.
Handlers in `router.py` translate the results into responses; queries live in
`repository.py`.

Nothing here is implemented yet.
"""

# TODO: launch_domain_scan(...) following the six-step order in
#   docs/architecture/scan-launch-and-upload-handling.md §1. The identifier is
#   generated first so declarations can bind to it, and tasks are enqueued only
#   after the creating transaction commits.
# TODO: launch_file_scan(...) creating the upload, job, and initial tasks in one
#   step, after raw-byte MIME validation.
# TODO: evaluate_launch_gates(...) covering authorization, verification, current
#   MFA assurance, rate and cooldown, and required declarations.
# TODO: claim_guest_scan(...) transferring ownership of the job and, for a file
#   scan, of the upload record. Every failure answers 404 (api-design §2.3).
# TODO: request_cancellation(...) recording durable intent, per data-model §7.2.
# TODO: recompute_purge_at(...) on terminal completion and on successful claim,
#   per api-design §11.
