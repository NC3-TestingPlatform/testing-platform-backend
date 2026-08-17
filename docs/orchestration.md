# Scan orchestration (B8 / US #84)

How a committed `scan_job` becomes tasks, results, and a terminal state.
Decision sources: IDR-004 (+ 2026-07-28 amendment), the *Runtime & lifecycle
views* scan-job state diagram and all-in-one activity flow, the
egress-segregated task queues ADR, the Datastore-split ADR, and data-model
`docs/reference/data-model-v4_0_2.md` §7–§8.

## The pipeline

```text
launch (API)                 platform queue                  module queue
────────────                 ──────────────                  ────────────
commit scan_job row ───────► scan.dispatch(job_id)
                             ├─ build task matrix            scan.run_module(task_id)
                             │  (catalog × requested         ├─ roster gate (require)
                             │   modules; blocked rows       ├─ queued → running
                             │   for uninstalled ones)       ├─ engine in killable child
                             ├─ job queued → running         │  (wall-clock budget)
                             └─ send one run_module per ───► ├─ persist result + findings
                                task, queue from the         ├─ task → terminal
                                module's declaration         └─ finalize job if all
                                                                children terminal
```

- **Task creation is worker-side.** The launch commits only the `scan_job`
  row, then calls `scan.dispatch(job_id)` *after* the transaction commits.
  Dispatch materializes the matrix: one `scan_task` per catalog test
  (`modules/catalog.py`, data-model §7.3) of each requested module. A catalog
  test with no installed module becomes a **blocked** task
  (`task.module_unavailable`) — visible, not silently absent. The reference
  module `web.noop` is on the roster but not in the catalog, so it is never
  scheduled by a real launch (the compose smoke schedules it explicitly via
  `tools/seed_scan.py`).
- **Routing** is read from the module's declaration at send time
  (`Roster.queue_for`); a worker refuses a task whose module declares a
  different queue (`task.misrouted`, egress ADR). `scan_task.id` is the queue
  task id (§7.2) — cancellation revokes by it.
- **Completion is counted, not chorded.** Each child commits its own terminal
  state; `finalize_job_if_done` locks the job row (`SELECT … FOR UPDATE`),
  counts terminal children, and closes the job at-most-once. No Celery chord,
  no result-backend coordination.

## Lifecycle and reasons

Job: `queued → running → completed | partial | failed | canceled`.
Task: adds `skipped` and `blocked` (`blocked` always carries a reason).

Timeout is a **reason, never a status**:

| Event | Task outcome | Job outcome |
|---|---|---|
| Engine overruns its wall-clock budget | `failed` + `task.timeout` | `partial` if sibling results exist, else `failed` |
| Job overruns `SCAN_JOB_TIMEOUT_SECONDS` | live tasks `failed` + `job.timeout` | `partial` / `failed` + `job.timeout` |
| Module not installed | `blocked` + `task.module_unavailable` | counts as unusable |
| Cancellation honored | `canceled` + `task.canceled` | `canceled` + `job.canceled` (when nothing usable) |

Per-engine timeouts are enforced by the **subprocess timeout + kill** of the
shared runner (`modules/execution.py`, IDR-004 amendment); Celery
`task_time_limit`/`soft_time_limit` are a prefork-only backstop. The
`derive_job_outcome` rule: all completed → `completed`; some completed →
`partial` (`job.tasks_incomplete` unless overridden); none completed →
`canceled` if anything was canceled, else `failed` (`job.no_usable_results`).

On terminal completion `purge_at` is set to `finished_at` + 12 months +
30 days (§7.1) unless a deadline already stands (unclaimed guest: 24 h from
creation, set at launch).

## Cancellation

`cancellation_requested_at` on the task row is the durable intent (§7.2).
Workers honor it at the safe points: before starting a task and again before
writing the result — a task closed mid-run never gains a result, and a late
success is dropped, not recorded. Job-level cancellation (the API's
`POST /scans/{id}/cancel`) is expected to stamp the intent on every
non-terminal task and revoke by task id; that endpoint's implementation is
the launch story's.

## The reaper and the heartbeat (beat, platform queue)

Every `SCAN_SWEEP_INTERVAL_SECONDS`, `scan.reap`:

1. re-publishes jobs stuck `queued` longer than `SCAN_STALE_AFTER_SECONDS`
   (stranded publish — dispatch is idempotent: existing matrices are never
   recreated, only still-queued tasks re-sent);
2. fails jobs stuck `running` past `SCAN_JOB_TIMEOUT_SECONDS`: live tasks →
   `failed` + `job.timeout`, queued deliveries revoked best-effort, job
   closed through the same finalize path.

Every `SCAN_HEARTBEAT_INTERVAL_SECONDS`, `scan.heartbeat` publishes one
heartbeat per running job. Beat runs with exactly one replica
(`infra/compose/celery.yml`).

## Event channel — the B13 seam

Everything publishes to Redis pub/sub **after** the PostgreSQL commit it
describes (Datastore-split ADR: database state is authoritative; events only
reduce latency).

- Channel: `scan:events:{scan_job_id}`
- Message: `{"event": "<task|job|heartbeat|end>", "data": {…}}` where `data`
  is exactly the matching SSE schema of `domains/scans/schemas.py`
  (`ScanTaskEvent`, `ScanJobEvent`, `ScanHeartbeatEvent`, `ScanEndEvent`).
- A terminal `job` message is immediately followed by `end` on the same
  channel; nothing follows `end`.
- B13's SSE endpoint subscribes and relays one message to one
  `event:`/`data:` pair. Missed events are recovered by refetching the
  snapshot, never replayed. Engine progress lines (`ProgressEmitter`) go to
  the worker log only — the SSE contract has no fine-grained progress event.

## Seams owned elsewhere

| Seam | Owner |
|---|---|
| Engine packages in worker images + preflight entries (chainvalidator landed with M11 / US #102 as the exemplar; the rest of the roll-out) | B1 |
| RLS revalidation of worker writes (`APP_DATABASE_URL`, `SET LOCAL`) | B5 / US #81 |
| `finding.status` derived from history — until then every finding is written `new` through `orchestration.derive_finding_status()` | B12a / US #87 |
| SSE delivery of the event channel | B13 |
| Launch gates, claim, job-level cancel endpoint | launch story |
| Guest quotas and rate limits | B10 |

No v4.0 module populates `ModuleResult.grade`; the column passes through as
`NULL` until the grading M-stories land.

## Live engine verification (dnssec)

CI's compose smoke deliberately stays on `web.noop` — deterministic, zero
egress — so a required check can never flake on someone else's DNS. Verifying
a provisioned engine against live DNS is always a manual, local step:

```bash
make up && make migrate
job_id=$(make scan DOMAIN=nc3.lu MODULE=dnssec | tail -n1)

docker compose exec -T postgres psql -U postgres -d nc3_testing_platform \
  -c "select status, status_reason from scan_task where scan_job_id = '${job_id}';" \
  -c "select f.check_id, f.severity, f.title from finding f
      join scan_result r on f.scan_result_id = r.id
      join scan_task t on r.scan_task_id = t.id where t.scan_job_id = '${job_id}';"
```

Expected: the task ends `completed` with `status_reason` NULL — specifically
**not** `task.engine_error`, which is what an image missing the engine
produces — and at least the `dnssec.chain_of_trust` finding is persisted.
Against a deliberately broken zone (any of the well-known dnssec-failed test
domains), the task still ends `completed` with `dnssec.delegation.bogus` /
HIGH findings: a bogus chain is a *finding*, not an engine failure.

`MODULE=<scan_module>` makes the seed commit the job alone and lets
`scan.dispatch` build the matrix from the §7.3 catalog — the production
shape. Without `MODULE`, the seed keeps its pre-created `web.noop` task (the
noop is roster-only, off-catalog). The engine runs under the runner's
wall-clock budget: 60 s by default, raisable to at most 120 s via the launch
options' `budget` key. A wrong image build surfaces before any scan:
`worker/preflight.py` checks each engine distribution and its exact version
at worker start (`make logs`).

The same procedure verifies the PQC module: `make scan DOMAIN=cloudflare.com
MODULE=pqc` (expect `pqc.readiness` INFO with `negotiated_group:
X25519MLKEM768`), and a classical-only host yields `pqc.readiness` +
`pqc.check.key_exchange`, both MEDIUM. Its budget clamp is 30 s default /
60 s max, and the launch options' `port` key points the probe at another
service (the engine fingerprints STARTTLS and SSH from the banner).
