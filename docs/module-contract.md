# The scan-module contract

A scan module is a plug-in that wraps one testing engine and implements the
contract in `src/nc3_testing_platform/modules/contract.py`. The contract
exists so the five module stories (Email, Web, File, PQC, DNSSEC) can be
built in parallel, by different people, **without touching core code**
(IDR-007): a module is discovered through an entry point, declares
everything the platform needs to route and describe it, runs its engine
through the shared child-process runner in `modules/execution.py`, and
communicates only through the dataclasses defined here.

The reference implementation is `modules/noop/` — a complete module whose
"engine" does nothing, end to end through the real execution path. Start by
reading it; it is shorter than this document.

## The six surfaces

| # | Surface | Where | Task |
|---|---|---|---|
| 1 | Registration & discovery | entry-point group + `registry.py` | #168 |
| 2 | Egress-queue declaration | `ModuleDescriptor.queue` | #169 |
| 3 | Input contract | `ScanInput` | #170 |
| 4 | Normalized output & severity hook | `NormalizedFinding`, `ModuleResult`, `map_severity` | #171 |
| 5 | Progress protocol | `ProgressEmitter` / `ProgressEvent` | #172 |
| 6 | Report contribution | `ReportContribution` protocol | #173 |

The execution model that ties them together lives in `execution.py` and is
described after the input contract.

## 1. Registration and discovery

A module registers one object implementing the `TestModule` protocol under
the `nc3_testing_platform.modules` entry-point group:

```toml
[project.entry-points."nc3_testing_platform.modules"]
dnssec = "nc3_testing_platform.modules.dnssec:MODULE"
```

`registry.discover()` loads the whole group, validates it, and returns the
`Roster` the platform works from. Discovery is the **only** path from
platform to module: nothing in `core/`, `domains/`, or `worker/` imports
`nc3_testing_platform.modules.*` by name, and
`tests/test_module_contract.py` fails the build if anything starts to.
Modules import the platform (enums, the contract), never the reverse.

Roster validation is loud and total, like `worker/preflight.py`: a broken
entry point, an object missing a protocol member, or two entries claiming
one `test_key` abort discovery entirely. A silently thinner roster would
produce scans that look complete and are not.

### The descriptor

Every module carries a frozen `ModuleDescriptor`:

| Field | Meaning | Constraint |
|---|---|---|
| `name` | `ScanModule` value (the five v4.0 modules) | enum-typed |
| `classification` | `ScanClassification` of its tests | enum-typed; File modules use `not_applicable` |
| `queue` | egress queue it runs on | must match the classification (below) |
| `engine`, `engine_version` | the wrapped engine package and its pinned version | non-empty |
| `tests` | the executable tests it implements | ≥ 1 `TestDeclaration(test_key, test_version)` |

`test_key` is namespaced text (`dnssec.chainvalidator`, `web.headers`), not
an enum — the vocabulary extends without a migration. It must carry its
module's namespace as prefix, and it is the key the whole runtime uses: the
`scan_task` row stores it, the roster resolves implementations by it, and
enqueue-time routing reads the declaration it points to.

## 2. Egress-queue declaration

The egress-segregated-task-queues ADR draws one line: **a module declares
its queue; it never chooses one at runtime.** The declaration is
`ModuleDescriptor.queue`; everything that acts on it lives platform-side:

- the API routes a task at enqueue time via `Roster.queue_for(test_key)`;
- a worker refuses a mis-routed task via `Roster.require(test_key, queue=…)`;
- worker startup validates its own image via `worker/preflight.py`.

The queue is implied by the classification, and the descriptor refuses a
mismatch:

| `classification` | queue |
|---|---|
| `non_intrusive` | `non-intrusive-scan` |
| `intrusive` | `intrusive-scan` |
| `not_applicable` (File) | `file-analysis` |

The names are the ones `worker/app.py` routes and `worker/preflight.py`
validates; a drift test keeps `contract.QUEUE_BY_CLASSIFICATION` identical
to them. `platform` is not a module queue — orchestration tasks live there,
modules never do.

## 3. Input contract

A module receives one frozen `ScanInput` per task:

| Field | Meaning |
|---|---|
| `target_domain` \| `file_path` | exactly one is set (mirrors the `one_task_target` row rule) |
| `options` | the task's `configuration` JSONB, verbatim |
| `timeout` | float seconds, > 0 — the engine's own per-probe timeout |

The launch contract's target union (`asset_id | target_domain |
file_upload_id`) is resolved **before** the input is built: core turns an
asset id into its domain and a file upload into a local path the worker has
fetched. A module never touches the database or object storage.

Each module documents the `options` keys it honors and ignores the rest;
an unusable *value* (not an unknown key) and a missing-but-required target
kind raise `ValueError`, which the platform maps to a failed task with the
message as `status_reason`.

## Execution model — the shared runner

Engines run in a **killable child process**, one per engine call, through
`execution.run_engine` (egress-queues ADR; Docmost decisions override the
older Taiga "in-process" text). The child **imports the engine and calls
`assess()`** — import-as-library, no CLI shelling — so reports stay
structured; the parent enforces a wall-clock **budget** and terminates,
then kills, a child that overruns it.

```python
outcome = run_engine(
    "chainvalidator.assessor:assess",          # resolved in the child
    args=(scan_input.target_domain,),
    kwargs={"timeout": scan_input.timeout},    # engine per-probe timeout
    budget=120.0,                              # wall-clock bound, parent-enforced
    progress=progress,
)
report = outcome.unwrap()                      # a plain dict, or RuntimeError
```

Marshalling rules, enforced structurally (everything crosses the pipe as
JSON text):

- the report crosses as its `dataclasses.asdict()` dict — **never** a
  pickled engine object, so the parent needs nothing from the engine
  package to receive a result;
- progress lines cross per call, tagged with their channel;
- child-side exceptions cross as `"Type: message"` text in
  `EngineOutcome.error`; a budget kill sets `EngineOutcome.timed_out`.

Two timeouts, two owners: `ScanInput.timeout` is the engine's own
per-probe network timeout, passed through inside `kwargs` (task #170);
`budget` is the platform's engine bound, chosen by the module runner. The
child comes from a `spawn` context — a fresh interpreter, not a fork of
the worker — so the runner behaves identically under both pools IDR-004
assigns (gevent for the scan queues, prefork for file-analysis). Do not
lean on Celery time limits for engine bounds; they are a backstop only.

## 4. Normalized output and the severity hook

`run()` returns a frozen `ModuleResult`, shaped like the `scan_result` row:

- `schema_version` — the **module's result schema**, not the engine
  version. Bump it when `raw_output` changes shape or the `check_id`
  vocabulary changes meaning; the stored rows carry it so consumers can
  interpret history.
- `raw_output` — the engine report as it crossed the boundary: the
  `asdict()` dict the runner marshalled. Normalization must lose nothing:
  whatever the findings view drops is still here.
- `summary` — small, render-ready aggregates (counts, verdicts).
- `findings` — the normalized view: `NormalizedFinding` per diagnostic,
  shaped like the `finding` row. `check_id` is the stable rule identifier
  regression matching keys on — renaming one is a breaking result-schema
  change. `status` (new/regression/…) is deliberately absent: the platform
  derives it from history at result time.
- `grade` — `ScanGrade` for modules whose catalog entry grades (Email, Web
  headers, Web TLS); `None` for everyone else.

Severity mapping stays an explicit per-module hook,
`TestModule.map_severity(engine_severity) -> FindingSeverity`. The engines'
five-tier `VerdictSeverity` (CRITICAL…INFO) happens to map 1:1 onto
`FindingSeverity`, and `contract.map_engine_severity` implements that
default — but the 1:1 is an observation about today's engines, not a law.
A module that must re-rank overrides the hook; everyone else delegates.
Unknown severities raise instead of guessing. Full per-module `check_id`
catalogues and any non-1:1 mapping tables belong to the M* stories and the
B2c normalization layer, not here.

## 5. Progress protocol

Every engine's `assess()` accepts `progress_cb: Callable[[str], None]`.
Because the engine runs in a child, its callbacks are **pipe writers** the
runner injects (`callbacks=("progress_cb",)` by default); each line is
marshalled to the parent and re-emitted on the task's `ProgressEmitter` as
a frozen `ProgressEvent(test_key, message, channel)`. The platform wires
the emitter's `sink` to task state; with no sink, events go to the module
logger — never silently dropped.

Chattier engines offer more callbacks with other arities — subdomainenum's
`debug_cb(tool, line)`, `cmd_cb(tool, cmd)`, `finish_cb(tool, result, ok)`.
Name them in `run_engine(callbacks=…)` and each becomes a child-side writer
of the matching channel, tolerant of any arity (`None` arguments are
dropped in rendering) — so no engine signature can break the contract. A
module narrating its own steps outside the engine call uses
`ProgressEmitter.progress_cb` / `extra_cb` in-process; the shapes are
identical on both sides of the pipe.

Events are **advisory**, exactly like the SSE stream they feed: database
state is authoritative. The platform (B8) decides which channels reach the
`/scans/{id}/events` stream; the SSE event vocabulary (`task`, `job`,
`heartbeat`, `end`) is owned by the API contract, and module progress
arrives there as sub-task detail, not as new event types.

## 6. Report contribution

`ReportContribution` is a signature-only protocol in this US: a module
*may* implement `contribute(result) -> Mapping[str, Any]` returning named
report fragments. R1a (report generation) consumes it; nothing calls it
yet, and no rendering happens module-side. A module that skips it is
reported from its normalized findings alone.

## Task lifecycle, as a module sees it

The platform owns the `ScanTaskStatus` state machine
(`queued → running → completed | failed | skipped | blocked | canceled`).
A module only ever causes three of those transitions:

| Module behavior | Task status |
|---|---|
| `run()` returns a `ModuleResult` | `completed` |
| `run()` raises `ValueError` (unacceptable input) | `failed`, message as `status_reason` |
| `run()` raises anything else (incl. `unwrap()` on a timeout) | `failed`, exception as `status_reason` |

`skipped`, `blocked` (always with a `status_reason`), and `canceled` are
platform decisions made before or around the run — verification gates,
declaration gates, user cancellation — never module decisions.

## Adding a module — the checklist

1. Implement a `TestModule`: frozen descriptor + `run()` + `map_severity()`.
   Copy `modules/noop/` as the skeleton.
2. Declare every executable test as a `TestDeclaration` with a namespaced
   `test_key` and a `test_version` you bump on behavior changes.
3. Run the engine through `execution.run_engine` — entry string, plain-data
   `kwargs` carrying `timeout=scan_input.timeout`, a `budget` you choose,
   extra callbacks named in `callbacks=…`. Never import the engine in the
   worker process and never shell out to its CLI. Engines are external
   packages, pinned in the `modules` optional-dependency extra; worker
   images provision them (B1).
4. Normalize: keep the marshalled report as `raw_output`, derive `findings`
   with stable `check_id`s, map severities through your hook.
5. Register the entry point in `pyproject.toml`.
6. Test against **recorded engine output** — capture the marshalled report
   dict once as a fixture; mapping tests must not touch the network. Add
   your module to the conformance suite in `tests/test_module_contract.py`.
7. Do **not** edit `core/`, `domains/`, or `worker/` — if your module seems
   to need it, the contract is missing something: raise it on US #76's
   thread instead of coupling.

## Worked example — the DNSSEC module

`modules/dnssec/` is the first module to wrap a real engine
(chainvalidator) and the template the other M* stories follow. Four small
files, one per contract concern:

- **`schema.py`** — the version pins (`ENGINE_VERSION` = the pinned
  chainvalidator tag, `SCHEMA_VERSION` = the module's own result schema) and
  the stable `check_id` constants. Everything that must not drift casually
  lives here, so a change to it is a visible edit.
- **`runner.py`** — `run_dnssec()` calls
  `execution.run_engine("chainvalidator.assessor:assess", …)` with
  `record_type` and `timeout` from the input, a `budget` clamped to
  `MAX_BUDGET`, and the task's `ProgressEmitter`. The engine entry is a
  parameter, defaulting to chainvalidator's real one — which is the seam the
  tests use to replay recorded output offline.
- **`mapping.py`** — `normalize()` turns the marshalled `DNSSECReport` dict
  into `NormalizedFinding`s: one overall `dnssec.chain_of_trust`, plus one
  per non-secure delegation (`dnssec.delegation.<status>` keyed on the zone)
  and a non-secure leaf. `map_status_severity()` is the module's **own**
  severity table — chainvalidator reports `secure`/`insecure`/`bogus`/
  `error`, not the `VerdictSeverity` tiers, so this module overrides the hook
  rather than delegating to the 1:1 default (bogus → HIGH, insecure →
  MEDIUM, error → LOW, secure → INFO).
- **`__init__.py`** — the frozen `DnssecModule` tying descriptor + `run()` +
  `map_severity()` together, and `MODULE`, the object the entry point
  resolves to.

The engine binding is a **string** (`"chainvalidator.assessor:assess"`)
resolved inside the runner's child, so `modules/dnssec/` imports nothing from
chainvalidator: the module is discoverable, and its descriptor readable,
without the engine installed. chainvalidator is declared only in the
`modules` optional-dependency extra (pinned to a tag), which the worker
images provision (B1); the default install and the test suite never need it.

Testing follows the plan's cost rule: **mapping is verified against recorded
engine output** — JSON fixtures under `tests/fixtures/dnssec/` captured in
the marshalled `asdict()` shape — so no test touches the network. The
contract conformance suite runs against the same recorded data through a
replay engine (`tests/dnssec_replay_engine.py`) that the runner drives in a
real child process, exercising discovery, child execution, progress
marshalling, and normalization end to end while staying offline. The module
passes the identical `assert_conformance_*` helpers the no-op does.

## What future revisions must do

- New egress queue or classification: extend `QUEUE_BY_CLASSIFICATION`,
  `worker/app.py` routing, and `worker/preflight.py` in the same commit —
  the drift test holds them together.
- New contract surface: add it to the protocol, the noop, this document,
  and the conformance suite in one change; the noop must always implement
  the whole contract.
- Result-shape changes: bump the affected module's `schema_version`; never
  reuse a `check_id` for a different rule.
- The child-process execution model is the egress-queues ADR's decision
  (Docmost > Taiga precedence, 2026-08-11); the stale "in-process
  `assess()`" wording in the Taiga US text must not be reintroduced. Pool
  changes (IDR-004, PR #24) must not require SDK changes — the `spawn`
  child is the invariant that keeps the runner pool-agnostic.
