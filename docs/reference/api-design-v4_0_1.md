# API design — v4.0.1 MVP

**Status:** delivery candidate **Base path:** `/api/v1`

**Scope:** API contracts, rules, and endpoint inventory for the NC3 Testing Platform v4.0 MVP.

## 1. Contract principles

- A ScanJob is always read through the canonical `/scans` resource, whether the caller is authenticated or a guest.
- `POST /scans` selects the request schema by media type: `application/json` launches a domain scan, `multipart/form-data` launches a file scan, any other media type receives `415`.
- Inside the JSON media type, the access state selects the variant: authenticated requests carry `asset_id`, unauthenticated requests carry `target`.
- Seven operations accept an anonymous caller: `POST /scans`, the three guest scan reads (§2.3), `GET /statements`, `GET /invitations/{token}`, `GET /feeds/{token}`. Every other operation requires an OpenID Connect token or a platform API key and answers `401` without one. `/healthz` and `/readyz` sit outside `/api/v1`.
- `ScanJob` and `ScanTask` state comes from the API. SSE events are advisory; when an event and a read disagree, the read is correct.
- Errors use the RFC 9457 Problem Details envelope.
- Some collection endpoints use cursor pagination and stable ordering. Lists order newest first, keyed on the UUIDv7 `id`; the audit log orders by (`chain_id`, `sequence_number`) (§15).
- Shapes fixed by the generated contract are versioned by the OpenAPI document itself. Three payloads live outside the document and carry their own `schema_version`: scan results, webhook payloads, and notification `data`.
- The identity provider owns identity, credentials, authentication methods, sessions, MFA enrollment, current assurance, and platform-administrator claims. The application owns its `app_user` projection, organization membership and role, assets, and verification state.

## 2. Scan launch and lifecycle

```http
POST /api/v1/scans
GET  /api/v1/scans
GET  /api/v1/scans/{scan_id}
GET  /api/v1/scans/{scan_id}/results
GET  /api/v1/scans/{scan_id}/events
POST /api/v1/scans/{scan_id}/cancel
POST /api/v1/scans/{scan_id}/claim
```

### 2.1 Domain launch (JSON)

`POST /scans` with `Content-Type: application/json` accepts exactly one target field, selected by access state.

- **Registered
  user:** carries `asset_id`. The Asset must belong to the caller's organization. Carrying `target` answers `422`.
-

**Guest:** carries `target`, a domain as free text — the only place in the API where free target text exists. The server canonicalizes it to lowercase IDNA (A-label) form without a trailing dot; text that does not parse as a domain answers `422`. Carrying `asset_id` answers `422`. Limited to non-intrusive tests. Anti-abuse gates apply. Persisted in `scan_job.target_domain` with no organization until claimed (§2.3).

- Both variants carry `modules`, a list of one or more. Requesting the `file` module answers `422`.
- Both variants may carry `module_configuration`. Each module defines its own option shape; the web module's subdomain-discovery option is one example.
- Neither variant accepts file data.

Rules:

- One launch produces one ScanTask per executable test in the selected modules. Each task queues, succeeds or fails, and is graded independently of the others.
- Verification, current MFA assurance, and declaration gates are evaluated when the selected tests require them. Operations reserved for registered users stay gated per operation.
- When a launch requires declarations, the request carries responses to the required versioned Statements, and the server records immutable, context-bound `StatementResponse` rows.

A launch answers `202 Accepted` with the ScanJob resource. Declarations sent with it are bound to the returned identifier. Gates run before the ScanJob is created, so the response carries the whole outcome.

### 2.2 File launch (multipart)

`POST /scans` with `Content-Type: multipart/form-data` launches a File-module scan. It requires one `file` part and may
include File-module configuration. It carries no target field and no `modules` field.

Server rules:

1. Quota: 100 uploads per org per day for registered users, 5 per IP per day for guests, by default.
2. Size: uploads above the configured maximum (50 MB by default) are rejected.
3. MIME type is detected from raw bytes and checked against the configured allow-list. Detection ignores the declared `Content-Type` and the filename extension.
4. FileUpload metadata, ScanJob, and initial File ScanTasks are created in one step.
5. Response is `202 Accepted` with the same ScanJob representation as other scans. It never exposes `storage_key`.
6. A rejected upload leaves no durable FileUpload row.
7. Accepted bytes are purged after analysis, or at the 24-hour deadline if analysis stalls.
8. ScanJob, results, and findings follow §11 retention. File ScanTasks use `classification = not_applicable`.

### 2.3 Guest access, reading, and claim

An unauthenticated launch returns the ScanJob state plus `claim_token`: a 256-bit random value, base64url, shown once. Only its hash is stored.

**Reading.** These three operations accept the token as a `claim_token` query parameter and declare no authentication:

```http
GET /api/v1/scans/{scan_id}
GET /api/v1/scans/{scan_id}/results
GET /api/v1/scans/{scan_id}/events
```

**Claiming.** `POST /scans/{scan_id}/claim` carries `claim_token` in the request body and requires an authenticated caller. If the job is an unclaimed guest job, the hash matches, and the retention deadline has not passed, it becomes claimed by the user and organization, and the stored hash is discarded.

- Every claim failure answers `404`.
- For a file scan, the claim also sets `file_upload.organization_id` to the claimed organization and `file_upload.uploaded_by_user_id` to the claiming user.

### 2.4 Statuses, timeout, and cancellation

- Job statuses: `queued`, `running`, `completed`, `partial`, `failed`, `canceled`.
- Task statuses: `queued`, `running`, `completed`, `failed`, `skipped`, `blocked`, `canceled`.
- A ScanResult belongs to one ScanTask, not directly to the ScanJob.
- Specific causes use stable machine-readable `status_reason` values. Labels, descriptions, localization, and operator guidance stay code-owned.
- A task timeout produces `failed` with a timeout `status_reason`. A job timeout terminates unfinished work; the job becomes `partial` when usable results exist, otherwise `failed`.
- `POST /scans/{scan_id}/cancel` records cancellation intent and preserves scan history. `DELETE` is never used to stop execution.

## 3. Live progress

`GET /scans/{scan_id}/events` is an SSE stream. Client pattern:

1. Fetch the current job/task snapshot.
2. Subscribe to the stream.
3. Apply advisory events; task events carry the public `task_id`.
4. Refetch the snapshot after reconnection or on uncertainty.

A client that misses events refetches the snapshot; the stream does not replay them.

### 3.1 Event types

| `event:`    | Payload                                             | Fires                               |
|-------------|-----------------------------------------------------|-------------------------------------|
| `task`      | `task_id`, `status`, `status_reason`, `occurred_at` | Every task state transition         |
| `job`       | `status`, `status_reason`, `occurred_at`            | Every job state transition          |
| `heartbeat` | `occurred_at`                                       | On an interval                      |
| `end`       | `status`, `occurred_at`                             | Once, at terminal state. Last event |

- `status_reason` is present on a terminal status.
- No event carries a completion percentage. The step-1 snapshot gives the total task count; each terminal `task` event advances the finished count.

## 4. Scheduling

```http
GET    /api/v1/schedules
POST   /api/v1/schedules
GET    /api/v1/schedules/{schedule_id}
PATCH  /api/v1/schedules/{schedule_id}
DELETE /api/v1/schedules/{schedule_id}
```

- Schedule creation requires an Asset that is currently eligible under verification rules.
- At execution time, re-verification runs before the ScanJob is created.
- When the gate fails: no ScanJob is created; the platform records an audit event; the platform creates the applicable user notifications; the schedule advances to its next-run state.
- A failed gate is never represented as a failed scan.

## 5. Assets and domain verification

```http
GET    /api/v1/assets
POST   /api/v1/assets
GET    /api/v1/assets/{asset_id}
PATCH  /api/v1/assets/{asset_id}
DELETE /api/v1/assets/{asset_id}
GET    /api/v1/assets/{asset_id}/scans
GET    /api/v1/assets/{asset_id}/verification
POST   /api/v1/assets/{asset_id}/verification
POST   /api/v1/assets/{asset_id}/verification/checks
POST   /api/v1/assets/{asset_id}/verification/token
GET    /api/v1/assets/{asset_id}/feeds
POST   /api/v1/assets/{asset_id}/feeds
POST   /api/v1/assets/{asset_id}/feeds/{feed_id}/revoke
```

- An Asset is an organization-owned monitored domain. Creator identity is attribution only.
- `PATCH` changes `regression_alerts_enabled`, the only mutable property. `value` and `asset_type` are immutable.
- `DELETE` answers `409` while scan history or discovered children reference the asset.

### 5.1 Verification

Verification is a separate resource nested under the Asset. Its representation carries the coverage already proven and the challenge currently running, and either of the two may be absent.

- `POST .../verification` creates a challenge with the requested `exact` or `zone` scope. On an already-verified asset the challenge is created beside the standing proof.
- `POST .../checks` triggers a DNS check.
- `POST .../token` replaces the challenge token.

The `challenge` object fully specifies the record to publish:

| Field                | Example                   | Meaning                                                                     |
|----------------------|---------------------------|-----------------------------------------------------------------------------|
| `record_type`        | `TXT`                     | Type of DNS record to create                                                |
| `record_name`        | `_nc3-verify.example.lu`  | Where to create it. Server-computed from the domain and a configured prefix |
| `verification_token` | `verify-4f7a2c9e1b8d3056` | The complete record value, pasted verbatim                                  |

Rules:

- Clients display the returned `record_name` rather than rebuilding it.
- A challenge expires seven days after issue by default: a verification reads as `expired` once `token_expires_at` has passed with no coverage proven. An asset that is already verified reads as `verified` past that deadline, whatever its challenge is doing.
- `POST .../token` answers `409` on a verified asset. Re-proving ownership or widening scope starts a new challenge with `POST .../verification`, which leaves `verified_scope` intact until the new challenge succeeds.
- `POST .../checks` sets `challenge.last_recheck_at` whether or not the record was found. A not-found result answers `200` with the challenge still in place and a `failure_code`.
- Verification statuses are `pending`, `verified`, and `expired`. The status is computed from `verified_scope` and `challenge`, so no request has to reconcile the three of them.
- Current MFA assurance is read from the identity provider's session or token.
- A verified domain is rechecked before an intrusive task is queued. No v4.0 test is intrusive, so nothing rechecks automatically in the MVP.

### 5.2 Feeds

- `POST .../feeds` creates a feed. The response is the only place the plaintext token and the full feed URL appear; only the hash is stored.
- `POST .../feeds/{feed_id}/revoke` stops serving a feed and keeps its row.
- Public delivery is `GET /feeds/{token}` (§7).

## 6. Findings

```http
GET /api/v1/findings
GET /api/v1/findings/{finding_id}
```

- `new`, `regression`, `persistent`, and `resolved` are immutable classifications derived from historical scan comparison. No operation mutates them.
- `GET /findings` takes four filters:

| Filter        | Restricts to                             |
|---------------|------------------------------------------|
| `severity`    | one severity band                        |
| `status`      | one historical-comparison classification |
| `asset_id`    | findings raised against one asset        |
| `scan_job_id` | findings from one scan                   |

- `asset_id` reaches an asset through `scan_result` → `scan_task` → `asset`.

## 7. Reports and feeds

```http
POST /api/v1/reports
GET  /api/v1/reports
GET  /api/v1/feeds/{token}
```

### 7.1 Reports

`POST /reports` accepts exactly one source: `source_scan_job_id` or `source_scan_task_id`. It renders synchronously and returns the document in the response body, with the media type matching the requested `format`:

| `format` | Response media type                                                       |
|----------|---------------------------------------------------------------------------|
| `pdf`    | `application/pdf`                                                         |
| `docx`   | `application/vnd.openxmlformats-officedocument.wordprocessingml.document` |
| `json`   | `application/json`                                                        |

- The response carries no report identifier, so a downloaded document cannot be matched to a `GET /reports` row.
- `generated_by_user_id` comes from the authenticated caller.
- To obtain a document again, submit another `POST /reports` while the source data is still retained. After `purge_at` passes, the provenance row remains and the operation answers `409`.
- Only the metadata is stored.
- Report content is assembled from scan results, whose shapes belong to the scan modules. Until those exist, only the format mapping above is settled.

### 7.2 Feed delivery

- `GET /feeds/{token}` serves a feed as `application/rss+xml` or `application/atom+xml` per the feed's configured
  format. The token in the path is the entire authorization.
- A revoked feed answers `410`.
- Feed creation and revocation are per-asset operations (§5.2).

## 8. User notifications

```http
GET    /api/v1/notifications
POST   /api/v1/notifications/{notification_id}/read
POST   /api/v1/notifications/read-all
DELETE /api/v1/notifications/{notification_id}
GET    /api/v1/account
PATCH  /api/v1/account
```

- Notifications are user-owned inbox items. Recipient selection is feature-specific application logic.
- In-app delivery has no opt-out.
- `DELETE` permanently removes the requesting user's row.
- `POST /read-all` answers `204`.
- `GET /account` returns the read-only `app_user` projection: `id`, `email`, `display_name`, `organization_id`, `organization_role`, `email_notifications_enabled`.
- `PATCH /account` changes `email_notifications_enabled` and nothing else. Profile data is owned by the identity
  provider and reaches this projection through claim updates.

## 9. Organization webhook

```http
GET    /api/v1/notifications/webhook
PUT    /api/v1/notifications/webhook
DELETE /api/v1/notifications/webhook
```

- An organization has zero or one webhook configuration.
- `PUT` creates or replaces it. `DELETE` disables the integration by deleting the configuration.
- Payload `schema_version` is part of the signed webhook contract, not configuration state.
- Retry, backoff, and delivery processing are internal application/outbox concerns.

## 10. Organization membership and invitations

### 10.1 Invitations

Admin operations:

```http
GET    /api/v1/org/invitations
POST   /api/v1/org/invitations
DELETE /api/v1/org/invitations/{invitation_id}
```

Invitee operations:

```http
GET  /api/v1/invitations/{token}
POST /api/v1/invitations/{token}/acceptance
```

Rules:

- The plaintext token appears only in the invitation link. The database stores only its unique hash.
- `DELETE` revokes the invitation. The lifecycle row is kept.
- Acceptance is authenticated and atomic. It requires an unexpired, unaccepted, non-revoked token, plus a verified user email matching the invited email.
- A user who already belongs to another organization cannot accept.
- Resending means revoking, then issuing a new invitation.
- `GET /invitations/{token}` is unauthenticated. It returns the organization name, the offered role, the invited address, and the expiry. A spent, revoked, or expired token answers `410`.

### 10.2 Members

```http
GET    /api/v1/org/members
PATCH  /api/v1/org/members/{user_id}
POST   /api/v1/org/members/{user_id}/disable
POST   /api/v1/org/members/{user_id}/enable
```

- All four require the `organization_admin` role.
- `PATCH` changes `organization_role` only, and answers `409` when the change would leave no enabled `organization_admin`.
- There is no `POST /org/members`.
- A registered user belongs to exactly one organization for the life of the account; removal is not modeled. `disable` ends access by setting `disabled_at`; a disabled user cannot authenticate against the application. Erasure is a separate workflow (§12).

## 11. Retention and hard deletion

```http
POST   /api/v1/scans/{scan_id}/retention/extend
DELETE /api/v1/scans/{scan_id}
```

- Every terminal ScanJob exposes a read-only `purge_at`, the final hard-deletion timestamp. Default `finished_at + 12 months + 30 days`. The platform sends notice 30 days before it.
- An unclaimed guest job's `purge_at` is `created_at + 24 hours`, set at creation. A successful claim recomputes `purge_at` under the normal rule, and notice applies from that point.
- Purging at the deadline does not wait for the job to finish; unfinished work is terminated.
- The extension operation updates `purge_at` and records an audit event. It takes no request body: how far the deadline moves is platform configuration. Read the new deadline from `purge_at` in the response.
- `DELETE /scans/{scan_id}` is hard deletion, distinct from `POST .../cancel`.

## 12. Account data access and product exports

- User-facing table exports operate on data that the normal list APIs already return.
- GDPR access and portability are a separate compliance responsibility concerning currently retained personal data.
- Account erasure is a multi-initiator workflow: a user request, a platform operator, or identity-provider account deletion. v4.0 defines no public self-service erasure endpoint. The 30-day completion guarantee and the erasure steps apply regardless of initiator, and every initiation is recorded in the audit log.

## 13. API keys

```http
GET  /api/v1/api-keys
POST /api/v1/api-keys
POST /api/v1/api-keys/{key_id}/revoke
```

- A key belongs to one user or to the organization when `owner_user_id` is null. Organization keys require the `organization_admin` role to create.
- `POST /api-keys` returns the plaintext secret once. Only a lookup prefix and a hash are stored.
- Creation accepts an optional `expires_at`. Absent means no expiry.
- Revocation is a `POST`. The row is kept with `revoked_at` and `revocation_reason`, and revoked keys stay listed.
- Every key-management operation consumes current MFA assurance.
- Erasing an account also revokes and deletes that user's keys.
- `read_only` permits `GET` operations. `full_scan` is additionally required to launch a scan, which is recorded with `source = api`.

## 14. Statements

```http
GET  /api/v1/statements
POST /api/v1/statement-responses
```

- `GET /statements` returns the statements currently in force — `effective_at` reached, not retired — each with its `id`, `statement_key`, `version`, `response_kind`, `required_context_type`, `content_hash`, `content_uri`, and `effective_at`. Unauthenticated.
- A client must send the exact version it answered. This operation is the only way to learn which version is current.
- `POST /statement-responses` records an account-level response, where `required_context_type` is null. It rejects a statement that requires a context; a per-launch declaration travels in the launch payload (§2.1).
- No v4.0 executable test is classified as intrusive, so no v4.0 launch requires a per-launch declaration.

## 15. Audit log

```http
GET /api/v1/admin/audit-events
```

- Requires the platform-administrator claim, which is independent of any organization role. An organization administrator has no access.
- Cursor pagination, ordered by (`chain_id`, `sequence_number`) — the pair that defines the hash chain.
- Filters: `chain_id`, `organization_id`, `event_type`, and a time range on `occurred_at`.
- The response returns the stored representation, including `detail` and the hash-chain fields. Encrypted payloads are returned as ciphertext; payload decryption is a separate operator procedure.

## 16. Organization settings and white-label

`organization.settings` and `white_label_config` are internal, deferred to ≥4.1.

