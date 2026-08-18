# Secret scanning: controls, triage record, and policy

Two scanners watch this repository: GitHub secret scanning with **push
protection** (enabled on all 12 organization repos) and the **GitGuardian**
GitHub App (org-wide). GitGuardian's PR check is deliberately **not** a
required branch-protection check: its generic detectors flag the repository's
documented development defaults (below), so a hard gate would train people to
ignore it. A GitGuardian finding is treated as real until it matches the
inventory in this document.

## What is and is not a secret here

**Real credentials never live in this repository.** They are supplied at
deployment time only:

- production database/broker passwords → the Dokploy environment tab
  (`docker-compose.dokploy.yml` interpolates `${VAR:?}` — required, no
  defaults);
- the envelope master key → `APP_ENCRYPTION_MASTER_KEY(_FILE)`, mounted into
  the api service only (data-model §1.2, `core/settings.py` `_FILE`
  indirection);
- development stacks → parameterized defaults (`postgres`, `nc3_app`,
  `app_platform`, `nc3_auth`, `rabbitmq`, the Rauthy dev admin, the dev
  master-key filler in `.env.example`). These work only against a
  developer's loopback Compose stack and are rotation-free by construction.

High-entropy strings in `src/` and `tests/` are **published contract
examples and mock constants** (claim tokens, API-key samples, feed tokens in
`domains/*/examples.py`, the mock routers, and the smoke suite). They
authenticate nothing.

## Triage record — GitGuardian incidents (as of 2026-08-18)

PR #38 check findings, verified against the working tree and full file
history:

| Incident | File | Verdict |
|---|---|---|
| 36316315 | `docker-compose.dokploy.yml` | False positive on URL shape: the flagged line is `${NC3_AUTH_DB_PASSWORD:?}` — a required interpolation carrying **no value at all** |
| 36317091 | `infra/compose/api.yml` | Development default `nc3_auth` inside a `${VAR:-default}` interpolation; loopback Compose stack only |
| 36317092 | `.env.example` | Documented development default (`NC3_AUTH_DB_PASSWORD=nc3_auth`); the file is explicitly development-only |

The 14 historical-scan incidents (2026-08-04 → 2026-08-18) are the same two
classes: *Generic Password* over the Compose/`.env.example` development
defaults (`infra/compose/celery.yml`, `infra/compose/api.yml`,
`docker-compose.dokploy.yml`, `.env.example`) and *Generic High Entropy
Secret* over contract mock constants
(`tests/test_smoke_surface.py`, `domains/api_keys/router.py`,
`domains/scans/examples.py`, `domains/assets/examples.py`). The
`docker-compose.dokploy.yml` history was audited end to end: no
non-interpolated credential has ever existed in it.

**Disposition:** ignore in the GitGuardian dashboard as *test/dev
credential* with a pointer to this file. Dashboard triage is workspace-side —
the GitHub App does not read in-repo configuration.

## Policy

1. Never commit a real credential — GitHub push protection blocks known
   provider tokens; nothing blocks a generic password, so the review habit
   is the control.
2. A new GitGuardian finding that is **not** covered by the inventory above
   is treated as a real leak: rotate first, investigate second, then update
   this record.
3. New development defaults follow the existing shape (`${VAR:-default}` in
   Compose, documented value in `.env.example`) and get triaged into the
   dashboard when GitGuardian flags them — never silenced by weakening the
   scanners.
4. `.gitguardian.yaml` configures **ggshield only** (local/CI CLI scans):
   it excludes `.env.example` because that file is by definition an
   inventory of development defaults. It has no effect on the GitHub App or
   the dashboard.
