# Database migrations

Schema changes travel as Alembic revisions in `migrations/versions/`. The models
(`nc3_testing_platform.models`) are the source of truth; a revision is the diff
that moves a live database to match them. CI proves three things on every push:
the schema builds from empty, `downgrade base` → `upgrade head` round-trips, and
the models and the head revision agree (`alembic check`).

## Everyday commands

```bash
make db-revision m="add asset tags"   # autogenerate a revision from model changes
make db-upgrade                       # apply everything up to head
make db-downgrade                     # step back one revision
make db-check                         # fail if models and head disagree
make db-current                       # where this database is
make db-history                       # the revision chain
```

All of them read `DATABASE_URL` (same variable as the application) and default
to the local Compose PostgreSQL.

## What needs a revision

Any change that alters DDL: a new or dropped table or column, a type or
nullability change, a default, an index, a constraint, an enum. If
`make db-check` complains after your change, you owe a revision. Doc-only,
comment-only, or pure application-logic changes do not.

One revision per logical change, committed together with the model change it
implements — never a shared "misc schema fixes" revision.

## Reviewing a generated revision

Autogenerate proposes; you decide. Before committing one:

1. Read every operation and match it against the model diff you intended.
   Anything you cannot explain does not ship.
2. Check the downgrade actually reverts the upgrade — run the round trip
   locally, not in your head: `make db-upgrade && make db-downgrade && make db-upgrade`.
3. Rename detection does not exist: a renamed column or table comes out as
   drop-and-create, which destroys data. Rewrite those by hand with
   `op.alter_column(..., new_column_name=...)` / `op.rename_table(...)`.
4. Constraint and index names must come from the naming convention in
   `core/db.py` — if a name looks hand-invented, it will never diff cleanly again.

## What autogenerate misses

- **`metadata=MetaData()` in rendered enums.** Because the shared enum types
  are bound to `Base.metadata`, autogenerate renders that binding as a bare
  `metadata=MetaData()` call it never imports — a `NameError` on first run.
  Delete the argument from the generated file; the binding lives in the
  models, not in a frozen revision.
- **Enum types on downgrade.** `op.drop_table()` does not drop the PostgreSQL
  enum types the table's creation brought along; the round trip then fails on
  "type already exists". Drop them explicitly (see the initial revision's
  downgrade for the pattern). Value changes to an existing enum are not
  detected at all — write those by hand (`ALTER TYPE ... ADD VALUE`, or a
  rename-copy-drop for removals).
- **CHECK constraint changes.** New or altered `CheckConstraint`s on an
  existing table are not detected; add/drop them by hand.
- **Renames** (above) — always drop-and-create unless rewritten.
- **Row-level security, grants, triggers.** Deliberately outside the models;
  when they arrive (RLS is descoped to a later phase), they are hand-written
  operations.

## Wipe rules

Until the first tagged release, the schema baseline may be rebuilt: revisions
can be squashed into the initial one, and development databases are wiped and
recreated (`alembic downgrade base && alembic upgrade head`, or drop the
volume). Do it only on `main`-bound PRs that say so explicitly.

From the first release on, history is append-only: a merged revision is never
edited, reordered, or deleted — a wrong migration is fixed by a new revision
that repairs it. The throwaway `scan_artifacts` table created by the compose
demo task predates this workflow and is dropped by wiping the dev database;
real tables exist only through revisions.
