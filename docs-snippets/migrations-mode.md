# Snippets for README.md and CHANGELOG.md (migrations mode)

Not merged into README/CHANGELOG on purpose (other branches edit them). Paste
when merging `feat/migrations-mode`.

## README — new section (suggested place: right after "Try it in 30 seconds")

### No database? Audit your migrations

```bash
npx airlock-rls migrations                 # reads ./supabase/migrations
npx airlock-rls migrations schema.sql      # or any files / folders
```

No connection string, no credentials, nothing leaves your machine. Airlock
replays your SQL migrations (in file-name order, like the Supabase CLI) into an
embedded Postgres ([PGlite](https://pglite.dev)) and runs **the same audit** as
the live mode: every rule, the grant-aware logic, `--allow`, `--fail-on`,
`--json`, `--prompts`. Each finding it can trace says which migration and line
created the object:

```
(migrations: 2 file(s), 12 of 16 statement(s) loaded into an embedded Postgres, 1 failed, 1 extension(s) skipped (pg_net))
✗ 2 problem(s) in "public":
    ✗ profiles table in "public" has RLS DISABLED — every row is exposed to the API roles (supabase/migrations/20260101000000_init.sql:9)
    ✗ notes."read all" [SELECT] USING(true) — anon reads every row (supabase/migrations/20260101000000_init.sql:22)
```

Before your first migration it recreates what a hosted project already has: the
`anon`/`authenticated`/`service_role`/`authenticator` roles, `auth.uid()`,
`auth.role()`, `auth.jwt()` and `auth.users`, `storage.buckets`/`objects` (RLS
on), the `extensions` schema, the `supabase_realtime` publication, and stubs for
`cron.schedule`. Common extensions load (`uuid-ossp`, `pgcrypto`, `pg_trgm`,
`citext`, `hstore`, `ltree`, `moddatetime`, `unaccent`, `fuzzystrmatch`,
`btree_gist`, `btree_gin`, and `vector` when available); others (`pg_net`,
`pg_graphql`, `pgsodium`…) are skipped and counted.

**Default grants.** Projects created before Oct 30, 2026 auto-grant new tables in
`public` to `anon`/`authenticated`, and most migrations rely on it (they never
`GRANT`). The migrations mode emulates that by default, because a security tool
should assume the grant. `--no-default-grants` models a newer project: an
ungranted `USING (true)` table is then not reported as exposed.

**Honest about what it couldn't load.** A statement that fails is listed with its
file, line and error, and the run adds a `migrations_incomplete` warning:
whatever it would have created was not audited. If nothing loads at all, the
exit code is `2`, never a clean pass. `BEGIN`/`COMMIT` are skipped so one bad
statement can't hide the rest of its file.

**Live vs. migrations.** The live mode reads the real catalog (including grants
made by hand in the dashboard and drift from what the migrations say) and can
prove leaks with DAST. Use migrations in CI on every PR; use the live mode (or
Airlock Monitor) on the deployed database. `--url`, `--anon-key`,
`--dast-write` and `--site` are refused in migrations mode.

Options table additions:

```
migrations [PATH...]  Replay SQL migrations (default: supabase/migrations) into an
                      embedded Postgres and audit them. No database needed.
--no-default-grants   (migrations) Don't emulate the pre-Oct-30 auto-grant on public.
```

Library: findings that come from migrations may carry `file` and `line`.

## CHANGELOG entry

- **`airlock migrations`: audit without a database.** Replays your SQL migrations
  (default `supabase/migrations`, file-name order) into an embedded Postgres
  (PGlite) after recreating what a hosted Supabase project has (API roles, auth
  helpers and `auth.users`, storage tables, realtime publication, default grants
  on `public`), then runs the same audit engine, unchanged. Findings get `file`
  and `line` of the migration that created the object. Statements that fail to
  load are listed and raise a `migrations_incomplete` warning; nothing loadable is
  exit 2. Unsupported `CREATE EXTENSION` is skipped and counted.
  `--no-default-grants` models projects created after Oct 30, 2026.
- New dependencies: `@electric-sql/pglite` and `@electric-sql/pglite-socket`
  (loaded only in migrations mode).
