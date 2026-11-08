# Airlock RLS — the CI gate for Supabase

[![test](https://github.com/mateuszingano/airlock-rls/actions/workflows/test.yml/badge.svg)](https://github.com/mateuszingano/airlock-rls/actions/workflows/test.yml)
[![npm](https://img.shields.io/npm/v/airlock-rls.svg)](https://www.npmjs.com/package/airlock-rls)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **Scanners check that a policy exists. Airlock proves it works — and blocks the merge if it doesn't.**

Airlock fails your build when a Supabase table ships with Row Level Security off,
or with a policy that is enabled but lets everyone through. `USING (true)` is the
obvious one; `auth.uid() = owner_id OR 1 = 1` does the same thing and passes
every "is RLS enabled?" check.

## Try it in 30 seconds

```bash
# audit your database (a read-only role is enough: it reads catalog metadata, never your rows)
npx airlock-rls "$SUPABASE_DB_URL"

# no database? scan your deployed app for a leaked service_role key
npx airlock-rls --site https://your-app.com
```

Real output against a test schema:

```
✗ 3 problem(s) in "public":
    ✗ profiles table in "public" has RLS DISABLED — every row is exposed to the API roles
    ✗ documents."own docs" [SELECT] USING (((auth.uid() = owner_id) OR (1 = 1))) always evaluates true — anon reads every row
    ✗ invoices."public read" [SELECT] USING(true) — anon reads every row

RLS audit failed: 3 problem(s) found.
```

Exit code `1`, so the same command blocks a merge in CI ([GitHub Action below](#use-it-as-a-github-action-the-gate)).

## No database? Audit your migrations

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

The embedded Postgres (~27 MB) is **not** a dependency of `airlock-rls`, so a plain
`npx airlock-rls` stays small. The first `airlock migrations` run downloads it once into
`~/.cache/airlock-rls/` (override with `$AIRLOCK_CACHE_DIR`); later runs start in about two seconds.


---

## How it works

1. **Reads the catalog** — `pg_tables`, `pg_policies`, grants, views, functions.
   It only reports a table a client role can actually reach (it checks the grants),
   so a locked-down table doesn't cry wolf.
2. **Parses each policy expression** into an AST and decides whether it really
   scopes rows to the caller, instead of matching strings. Shapes it can't prove
   become a warning, never a silent pass.
3. **Optionally proves it (DAST)** — add `--url` and `--anon-key` next to the DB
   URL and it reads every table over the REST API as an anonymous user. A row
   coming back is a proven leak, not a guess.

**Why now:** on Oct 30, 2026 Supabase stops auto-granting new tables to `anon` /
`authenticated`. The quickest fix for the first `permission denied` is
`grant ... on all tables in schema public`, which also grants every table that has
RLS off. That is exactly what Airlock fails on.
([Write-up of the change](https://shipsealed.com/rls/supabase-october-30-grants-change/?utm_source=readme&utm_medium=referral&utm_campaign=airlock-rls))

**More:** [live demo](https://shipsealed.com/demo/?utm_source=readme&utm_medium=referral&utm_campaign=airlock-rls) · [Supabase RLS guides](https://shipsealed.com/rls/?utm_source=readme&utm_medium=referral&utm_campaign=airlock-rls) · [browser scanner, no install](https://shipsealed.com/service-role-scanner/?utm_source=readme&utm_medium=referral&utm_campaign=airlock-rls)

---

## What it checks

Airlock audits the *logic* of your policies, not just their presence.

**Fails the build (exposure):**
1. **`rls_disabled`** — a table with RLS off; every row exposed to the API roles.
2. **`permissive_true`** — a policy `USING (true)` / `WITH CHECK (true)`, **or one
   that reduces to always-true**: a common tautology OR-joined to the scope token
   (`auth.uid() = x OR 2=2`, `OR 'a'='a'`, `OR 1<2`, `OR 1 in (1)`, `OR length(x) >= 0`,
   even nested `OR (a OR 1=1)`), a reflexive `owner_id = owner_id`, or the bare form —
   the scope token is present but the row still matches for everyone. (A tautology
   under `AND` is fine — the scope survives.) It catches the *common* always-true
   shapes (literal `true`, self-equality, evaluated constant comparisons, a constant
   `IN` a constant list, a non-negative built-in like `length(x) >= 0`) as a hard
   fail. An OR branch it *can't* prove — an exotic tautology (`NOT (1=2)`), a
   widening predicate (`OR status = 'published'`), anything unrecognized — is not
   passed silently: it becomes an **`or_branch_unscoped` warn** (see below), so a
   new tautology shape never re-opens a silent hole.
3. **`anon_unscoped`** — an anon-readable policy that doesn't scope to the user
   (no `auth.uid()`) — everyone reads every row, even when it isn't literally `true`.
4. **`write_unscoped`** — an anon INSERT/UPDATE whose `WITH CHECK` is present but
   doesn't tie the new row to the caller — anyone can forge rows as another tenant.
5. **`delete_unscoped`** — a `FOR DELETE` policy whose `USING` doesn't scope to the
   caller, so anyone the policy applies to can delete rows they don't own. Unlike
   a read, this is a **fail for `authenticated` too**: destroying another tenant's
   data is worse than reading it, and it isn't reversible.
6. **`update_using_unscoped`** — a `FOR UPDATE` policy whose `USING` doesn't scope
   to the caller. The subtle one: a scoped `WITH CHECK` constrains what the new
   row may *look like*, but `USING` is what decides which rows can be **targeted**.
   With an open `USING`, any row can be taken over — and writing *less* SQL (no
   `WITH CHECK` at all) used to look safer to the gate than writing it explicitly.
   Also a fail for `authenticated`.
7. **`anon_read_leak`** *(DAST)* — with an anon key, Airlock actually reads each
   table over the REST API; a returned row is a **proven** leak, not an inference.
8. **`matview_exposed`** — a **materialized view** a client role can read. RLS
   does not apply to a matview *at all*: `CREATE MATERIALIZED VIEW
   public.all_payments AS SELECT * FROM payments` plus a grant to `anon` is a
   full dump of the underlying table, no matter how correct the policies on
   `payments` are.
9. **`service_role_exposed`** — a Supabase **service key** shipped to the browser
   (a `service_role` JWT or an `sb_secret_...` key). It bypasses *every* RLS
   policy at once, so whoever reads it owns your database. Scanned straight from
   your deployed site — no database needed (see below).
10. **`policy_trusts_user_metadata`** — a policy that decides access from
   `user_metadata`: `auth.jwt() -> 'user_metadata'`, the `#>> '{user_metadata,…}'`
   path form, or `auth.users.raw_user_meta_data` (also inside a subquery). Every
   signed-in user can rewrite their own user_metadata from the browser with
   `supabase.auth.updateUser({ data })`, so anyone who signs up passes the check:
   `(auth.jwt()->'user_metadata'->>'role') = 'admin'` is an admin gate they can
   open, and `org_id = (auth.jwt()->'user_metadata'->>'org_id')::uuid` is a tenant
   id they can set to someone else's (this one looked scoped and used to pass).
   **Fail** on a permissive policy reachable by `authenticated` (downgraded to a
   warn only when a restrictive policy that doesn't itself trust user_metadata
   scopes every command); **warn** on a RESTRICTIVE policy (its narrowing can be
   bypassed) and on a client-callable SECURITY DEFINER function whose body reads
   it (e.g. an `is_admin()` helper). `app_metadata` / `raw_app_meta_data`
   (server-only) never fires; neither do the words inside a string literal, a
   policy only `TO anon`, or a table authenticated holds no grant on. Waive with
   `table.policy` (or `fn:<name>` for a function).

**Warns (worth a review):**
- **`default_privileges_to_api_roles`** — `ALTER DEFAULT PRIVILEGES` that hand
  every *future* table to `anon` / `authenticated` (or `PUBLIC`). Since Supabase's
  Oct 30, 2026 change, new tables in `public` are no longer granted to the API
  roles, and the quickest way to silence the resulting `42501 permission denied`
  is a blanket default grant. Nothing leaks because of it today, but the next
  table whose migration forgets `ENABLE ROW LEVEL SECURITY` ships open. One warn
  per owner and schema, naming the privileges (writes called out). Defaults owned
  by Supabase-managed roles (`supabase_admin`, `supabase_*`, `pg_*`,
  `service_role`, …) are the platform's own and are never flagged; defaults owned
  by `postgres` or any custom role are. Waive with `defaults:<owner>`. The
  one-off `GRANT ALL ON ALL TABLES` form leaves only per-table grants, which the
  existing rules already judge (RLS off → `rls_disabled`).
- **`or_branch_unscoped`** — the policy scopes to `auth.uid()` but an `OR` branch
  widens it in a way a static scan can't prove restricts (`auth.uid() = owner OR
  status = 'published'`, `OR deleted_at IS NULL`, an exotic tautology). It may be
  intentional public sharing, or a leak — this is a **fail-safe**: unproven OR
  branches warn instead of passing silently. Prove it with the DAST pass or
  allow-list it if intended.
- **`authenticated_unscoped`** — any logged-in user reads all rows (role-only check).
- **`helper_scoped`** — a client-reachable read scoped *only* through a helper
  function of any name (`is_public()`, `authorize('posts.read')`, `belongs_to_org()`);
  a static scan can't see inside it, so verify it actually restricts the caller
  (or allow-list it if intentional).
- **`write_unchecked`** — an INSERT/UPDATE policy with no `WITH CHECK` guard.
- **`anon_write_inconclusive`** *(DAST, `--dast-write`)* — an anon INSERT hit a
  column constraint (e.g. `NOT NULL`), not an RLS block. That can fire *before*
  the RLS check, so it does **not** prove RLS would admit a valid row — verify by
  hand. Only a `201` (a row actually inserted) is reported as a proven write leak.
- **`public_bucket`** — a public storage bucket.
- **`security_definer`** — a function that runs as its owner and can bypass RLS.
- **`definer_search_path_mutable`** — a SECURITY DEFINER function with no pinned
  `search_path`. It resolves unqualified names against the *caller's* search_path,
  so a caller can shadow a referenced object and run code as the function's owner
  (Supabase advisor: `function_search_path_mutable`). Fix with
  `ALTER FUNCTION f SET search_path = ''`.
- **`bypassrls_role`** — a role with `BYPASSRLS` or `SUPERUSER` outside the
  Supabase-managed set (`postgres`, `service_role`, `supabase_*`, `pg_*`…), **or
  any bypass role the API caller can reach, whatever its name** (the `supabase_`
  prefix is not reserved, so a backdoor can't hide behind it). RLS never applies
  to such a role; if the client reaches it, every policy is skipped. Allow-list
  it (`role:<name>`) if it is a deliberate admin role.
- **`owner_bypasses_rls`** — a table whose **owner** is a role the API can reach
  (`anon`, `authenticated`, or a role granted to them). The owner bypasses its own
  RLS unless the table sets `FORCE ROW LEVEL SECURITY`. Reassign the owner or
  `ALTER TABLE t FORCE ROW LEVEL SECURITY`.

**What it does NOT cover yet (declared, not silently missed):**
- **`--site` does not defeat DNS rebinding.** Literal private, loopback,
  link-local and metadata addresses are refused (including their IPv4-mapped
  IPv6 spellings), and every fetch has a timeout and a body cap. Redirects are
  followed by hand and every hop is re-validated, so a `302` to an internal
  address is refused — but a hostname that *resolves* to a private address is
  still not caught, because the check runs on the URL, not on the resolved socket.
- **Checks that could not run are reported, not assumed clean.** If the audit
  role lacks permission to read `storage.buckets`, the realtime publication or
  storage policies, each one is surfaced as `check_skipped` with its reason. A
  clean report means "I looked", not "I could not look".
- **One schema per run.** Other schemas exposed through PostgREST are not
  audited. A schema with nothing in it now *fails* rather than passing green,
  but that only catches the typo, not the second schema you forgot to scan.
- An **unscoped but not provably-true** qualifier for `authenticated` (e.g.
  `USING (org = 'acme')`) is a **warn**, not a fail — there the scan genuinely
  cannot tell whether the openness is intended. Gate it with `--fail-on warn`.
  A *provable* tautology for `authenticated` **is** a fail.
- **Custom roles reached only by `SET ROLE`.** A role a client can *switch into*
  via `authenticator` is undecidable statically, so a `USING(true)` policy on such
  a role is not flagged. A custom role reached by **inheritance** (`GRANT app_role
  TO authenticated`) IS now caught — every logged-in user holds it without
  `SET ROLE`, and Airlock resolves that membership with `pg_has_role`.
- **`ALTER POLICY` is not read.** Airlock audits the policies as the database
  currently holds them (`pg_policies`), which is the end state — but if you are
  looking for a *migration-time* gate on a policy being loosened, that is
  `migration-guard`'s job, not this one.
- **A bare `--allow` name is refused when it is ambiguous.** Policy names are
  unique per table, not per schema, so `--allow public_read` is only applied when
  exactly one table carries that name. When two or more do, nothing is silenced
  and an `allow_ambiguous` warn tells you the qualified form to use. This is a
  deliberate refusal, not a miss.
- **Only policies may be waived by a bare name.** Buckets, views, materialized
  views, SECURITY DEFINER functions and realtime tables live in their own
  namespaces and must be qualified the same way the finding prints them:
  `storage:receipts`, `view:reports`, `matview:reports`, `fn:is_admin`,
  `realtime:orders`, `role:reporting`, `table:notes`. One flat name used to
  silence all of them at once, so
  `--allow reports` could mute a matview FAIL the author never looked at. A bare
  name that would have matched raises `allow_needs_namespace` and waives nothing.
- **An `--allow` entry that matches nothing raises `allow_unused`.** A waiver
  left behind by a rename protects nothing while reading like it does.
- A `WITH CHECK` scoped *only* through a helper function is treated as scoped
  (same "can't see inside" limit as reads) — use the DAST write probe to prove it.

Intentionally-public policies (a status page, a contact form) can be waved
through with an allow-list, so the gate stays honest without crying wolf.

### The DAST pass (prove it, don't infer it)

Give Airlock a project URL and an anon key and it runs the dynamic check the
static scanners can't — it reads each table *as an anonymous attacker would*:

```bash
airlock "$SUPABASE_DB_URL" --url "$SUPABASE_URL" --anon-key "$SUPABASE_ANON_KEY"
```

### Scan a deployed site for an exposed service key (zero setup)

The worst leak a Supabase app can have is its **service key in the browser** — a
`service_role` JWT or an `sb_secret_...` key bundled into the frontend. It
bypasses every RLS policy at once. Airlock finds it with **only your site URL** —
no database, no credentials:

```bash
npx airlock-rls --site https://your-app.com
```

It fetches the page and its JS bundles and fails (exit `1`) if a service key is
present. It **never** flags the `anon` key — that one is public by design — and
**never** prints the key it finds.

The same run also checks three files a static host should never serve:

- **a downloadable `.env`** (fail) — reports how many variables it holds, never a value;
- **a public `.git` folder** (fail) — your source and its full history;
- **public source maps** (warn) — your original source; a service key inside a
  map's `sourcesContent` is still a fail.

Each one is confirmed by **content**, not by status code: SPA hosts answer `200`
with `index.html` for any path, and that is never reported.

If the site ships your Supabase **public** key (anon or `sb_publishable_`), the
report says so: that is normal, but it means RLS is the only lock on your tables,
and a site scan can't see RLS. Run the DB audit for that.

### Copy-paste fix prompts (`--prompts`)

Add `--prompts` and every problem comes with a prompt to paste into Cursor,
Lovable, Bolt or Claude Code. It carries the exact table/policy and what Airlock
found, the change to ask for, and the guard rails an AI tends to skip (never
"fix" by disabling RLS or by writing `USING (true)`, show the SQL first, re-run
the check). `--json` always includes it, as `fixPrompt` on each finding.

```bash
npx airlock-rls "$SUPABASE_DB_URL" --prompts
```

### A draft fix migration (`--fix-sql`)

```bash
npx airlock-rls "$SUPABASE_DB_URL" --fix-sql airlock-fix.sql
```

Writes a **draft** migration for this audit, wrapped in `begin; … commit;`:

- **Mechanical fixes as real SQL**, each with a note on what it can break:

  | Finding | Statement |
  |---|---|
  | `rls_disabled` | `alter table … enable row level security;` (+ a commented policy template: RLS with no policy locks the table for the API) |
  | `anon_executes_definer` | `revoke execute on function … from public, anon;` |
  | `definer_search_path_mutable` | `alter function … set search_path = '';` |
  | `view_bypasses_rls` | `alter view … set (security_invoker = true);` |
  | `matview_exposed` | `revoke select on … from anon, authenticated;` |
  | `public_bucket` | `update storage.buckets set public = false where id = '…';` |
  | `owner_bypasses_rls` | `alter table … force row level security;` |

- **Everything that needs a decision is a commented `TODO`**: permissive or
  unscoped policies (a `drop policy` / `create policy` template with an
  `<owner_column>` placeholder — a policy is never rewritten automatically),
  a SECURITY DEFINER function callable by `authenticated`, Realtime exposure,
  a `BYPASSRLS` role, and DAST-proven anon reads/writes.

Identifiers are always double-quoted from the catalog spelling, so names with
spaces, uppercase or quotes apply correctly. Allow-listed findings are never
included. Review it before applying, then re-run `npx airlock-rls`.

With `--json`, the "written to" note goes to stderr so stdout stays valid JSON.

### GitHub code scanning (SARIF) and annotations

Two outputs make findings show up where you already look on GitHub. Both are
**additive**: the normal report still prints and the exit code doesn't change.

```bash
npx airlock-rls "$SUPABASE_DB_URL" --sarif airlock.sarif   # also write a SARIF 2.1.0 log
npx airlock-rls "$SUPABASE_DB_URL" --format github         # also print ::error / ::warning annotations
```

- **`--sarif <file>`** writes a SARIF 2.1.0 log (validated against the official
  OASIS schema in the test suite): one rule per finding kind, `fail` → `error`,
  `warn` → `warning`, the finding's detail as the message, a stable fingerprint,
  and the copy-paste fix prompt under `properties.fixPrompt`.
- **`--format github`** prints one workflow command per finding, so GitHub
  renders it as an annotation on the run. It's skipped under `--json`, which
  stays parseable. Also read from `$AIRLOCK_FORMAT`.

**Where a finding points.** A finding from the live database has no file: its
location is the database object (`public.payments`, `notes."read all"`), as a
SARIF *logical* location. A finding that carries a file and line (from a
migrations file) gets a *physical* location, and GitHub points at that line.

#### Upload to code scanning (GitHub Action)

```yaml
permissions:
  contents: read
  security-events: write   # needed by upload-sarif

steps:
  - uses: actions/checkout@v4
  - uses: mateuszingano/airlock-rls@v1
    with:
      db-url: ${{ secrets.SUPABASE_DB_URL }}
      sarif: airlock.sarif
  - uses: github/codeql-action/upload-sarif@v3
    if: always()            # the gate fails the step on a leak; upload anyway
    with:
      sarif_file: airlock.sarif
      category: airlock-rls
```

The `sarif` input only adds the file; the gate still fails the job on a leak.

> Note: GitHub code scanning is built around files. Database findings carry a
> logical location only, so they may show without a line link (or, depending on
> GitHub's ingestion rules, not as an alert at all). Findings with a file and
> line (migrations mode) map cleanly. `--format github` annotations work for both.

### Use it from a coding agent (skill)

Airlock ships an agent skill so Claude Code, Cursor and other agents that support skills can
run the audit and fix what it finds, without you remembering the flags:

```bash
npx skills add https://github.com/mateuszingano/airlock-rls --skill airlock-rls
```

Or copy `skills/airlock-rls/` into `~/.claude/skills/` (Claude Code). Then ask your agent:

```
audit the RLS of this Supabase project
is my deployed app leaking a service key? https://your-app.com
```

The skill picks the mode (site scan with just a URL, or the full DB audit from
`$SUPABASE_DB_URL`, never printing it), reads the `--json` findings, turns each `fixPrompt` into
a migration it shows you before applying, never "fixes" by disabling RLS or writing
`USING (true)`, and re-runs the check to confirm.

---

## Use it as a GitHub Action (the gate)

Add your Supabase Postgres connection string as a repo secret named
`SUPABASE_DB_URL` (a read-only role is enough — the static audit reads only
catalog metadata: `pg_tables`, `pg_policies`, grants, functions and views, never
your row data), then drop this in `.github/workflows/rls-gate.yml`:

```yaml
name: RLS Gate
on: [push, pull_request]

jobs:
  rls-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: mateuszingano/airlock-rls@v1
        with:
          db-url: ${{ secrets.SUPABASE_DB_URL }}
          # allow: public_read,status_select   # optional
          # schema: public                      # optional
```

If any table is exposed or any policy is permissive, the job exits non-zero and
the merge is blocked. A full example lives in [`examples/rls-gate.yml`](examples/rls-gate.yml).

### Action inputs

| Input          | Required | Default    | Description                                                        |
| -------------- | -------- | ---------- | ------------------------------------------------------------------ |
| `db-url`       | yes      | —          | Postgres connection string for the project to audit.               |
| `allow`        | no       | `''`       | Comma-separated waivers: policy names, or `ns:name` for buckets/views/matviews/functions/realtime. |
| `schema`       | no       | `public`   | Schema to audit.                                                   |
| `site`         | no       | `''`       | Deployed site URL to also scan for an exposed `service_role` key.  |
| `url`          | no       | `''`       | Supabase project URL. With `anon-key`, runs the DAST pass that **proves** exposure. |
| `anon-key`     | no       | `''`       | Public anon key for the DAST pass (public by design). Used with `url`. |
| `dast-write`   | no       | `false`    | Also probe anonymous INSERTs during DAST (safe — leaves no test data). |
| `sarif`        | no       | `''`       | Also write a SARIF 2.1.0 log to this path (upload it with `github/codeql-action/upload-sarif`). |
| `node-version` | no       | `20`       | Node.js version used to run the audit.                            |

---

## Use it as a CLI (local / any CI)

```bash
# via npx (no install)
SUPABASE_DB_URL=postgresql://... npx airlock-rls

# or install it
npm i -D airlock-rls
SUPABASE_DB_URL=postgresql://... npx airlock

# pass the URL directly
airlock postgresql://postgres:postgres@127.0.0.1:54322/postgres

# machine-readable output
airlock --json
```

Get the URL from `supabase status` (local) or your project's connection string.

### Options

```
--fail-on <level>  What breaks the build: "fail" (default) or "warn". Several
                   rules emit warn — including an authenticated tenant leak —
                   so without this they are printed, never enforced.
                   (also read from $RLS_AUDIT_FAIL_ON).
--strict           Alias for --fail-on warn.
--allow <names>    Policy names to treat as intentionally permissive
                   (also read from $RLS_AUDIT_ALLOW). Prefer "table.policy":
                   a bare name applies only when one table carries it.
                   Non-policy objects must be qualified by namespace:
                   storage:<bucket>, view:<name>, matview:<name>,
                   fn:<name>, realtime:<table>.
--schema <name>    Schema to audit (default: public).
--url URL          Supabase project URL — enables the DAST pass ($SUPABASE_URL).
--anon-key VALUE   Public anon key for the DAST pass ($SUPABASE_ANON_KEY).
--dast-write       Also probe anonymous INSERTs (safe — leaves no test data).
--site URL         Deployed site URL — scan its HTML/JS for an exposed
                   service_role key, plus a downloadable .env, a public .git
                   and public source maps. Needs no database ($SUPABASE_SITE_URL).
--prompts          Print a copy-paste fix prompt for each problem (Cursor,
                   Lovable, Bolt, Claude Code).
--fix-sql <file>   Write a DRAFT fix migration (mechanical fixes as SQL,
                   decisions as commented TODOs). Review before applying.
--sarif <file>     Also write a SARIF 2.1.0 log (GitHub code scanning).
--format github    Also print ::error / ::warning annotations.
--no-default-grants  (migrations) Don't emulate the pre-Oct-30 auto-grant.
--json             Print the result as JSON instead of a report.
-h, --help         Show help.
-v, --version      Show the version.
```

`airlock migrations [PATH...]` audits SQL migrations (default `supabase/migrations`) with no database.

The DB URL is optional when you pass `--site`: `airlock --site https://your-app.com`
runs the service-key scan on its own, with no database.

### Exit codes

| Code | Meaning                                             |
| ---- | --------------------------------------------------- |
| `0`  | Passed — no exposure found.                         |
| `1`  | Failed — at least one exposed table or permissive policy. |
| `2`  | Usage / connection error (bad args, no URL, DB unreachable). |

---

## Use it as a library

```js
import { audit } from 'airlock-rls'

const result = await audit({ dbUrl: process.env.SUPABASE_DB_URL, schema: 'public' })
if (!result.passed) {
  console.error(`${result.problems} problem(s)`)
  for (const f of result.findings.filter((f) => f.severity === 'fail')) {
    console.error(`  ✗ ${f.object} — ${f.detail}`)
  }
}
```

`audit()` returns:

```js
{
  schema,     // the audited schema
  findings,   // Finding[] — { kind, severity: 'fail'|'warn', object, detail }, fail-first
  allowed,    // Finding[] — permissive findings waved through by `allow`
  problems,   // number of severity 'fail' findings
  warnings,   // number of severity 'warn' findings
  passed,     // problems === 0
  tables,     // string[] — every table in the schema (used by the DAST pass)
}
```

It never exits the process — you decide how to report.

---

## What's free vs. paid

This gate (the CLI, the GitHub Action and the library) is free and MIT-licensed,
forever. For what a one-shot CI run can't cover, there is
[Airlock Monitor](https://shipsealed.com/#monitor): a hosted, scheduled run that
alerts you when a migration reopens a hole between CI runs. It has a free plan
(one project, weekly) and a paid one.

## Development

```bash
npm install
npm test        # unit tests, no database required
npm start -- --help
```

The audit logic (`src/audit.mjs`) is framework-free and split into a pure core
(`buildResult`, tested without a DB) and the thin `audit()` that talks to Postgres.

### Integration test (real Postgres)

`test/integration.test.mjs` runs the real `audit()` against a live database using
the fixtures in `test/fixtures/` (a leaky schema that must fail, a clean one that
must pass). It's **gated**: with no database URL it skips, so `npm test` stays
green offline. Point it at any Postgres to run it:

```bash
AIRLOCK_TEST_DB_URL=postgresql://postgres:postgres@127.0.0.1:5432/postgres npm test
```

In CI, the `integration` job in `.github/workflows/test.yml` stands up a Postgres
service container and runs it automatically.

## License

MIT © ZINGUI
