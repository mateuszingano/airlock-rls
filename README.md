# Airlock RLS — the CI gate for Supabase

[![test](https://github.com/mateuszingano/airlock-rls/actions/workflows/test.yml/badge.svg)](https://github.com/mateuszingano/airlock-rls/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **Scanners check that a policy exists. Airlock proves it works — and blocks the merge if it doesn't.**

Airlock fails your CI when a table ships without Row Level Security, or when a
policy is **permissive** (`USING (true)` / `WITH CHECK (true)` — the always-true
rules that let every API role through and quietly defeat tenant isolation).

It's not another scanner you read a report from. It's a **gate**: the migration
doesn't reach production with an exposed table.

---

## Why this exists

The #1 Supabase security footgun is shipping a table to the `public` schema
with RLS off, or a policy that's technically present but logically wide open.
Native advisors and free scanners tell you *after the fact*. Airlock runs in CI
and **fails the build**, so the leak never merges.

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

**Warns (worth a review):**
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

**What it does NOT cover yet (declared, not silently missed):**
- **`FORCE ROW LEVEL SECURITY` is never read** — only `rowsecurity`. A table
  whose owner is reachable keeps a silent bypass.
- **`--site` does not defeat DNS rebinding.** Literal private, loopback,
  link-local and metadata addresses are refused (including their IPv4-mapped
  IPv6 spellings), and every fetch has a timeout and a body cap — but a hostname
  that *resolves* to a private address is not caught, because the check runs on
  the URL, not on the resolved socket.
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
- Custom database roles beyond `anon`/`authenticated`/`public` in a `USING(true)`
  policy — whether a custom role is client-reachable is undecidable statically.
- **`ALTER POLICY` is not read.** Airlock audits the policies as the database
  currently holds them (`pg_policies`), which is the end state — but if you are
  looking for a *migration-time* gate on a policy being loosened, that is
  `migration-guard`'s job, not this one.
- **A bare `--allow` name is refused when it is ambiguous.** Policy names are
  unique per table, not per schema, so `--allow public_read` is only applied when
  exactly one table carries that name. When two or more do, nothing is silenced
  and an `allow_ambiguous` warn tells you the qualified form to use. This is a
  deliberate refusal, not a miss.
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

---

## Use it as a GitHub Action (the gate)

Add your Supabase Postgres connection string as a repo secret named
`SUPABASE_DB_URL` (a read-only role is enough — the audit only reads
`pg_tables` and `pg_policies`), then drop this in
`.github/workflows/rls-gate.yml`:

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
| `allow`        | no       | `''`       | Comma-separated policy names that are permissive on purpose.       |
| `schema`       | no       | `public`   | Schema to audit.                                                   |
| `site`         | no       | `''`       | Deployed site URL to also scan for an exposed `service_role` key.  |
| `url`          | no       | `''`       | Supabase project URL. With `anon-key`, runs the DAST pass that **proves** exposure. |
| `anon-key`     | no       | `''`       | Public anon key for the DAST pass (public by design). Used with `url`. |
| `dast-write`   | no       | `false`    | Also probe anonymous INSERTs during DAST (safe — leaves no test data). |
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
--schema <name>    Schema to audit (default: public).
--url URL          Supabase project URL — enables the DAST pass ($SUPABASE_URL).
--anon-key VALUE   Public anon key for the DAST pass ($SUPABASE_ANON_KEY).
--dast-write       Also probe anonymous INSERTs (safe — leaves no test data).
--site URL         Deployed site URL — scan its HTML/JS for an exposed
                   service_role key. Needs no database ($SUPABASE_SITE_URL).
--json             Print the result as JSON instead of a report.
-h, --help         Show help.
-v, --version      Show the version.
```

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

Airlock is **open core**. This gate — the CLI and the GitHub Action — is free
and MIT-licensed, forever. Paid tiers (coming) add the pieces a one-shot CI run
can't cover:

- **Logic audit** — deeper policy analysis beyond always-true.
- **Continuous monitoring** — a scheduled run that alerts on *drift* when a new
  migration reopens a hole between CI runs.

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
