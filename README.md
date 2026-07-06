# Airlock RLS — the CI gate for Supabase

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

1. **Tables with RLS disabled** in the target schema — every row exposed to the API roles.
2. **Permissive policies** — `USING (true)` or `WITH CHECK (true)`, which bypass isolation.

Intentionally-public policies (a status page, say) can be waved through with an
allow-list, so the gate stays honest without crying wolf.

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
      - uses: SEU_USUARIO/airlock@v1
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
--allow <names>    Policy names to treat as intentionally permissive
                   (also read from $RLS_AUDIT_ALLOW).
--schema <name>    Schema to audit (default: public).
--json             Print the result as JSON instead of a report.
-h, --help         Show help.
-v, --version      Show the version.
```

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
  console.error(`${result.problems} issue(s)`, result.tablesWithoutRls, result.permissive)
}
```

`audit()` returns `{ schema, tablesWithoutRls, permissive, allowed, problems, passed }`
and never exits the process — you decide how to report.

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

## License

MIT © ZINGUI
