---
name: airlock-rls
description: Audit a Supabase app for data exposure with the airlock-rls CLI and fix what it finds. Use when asked to audit or review Supabase Row Level Security (RLS), "is my Supabase app leaking", "can users see each other's data", check a deployed site for an exposed service_role / sb_secret key or a downloadable .env / .git, fix Supabase Security Advisor warnings about RLS, policies, SECURITY DEFINER functions or public buckets, or add an RLS gate to CI.
---

# airlock-rls

`airlock-rls` is an MIT CLI that audits a Supabase project's Row Level Security from the
**live catalog** (policies, real grants, roles) and scans a deployed site for leaked secrets.
It exits `0` = passed, `1` = exposure found, `2` = usage / connection error. Always run it
with `--json` so you can read the findings, and use `npx -y airlock-rls@latest`.

## 1. Pick the mode

| What you have | Command | Needs |
|---|---|---|
| Only the deployed URL | `npx -y airlock-rls@latest --site https://app.example.com --json` | Nothing else. Reads the page, its JS bundles, `/.env`, `/.git/HEAD` and source maps. |
| The repo, with `supabase/migrations/` (no DB access) | `npx -y airlock-rls@latest migrations --json` (or `migrations <path>`) | Nothing secret. Replays the SQL into an embedded Postgres (first run downloads ~27 MB once) and runs the same audit; findings carry `file` and `line`. Can't see grants made by hand in the dashboard: say so. |
| The database connection string | `npx -y airlock-rls@latest --json` (reads `$SUPABASE_DB_URL`) | Postgres URL: Supabase dashboard, Connect, connection string. |
| DB URL + project URL + anon key | add `--url "$SUPABASE_URL" --anon-key "$SUPABASE_ANON_KEY"` | Also runs DAST: actually reads each table with the anon key and proves anonymous leaks. |
| Both site and DB | combine `--site <url>` with the DB run | |

Start with `--site` when the user only gave a URL. In a repo that has `supabase/migrations/`,
start with the `migrations` mode: it needs no credentials. Offer the live DB audit for the
deployed database: a site scan cannot see policies, and migrations can drift from production.

**The connection string is a secret.** Never print it, echo it, paste it into a command
line that will be shown, or write it to a file in the repo. Read it from the environment
(`SUPABASE_DB_URL`, which the CLI reads by itself). If it isn't set, ask the user to set it
in their shell; don't ask them to paste it into the chat. Never ask for the service_role key:
the CLI does not need it.

Other options that exist (don't invent more; run `npx -y airlock-rls@latest --help` if unsure):
`--schema <name>` (default `public`), `--allow <names>`, `--fail-on fail|warn`, `--strict`
(= `--fail-on warn`), `--dast-write`, `--max-scripts <n>`, `--prompts` (human-readable fix
prompts; `--json` already includes them), `--fix-sql <file>` (a draft migration: real SQL for
mechanical fixes, TODO templates for the rest; review it with the user before applying),
`--sarif <file>`, `--format github`, `--no-default-grants` (migrations mode).

## 2. Read the result

The JSON has `findings[]`, each `{ kind, severity, object, detail, fixPrompt? }`, plus
`passed`, `gatePassed`, `problems` (fail count) and `warnings` (warn count). A site scan adds
`siteScan: { url, scanned, publicKeyFound }`.

- **`severity: "fail"`** is an exposure: fix it.
- **`severity: "warn"`** needs a human look: it may be intentional (a public catalogue) or a
  leak the static scan can't prove (`or_branch_unscoped`, `helper_scoped`,
  `authenticated_unscoped`). Ask the user about the data before calling it a leak.
- `siteScan.publicKeyFound: true` is normal (the anon/publishable key is public by design).
  It means RLS is the only lock, so suggest the DB audit if it hasn't run.
- What each `kind` means: [references/finding-kinds.md](references/finding-kinds.md).

## 3. Fix

1. For each fail (then each confirmed warn), use the finding's **`fixPrompt`**: it states the
   object, what was found and the change to make. Turn it into a SQL migration in the
   project's migrations folder (e.g. `supabase/migrations/<timestamp>_fix_rls.sql`).
2. **Show the SQL to the user and explain each statement before applying anything.** Do not
   run it against a database without their explicit OK.
3. Hard rules:
   - Never "fix" a finding by disabling RLS, by adding a policy `USING (true)` /
     `WITH CHECK (true)`, or by granting everything to `anon`.
   - Scope rows to the owner or tenant, e.g. `(select auth.uid()) = user_id`.
   - Never weaken a policy to make an error (`42501`) go away without saying so.
   - Rotate any secret a site scan found (service key, `.env` contents): it is already public.
4. If something is **intentionally** public, waive it explicitly instead of hiding it:
   `--allow table.policy` for a policy (prefer the qualified form), or the namespaced form the
   finding prints for other objects: `storage:<bucket>`, `view:<name>`, `matview:<name>`,
   `fn:<name>`, `realtime:<table>`, `role:<name>`, `table:<name>`. Also read from
   `$RLS_AUDIT_ALLOW`. An entry that matches nothing raises `allow_unused`.
5. **Re-run the same command** and confirm the finding is gone and the exit code is `0`.

## 4. Gate it in CI (optional)

GitHub Action:

```yaml
- uses: mateuszingano/airlock-rls@v1
  with:
    db-url: ${{ secrets.SUPABASE_DB_URL }}
```

Or any CI: `npx -y airlock-rls@latest` with `SUPABASE_DB_URL` as a secret; exit `1` fails the
build. Check the README for the current Action inputs before writing the workflow:
https://github.com/mateuszingano/airlock-rls

## Limits (say them, don't overclaim)

- A clean DB audit means none of the checked patterns were found; it is not a proof of
  security. Helper functions are opaque to the static scan (`helper_scoped`).
- A site scan sees only what a visitor's browser downloads; it never sees policies.
- An empty table can't leak rows in DAST, so a static fail on it stays a fail.
