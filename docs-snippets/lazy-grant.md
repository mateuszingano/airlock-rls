# default_privileges_to_api_roles (snippet for README + CHANGELOG)

## README — "What it checks" (warn list)

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

## CHANGELOG

- **`default_privileges_to_api_roles`** (warn): default privileges on tables
  that grant to `anon` / `authenticated` / `PUBLIC`, in the audited schema or in
  every schema — the latent footprint of silencing the post-Oct-30 42501 errors.
  Reads `pg_default_acl` (optional check: a role that cannot read it gets
  `check_skipped`). Supabase-managed owners are skipped. Waive with
  `defaults:<owner>`. Fix prompt included.
