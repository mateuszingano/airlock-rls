# airlock-rls finding kinds

Generated from `src/audit.mjs`, `src/dast.mjs` and `src/service-role.mjs` (v0.5.1). Severity is
the default; `--fail-on warn` makes warns break the build too. A `storage_` prefix (e.g.
`storage_permissive_true`) means the same rule fired on a Supabase Storage policy on
`storage.objects`.

## Fail (exposure)

| kind | Meaning |
|---|---|
| `rls_disabled` | A table the API roles can reach has RLS off: every row is exposed. |
| `policy_trusts_user_metadata` | A policy decides access from `user_metadata` (`auth.jwt() -> 'user_metadata'` or `auth.users.raw_user_meta_data`), which every user can edit with `auth.updateUser()`. Warn instead when only a restrictive policy or a SECURITY DEFINER body reads it. Fix: move the value to `app_metadata` or a table users can't write. |
| `permissive_true` | A policy is `USING (true)` / `WITH CHECK (true)` or reduces to always-true (`auth.uid() = x OR 1=1`, `owner_id = owner_id`). |
| `anon_unscoped` | An anon-readable policy that doesn't scope to the user: everyone reads every row. |
| `write_unscoped` | An INSERT/UPDATE whose `WITH CHECK` doesn't tie the new row to the caller: anyone can write rows as someone else. |
| `delete_unscoped` | A DELETE policy whose `USING` doesn't scope to the caller (fail for `authenticated` too). |
| `update_using_unscoped` | An UPDATE policy whose `USING` doesn't scope to the caller: any row can be targeted (fail for `authenticated` too). |
| `matview_exposed` | A materialized view a client role can read. RLS never applies to matviews. |
| `anon_read_leak` | DAST: a live request with the anon key returned rows. Proven, not inferred. |
| `anon_write_leak` | DAST (`--dast-write`): an anonymous INSERT was accepted. |
| `service_role_exposed` | A service key (`service_role` JWT or `sb_secret_...`) is in the site's HTML/JS or a source map. Bypasses all RLS; rotate it. |
| `env_file_exposed` | Site scan: `/.env` is downloadable. The finding counts variables, never shows values. Rotate every secret. |
| `git_exposed` | Site scan: `/.git/` is served publicly (source and full history). |
| `nothing_audited` | No tables or policies found in the schema: nothing was checked (wrong schema or URL?). |

## Warn (needs a human look)

| kind | Meaning |
|---|---|
| `or_branch_unscoped` | Scoped to `auth.uid()`, but an OR branch widens it in a way a static scan can't prove (`OR status = 'published'`). Maybe intended sharing, maybe a leak. |
| `authenticated_unscoped` | Any signed-in user reads all rows (role-only check). Usually a tenant leak. |
| `helper_scoped` | Read scoped only through a helper function the scan can't see inside. Verify it restricts the caller. |
| `write_unchecked` | An INSERT/UPDATE policy with no `WITH CHECK`. |
| `anon_write_inconclusive` | DAST: an anonymous INSERT hit a column constraint, not an RLS block. Verify by hand. |
| `public_bucket` | A public storage bucket: anyone with a file URL can download it. |
| `security_definer` | A SECURITY DEFINER function: runs as its owner and can bypass RLS. |
| `anon_executes_definer` | Anonymous visitors can call a SECURITY DEFINER function. |
| `definer_search_path_mutable` | A SECURITY DEFINER function without a pinned `search_path` (fix: `SET search_path = ''`). |
| `view_bypasses_rls` | A view that runs with its owner's rights, ignoring RLS underneath (fix: `security_invoker = true`). |
| `realtime_exposure` | A table published to Realtime whose rows are anon-readable: changes stream to anonymous listeners. |
| `bypassrls_role` | A role with BYPASSRLS/SUPERUSER outside the Supabase-managed set, or any bypass role the API caller can reach. |
| `owner_bypasses_rls` | A table owned by a client-reachable role without `FORCE ROW LEVEL SECURITY`. |
| `default_privileges_to_api_roles` | Default privileges hand every future table to anon/authenticated/PUBLIC (the post-Oct-30 "lazy fix"). Nothing leaks today; the next table without RLS will. Waive with `defaults:<owner>`. |
| `migrations_incomplete` | Migrations mode: some statements failed to load, so what they create was not audited. |
| `source_map_exposed` | Site scan: public source maps expose the original source code. |
| `scan_truncated` | Site scan read only the first N bundles; raise `--max-scripts`. |
| `check_skipped` | A check couldn't run (e.g. missing catalog access); the report says which. |

## Allow-list bookkeeping (warn)

| kind | Meaning |
|---|---|
| `allow_ambiguous` | A bare `--allow` name matches policies on more than one table; use `table.policy`. |
| `allow_needs_namespace` | A bare name would match a non-policy object; use `storage:`, `view:`, `matview:`, `fn:`, `realtime:`, `role:` or `table:`. Nothing was waived. |
| `allow_unused` | An `--allow` entry matched nothing. |
