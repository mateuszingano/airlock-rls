# Docs snippet: `--fix-sql` (for README + CHANGELOG, merged by the parent)

## README — new subsection (after "Copy-paste fix prompts")

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

## README — options block line

```
--fix-sql <file>   Write a DRAFT fix migration (mechanical fixes as SQL,
                   decisions as commented TODOs). Review before applying.
```

## CHANGELOG entry

- **`--fix-sql <file>`: a draft fix migration.** Real SQL for the fixes whose
  effect is fully determined by the finding (enable RLS, revoke a grant, pin a
  search_path, `security_invoker` on a view, make a bucket private, `FORCE ROW
  LEVEL SECURITY`), each with a note on what it can break; commented TODO
  templates for anything that needs a decision. Policies are never rewritten
  automatically. Proven by a round-trip test on a real Postgres with hostile
  identifiers: the draft applies cleanly and every mechanical finding is gone.
