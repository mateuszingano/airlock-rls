# policy_trusts_user_metadata — text to merge into README and CHANGELOG

## README → "What it checks" → "Fails the build (exposure)"

- **`policy_trusts_user_metadata`** — a policy that decides access from
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

## CHANGELOG line

- **New rule `policy_trusts_user_metadata` (fail).** A policy that decides access
  from `user_metadata` (`auth.jwt() -> 'user_metadata'`, the path form, or
  `auth.users.raw_user_meta_data`) is satisfiable by any user, who can edit their
  own metadata with `auth.updateUser()`. The tenant shape
  `org_id = (auth.jwt()->'user_metadata'->>'org_id')::uuid` passed green before.
  Restrictive policies and client-callable SECURITY DEFINER bodies that read it
  are warns. `app_metadata` never fires. Fix prompt included (`--prompts`).
