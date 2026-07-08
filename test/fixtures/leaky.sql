-- Fixture: a schema that MUST FAIL the audit.
--
-- Two independent leaks, plus one control table that is safe, so the audit has
-- to classify each correctly (not just "something is wrong").
--
-- Mirrors the Supabase setup: the API roles are `anon` (public) and
-- `authenticated` (logged-in). RLS only matters where those roles hold a GRANT,
-- so the fixture grants SELECT to anon exactly where a leak is intended.

-- Supabase ships these roles; a bare Postgres doesn't, so create them idempotently.
do $$ begin
  if not exists (select from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
end $$;

drop schema if exists app cascade;
create schema app;
grant usage on schema app to anon, authenticated;

-- LEAK 1: RLS disabled - every row exposed to the API roles.
create table app.payments (
  id bigint generated always as identity primary key,
  user_id uuid not null,
  amount_cents int not null
);
grant select on app.payments to anon, authenticated;
-- (no `alter table ... enable row level security` on purpose)

-- LEAK 2: RLS enabled but a permissive USING(true) policy readable by anon.
create table app.notes (
  id bigint generated always as identity primary key,
  owner uuid not null,
  body text
);
alter table app.notes enable row level security;
grant select on app.notes to anon, authenticated;
create policy "read all" on app.notes for select to anon using (true);

-- CONTROL (safe): RLS on + a policy scoped to the caller via auth.uid().
-- A real Supabase DB has auth.uid(); a bare Postgres doesn't, so define a
-- stand-in so the fixture loads and the policy is genuinely scoped.
create schema if not exists auth;
create or replace function auth.uid() returns uuid language sql stable as
  $fn$ select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $fn$;

create table app.profiles (
  id uuid primary key,
  display_name text
);
alter table app.profiles enable row level security;
grant select on app.profiles to authenticated;
create policy "own profile" on app.profiles for select to authenticated using (id = auth.uid());
