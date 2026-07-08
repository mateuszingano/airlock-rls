-- Fixture: a schema that MUST PASS the audit (no fail-severity findings).
--
-- Every table has RLS on and a policy scoped to the caller. There may be
-- informational warnings, but zero `problems` - the gate should exit 0.

do $$ begin
  if not exists (select from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
end $$;

drop schema if exists clean_app cascade;
create schema clean_app;
grant usage on schema clean_app to anon, authenticated;

create schema if not exists auth;
create or replace function auth.uid() returns uuid language sql stable as
  $fn$ select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $fn$;

-- Scoped-by-user table: RLS on, policy ties every read to auth.uid().
create table clean_app.orders (
  id bigint generated always as identity primary key,
  user_id uuid not null,
  total_cents int not null
);
alter table clean_app.orders enable row level security;
grant select, insert, update on clean_app.orders to authenticated;
create policy "own orders read" on clean_app.orders for select to authenticated using (user_id = auth.uid());
create policy "own orders write" on clean_app.orders for insert to authenticated with check (user_id = auth.uid());

-- Table with RLS on and NO policy at all: default-deny, so nothing is exposed.
create table clean_app.audit_log (
  id bigint generated always as identity primary key,
  event text
);
alter table clean_app.audit_log enable row level security;
-- no grants to anon/authenticated, no policies -> locked down.
