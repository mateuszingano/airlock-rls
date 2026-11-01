-- Fixture: hardening checks (01/11/26) — search_path pinning, BYPASSRLS roles,
-- owner-bypass. Added after reviewing a competitor's audit coverage.

do $$ begin
  if not exists (select from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
end $$;

-- #2: a role OUTSIDE the Supabase-managed set that bypasses RLS entirely.
drop role if exists hardening_bypass;
create role hardening_bypass nologin bypassrls;

drop schema if exists hardening cascade;
create schema hardening;
grant usage on schema hardening to anon, authenticated;

-- #1a: SECURITY DEFINER function with NO pinned search_path → flagged.
create function hardening.mutable_fn() returns int language sql
  security definer as $$ select 1 $$;

-- #1b: SECURITY DEFINER function WITH a pinned search_path → NOT flagged.
create function hardening.pinned_fn() returns int language sql
  security definer set search_path = '' as $$ select 1 $$;

-- #3: a table owned by a client-reachable role, RLS on but not FORCEd → the
-- owner bypasses its own policies. RLS is left ON so this isolates the
-- owner-bypass warn (no rls_disabled fail in the way).
create table hardening.owned_by_authed (id bigint primary key);
alter table hardening.owned_by_authed enable row level security;
alter table hardening.owned_by_authed owner to authenticated;
