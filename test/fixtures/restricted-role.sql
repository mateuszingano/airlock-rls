-- C1 regression fixture: a least-privilege audit role that is NOT a member of
-- anon/authenticated — exactly what the README tells the user to use, and
-- exactly the role that made role_table_grants return zero rows and turn the
-- gate green on a live leak.
--
-- The Supabase client roles (anon/authenticated exist on a real Supabase DB but
-- not on a bare Postgres) are created here so the fixture is self-contained.
do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then
    create role anon nologin;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then
    create role authenticated nologin;
  end if;
end $$;

-- The restricted auditor: can log in and read the catalog, but is NOT a member
-- of anon/authenticated and did not grant any of the policies below.
-- Idempotent teardown: a role holding grants cannot be dropped directly, so
-- strip everything it owns/was-granted first (needed on re-runs).
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'airlock_restricted') then
    execute 'drop owned by airlock_restricted';
    drop role airlock_restricted;
  end if;
end $$;
create role airlock_restricted login password 'restricted';
grant connect on database postgres to airlock_restricted;
grant usage on schema app to airlock_restricted;
-- read-only visibility on the tables themselves (does not grant it anon's rights)
grant select on all tables in schema app to airlock_restricted;
