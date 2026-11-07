-- Fixture: default_privileges_to_api_roles (07/11/26). The latent footprint of
-- silencing the post-Oct-30 42501 errors with ALTER DEFAULT PRIVILEGES.
do $$ begin
  if not exists (select from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
  if not exists (select from pg_roles where rolname = 'supabase_admin') then create role supabase_admin nologin; end if;
end $$;

drop schema if exists lazygrant cascade;
create schema lazygrant;
grant usage on schema lazygrant to anon, authenticated;
create table lazygrant.notes (id bigint primary key);
alter table lazygrant.notes enable row level security;

-- The lazy fix: every future table postgres creates here is handed to the API.
alter default privileges for role postgres in schema lazygrant grant all on tables to anon, authenticated;
-- The platform's own defaults: must NOT be flagged.
alter default privileges for role supabase_admin in schema lazygrant grant select on tables to anon;

-- A schema with no such defaults: must stay silent.
drop schema if exists lazyclean cascade;
create schema lazyclean;
create table lazyclean.notes (id bigint primary key);
alter table lazyclean.notes enable row level security;
