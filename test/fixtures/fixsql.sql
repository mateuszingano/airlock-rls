-- Fixture: --fix-sql round-trip. One of each finding the draft migration fixes
-- mechanically, plus one it must leave as a TODO (a USING (true) policy), all
-- under hostile names: a schema with a space and uppercase, and identifiers
-- carrying double quotes, single quotes and spaces. If quoting is wrong the
-- generated SQL fails to apply.

do $$ begin
  if not exists (select from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
end $$;

drop schema if exists "Fix Me" cascade;
create schema "Fix Me";
grant usage on schema "Fix Me" to anon, authenticated;

-- rls_disabled (mechanical: enable RLS)
create table "Fix Me"."Pay ""Out""" (id bigint primary key, user_id uuid);
grant select on "Fix Me"."Pay ""Out""" to anon, authenticated;

-- permissive_true (TODO only: never rewritten automatically)
create table "Fix Me".notes (id bigint primary key, owner uuid);
alter table "Fix Me".notes enable row level security;
grant select on "Fix Me".notes to anon, authenticated;
create policy "say ""hi"" to all" on "Fix Me".notes for select to anon using (true);

-- anon_executes_definer + definer_search_path_mutable (mechanical: revoke + pin)
create function "Fix Me"."Leak""Fn"() returns int language sql security definer as $$ select 1 $$;
grant execute on function "Fix Me"."Leak""Fn"() to anon;

-- view_bypasses_rls (mechanical: security_invoker)
create view "Fix Me"."Open View" as select id from "Fix Me".notes;
grant select on "Fix Me"."Open View" to anon, authenticated;

-- matview_exposed (mechanical: revoke)
create materialized view "Fix Me"."It's a Dump" as select id from "Fix Me".notes;
grant select on "Fix Me"."It's a Dump" to anon;

-- owner_bypasses_rls (mechanical: force RLS)
create table "Fix Me"."Owned By Authed" (id bigint primary key);
alter table "Fix Me"."Owned By Authed" enable row level security;
alter table "Fix Me"."Owned By Authed" owner to authenticated;
