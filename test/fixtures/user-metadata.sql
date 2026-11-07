-- Fixture: policies that decide access from user_metadata (user-editable)
-- versus app_metadata (server-only). Rule: policy_trusts_user_metadata.

do $$ begin
  if not exists (select from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
end $$;

-- What a bare Postgres lacks and a Supabase DB has: auth.uid(), auth.jwt(), auth.users.
-- Created only when missing: node --test runs test files in parallel and the
-- other fixtures `create or replace` auth.uid() at the same moment, which makes
-- an unconditional replace here fail with "tuple concurrently updated".
create schema if not exists auth;
do $$ begin
  if to_regprocedure('auth.uid()') is null then
    create function auth.uid() returns uuid language sql stable as
      'select nullif(current_setting(''request.jwt.claim.sub'', true), '''')::uuid';
  end if;
  if to_regprocedure('auth.jwt()') is null then
    create function auth.jwt() returns jsonb language sql stable as
      'select coalesce(nullif(current_setting(''request.jwt.claims'', true), ''''), ''{}'')::jsonb';
  end if;
  if to_regclass('auth.users') is null then
    create table auth.users (id uuid primary key);
  end if;
end $$;
alter table auth.users add column if not exists raw_user_meta_data jsonb;
alter table auth.users add column if not exists raw_app_meta_data jsonb;

drop schema if exists usermeta cascade;
create schema usermeta;
grant usage on schema usermeta to anon, authenticated;

-- FAIL: admin gate from the JWT user_metadata claim.
create table usermeta.admin_notes (id bigint primary key, body text);
alter table usermeta.admin_notes enable row level security;
create policy "admins read" on usermeta.admin_notes for select to authenticated
  using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');

-- FAIL: tenant id from user_metadata. Looks scoped (caller token = row column),
-- so it passed green before this rule.
create table usermeta.tenant_docs (id bigint primary key, org_id uuid, body text);
alter table usermeta.tenant_docs enable row level security;
create policy "tenant read" on usermeta.tenant_docs for select to authenticated
  using (org_id = ((auth.jwt() -> 'user_metadata' ->> 'org_id'))::uuid);

-- FAIL: admin check through auth.users.raw_user_meta_data, in a subquery.
create table usermeta.reports (id bigint primary key, body text);
alter table usermeta.reports enable row level security;
create policy "admin via users" on usermeta.reports for update to authenticated
  using (exists (select 1 from auth.users u
                 where u.id = auth.uid() and (u.raw_user_meta_data ->> 'role') = 'admin'))
  with check (exists (select 1 from auth.users u
                 where u.id = auth.uid() and (u.raw_user_meta_data ->> 'role') = 'admin'));

-- WARN: a RESTRICTIVE narrowing that trusts user_metadata (bypassable).
create table usermeta.billing (id bigint primary key, user_id uuid);
alter table usermeta.billing enable row level security;
create policy "own billing" on usermeta.billing for select to authenticated using (user_id = auth.uid());
create policy "paid only" on usermeta.billing as restrictive for select to authenticated
  using ((auth.jwt() -> 'user_metadata' ->> 'plan') = 'pro');

-- CONTROL (quiet for this rule): app_metadata is server-only.
create table usermeta.app_docs (id bigint primary key, org_id uuid);
alter table usermeta.app_docs enable row level security;
create policy "tenant via app_metadata" on usermeta.app_docs for select to authenticated
  using (org_id = ((auth.jwt() -> 'app_metadata' ->> 'org_id'))::uuid);

-- CONTROL: the words only inside a string literal, policy scoped to the owner.
create table usermeta.notes (id bigint primary key, owner uuid, note text);
alter table usermeta.notes enable row level security;
create policy "own notes" on usermeta.notes for select to authenticated
  using (owner = auth.uid() and note <> 'user_metadata');

-- CONTROL: a policy only TO anon (an anon token has no user_metadata to edit).
create table usermeta.anon_only (id bigint primary key);
alter table usermeta.anon_only enable row level security;
create policy "anon meta" on usermeta.anon_only for select to anon
  using ((auth.jwt() -> 'user_metadata' ->> 'x') = 'y');

grant select, update on all tables in schema usermeta to authenticated;
grant select on all tables in schema usermeta to anon;

-- WARN: client-callable definer helper reading raw_user_meta_data.
create function usermeta.is_admin() returns boolean language sql stable
  security definer set search_path = '' as
  $$ select coalesce((select (u.raw_user_meta_data ->> 'role') = 'admin' from auth.users u where u.id = auth.uid()), false) $$;
grant execute on function usermeta.is_admin() to authenticated;

-- CONTROL: definer body that only MENTIONS it in a comment, reads app_metadata.
create function usermeta.is_admin_safe() returns boolean language plpgsql stable
  security definer set search_path = '' as
  $$ begin
    -- never read raw_user_meta_data here: users can edit it
    return coalesce((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false);
  end $$;
grant execute on function usermeta.is_admin_safe() to authenticated;
