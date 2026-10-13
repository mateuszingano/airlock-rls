-- Fixture: exposure through COLUMN grants (13/10/26).
--
-- `grant select (id, card) on t to anon` never shows up in has_table_privilege(),
-- but PostgREST serves those columns. Before the fix, a USING (true) policy
-- behind a column grant audited clean while anon read the card numbers, and a
-- matview granted by column audited clean too.

do $$ begin
  if not exists (select from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
end $$;

drop schema if exists colgrant cascade;
create schema colgrant;
grant usage on schema colgrant to anon, authenticated;

-- LEAK: RLS on, policy always true, anon reaches it only through a column grant.
create table colgrant.cards (id bigint primary key, card text not null);
alter table colgrant.cards enable row level security;
create policy "read all" on colgrant.cards for select to anon using (true);
grant select (id, card) on colgrant.cards to anon;

-- LEAK: a matview (no RLS at all) granted to anon by column.
create materialized view colgrant.cards_dump as select id, card from colgrant.cards;
grant select (id, card) on colgrant.cards_dump to anon;
