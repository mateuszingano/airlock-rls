-- Manual-only companion to fixsql.sql: public_bucket round-trip. Not loaded by
-- the integration tests, because storage.buckets is global (not per schema) and
-- a public bucket would show up in every other test file running in parallel.

-- public_bucket (mechanical: make private). A minimal stand-in for Supabase's
-- storage.buckets, with a bucket id carrying both quote kinds.
create schema if not exists storage;
create table if not exists storage.buckets (id text primary key, name text, public boolean default false);
delete from storage.buckets where id like 'fixsql%';
insert into storage.buckets (id, name, public) values ('fixsql "ava''tars"', 'fixsql "ava''tars"', true);
