-- A platform extension the embedded Postgres can't load: skipped and counted.
create extension if not exists pg_net with schema extensions;

-- PLANTED: SECURITY DEFINER, callable by anon (PUBLIC execute), no search_path
create or replace function public.grant_credits(target uuid, amount int)
returns void
language plpgsql
security definer
as $$
begin
  update public.profiles set full_name = full_name where id = target; -- ; inside a body
end;
$$;

-- PLANTED: public bucket
insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);

-- PLANTED: realtime on a table anon can read
alter publication supabase_realtime add table public.notes;

-- Uses a platform helper that the bootstrap stubs: must load.
select cron.schedule('nightly', '0 3 * * *', 'select 1');

-- PLANTED load failure: the table does not exist, so this must be reported,
-- never silently dropped.
alter table public.does_not_exist enable row level security;
