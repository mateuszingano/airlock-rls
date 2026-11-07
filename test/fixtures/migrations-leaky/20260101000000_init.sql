-- Planted problems for the migrations mode. Shaped like what an AI app
-- builder exports: no GRANTs (relies on Supabase's default privileges),
-- BEGIN/COMMIT around the file, an extension in the extensions schema.
begin;

create extension if not exists "uuid-ossp" with schema extensions;

-- PLANTED: RLS never enabled -> rls_disabled
create table public.profiles (
  id uuid primary key references auth.users(id),
  full_name text,
  phone text
);

-- PLANTED: USING (true) -> permissive_true
create table public.notes (
  id uuid primary key default extensions.uuid_generate_v4(),
  owner_id uuid not null,
  body text
);
alter table public.notes enable row level security;
create policy "read all" on public.notes for select using (true);

-- Clean: owner-scoped
create table public.todos (
  id bigint generated always as identity primary key,
  user_id uuid not null default auth.uid(),
  title text
);
alter table public.todos enable row level security;
create policy "own todos" on public.todos for all
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

commit;
