-- A clean schema: owner-scoped RLS, explicit grants, a definer function
-- closed to anon with a pinned search_path.
create table public.todos (
  id bigint generated always as identity primary key,
  user_id uuid not null default auth.uid(),
  title text
);
alter table public.todos enable row level security;
create policy "own todos" on public.todos for all to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);
revoke all on public.todos from anon;

create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = ''
as $$
begin
  return new;
end;
$$;
revoke execute on function public.handle_new_user() from public, anon, authenticated;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();
