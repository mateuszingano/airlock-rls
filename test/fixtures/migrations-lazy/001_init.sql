create table public.notes (id uuid primary key, owner uuid);
alter table public.notes enable row level security;
create policy own on public.notes for select to authenticated using (owner = auth.uid());
