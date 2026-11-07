-- Every statement fails: the run must exit 2, never report "clean".
alter table public.ghost enable row level security;
create policy "x" on public.ghost for select using (true);
