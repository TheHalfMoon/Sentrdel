create table public.accounts (id uuid primary key, owner_id uuid not null);
alter table public.accounts disable row level security;
grant select on public.accounts to anon, authenticated;
