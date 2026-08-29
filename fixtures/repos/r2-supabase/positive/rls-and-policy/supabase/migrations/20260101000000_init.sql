create table public.accounts (id uuid primary key, owner_id uuid not null);
alter table public.accounts enable row level security;
create policy account_owner_read on public.accounts for select using (auth.uid() = owner_id);
grant select on public.accounts to authenticated;
