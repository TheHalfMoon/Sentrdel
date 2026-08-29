create table public.accounts (
    id bigint primary key,
    owner_id uuid not null
);

alter table public.accounts enable row level security;

create policy accounts_select_own
on public.accounts
for select
to authenticated
using (owner_id = auth.uid());

revoke all on table public.accounts from anon;
grant select on table public.accounts to authenticated;

create or replace function private.current_account_id()
returns bigint
language sql
security definer
set search_path = ''
as $$
    select 1::bigint;
$$;

revoke all on function private.current_account_id() from public;
grant execute on function private.current_account_id() to authenticated;

create table storage.objects_fixture (
    id uuid primary key,
    owner_id uuid not null
);

alter table storage.objects_fixture enable row level security;
create policy storage_owner_select
on storage.objects_fixture
for select
to authenticated
using (owner_id = auth.uid());
