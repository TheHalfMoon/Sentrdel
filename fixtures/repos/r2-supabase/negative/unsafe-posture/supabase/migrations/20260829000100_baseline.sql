create table public.profiles (
    id uuid primary key,
    owner_id uuid not null
);

alter table public.profiles disable row level security;
grant select, insert, update, delete on table public.profiles to anon, authenticated;

create policy profiles_open
on public.profiles
for all
to public
using (true)
with check (true);

create or replace function public.admin_lookup()
returns text
language sql
security definer
as $$
    select 'fixture';
$$;

grant execute on function public.admin_lookup() to anon;

create table storage.objects_fixture (
    id uuid primary key,
    owner_id uuid
);
alter table storage.objects_fixture enable row level security;
create policy storage_open
on storage.objects_fixture
for all
to public
using (true)
with check (true);
