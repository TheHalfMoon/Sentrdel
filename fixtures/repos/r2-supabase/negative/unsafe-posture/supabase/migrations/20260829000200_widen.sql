drop policy profiles_open on public.profiles;
create policy profiles_widened
on public.profiles
for all
to anon, authenticated
using (true)
with check (true);

grant execute on function public.admin_lookup() to authenticated;
