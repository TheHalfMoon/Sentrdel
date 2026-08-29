create function public.lookup_profile() returns text
language sql
security definer
as $$ select current_user::text $$;
grant execute on function public.lookup_profile() to authenticated;
