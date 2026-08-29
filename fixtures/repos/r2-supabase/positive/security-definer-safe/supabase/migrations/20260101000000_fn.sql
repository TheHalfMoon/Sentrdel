create function public.current_account_id() returns uuid
language sql
security definer
set search_path = pg_catalog, public
as $$ select auth.uid() $$;
revoke execute on function public.current_account_id() from public;
grant execute on function public.current_account_id() to authenticated;
