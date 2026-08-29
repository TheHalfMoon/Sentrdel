do $$
begin
  execute 'alter table public.accounts disable row level security';
end
$$;
