do $$
begin
    execute 'alter table public.dynamic_target disable row level security';
end;
$$;

-- Dynamic SQL is security-relevant but outside the supported R2 semantic subset.
