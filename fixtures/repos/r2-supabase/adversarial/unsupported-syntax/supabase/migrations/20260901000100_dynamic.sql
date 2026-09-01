-- Synthetic unsupported-security-relevant SQL. Data only; never execute.
DO $$
BEGIN
  EXECUTE 'ALTER TABLE public.accounts DISABLE ROW LEVEL SECURITY';
END
$$;
