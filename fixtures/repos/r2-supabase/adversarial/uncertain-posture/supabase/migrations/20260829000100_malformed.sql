create table public.broken (
    id bigint primary key,
    owner_id uuid not null
-- Intentionally malformed: missing closing parenthesis and semicolon.

alter table public.broken enable row level security;
