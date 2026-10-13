-- Minimal stand-in for Supabase's auth schema + roles so 0001_init.sql applies on vanilla Postgres.
-- Test-only. Apply BEFORE the migration (see packages/core/test/pg.integration.test.ts).
create schema if not exists auth;
create table if not exists auth.users (id uuid primary key);

-- Supabase's auth.uid() reads the JWT `sub` claim from the request GUC.
create or replace function auth.uid() returns uuid
language sql stable as $$
  select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid;
$$;

do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role') then create role service_role nologin bypassrls; end if;
end $$;

grant usage on schema public, auth to anon, authenticated, service_role;
grant execute on function auth.uid() to anon, authenticated, service_role;

-- Grants on objects the migration creates: default privileges, applied to future objects in public.
alter default privileges in schema public grant select, insert, update on tables to authenticated;
alter default privileges in schema public grant usage, select on sequences to authenticated;
alter default privileges in schema public grant execute on functions to authenticated;
alter default privileges in schema public grant all on tables to service_role;
alter default privileges in schema public grant all on sequences to service_role;
alter default privileges in schema public grant execute on functions to service_role;
