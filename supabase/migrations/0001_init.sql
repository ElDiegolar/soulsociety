-- soulsociety: zero-knowledge soul hosting. The host stores ciphertext only.
-- Apply with: supabase db push   (or psql -f on a plain Postgres with an `auth.users` table and auth.uid())

create extension if not exists pgcrypto;

-- ---------- tables ----------

create table if not exists public.souls (
  id                  uuid primary key default gen_random_uuid(),
  owner               uuid not null references auth.users(id) on delete cascade,
  name                text not null check (char_length(name) between 1 and 80),
  salt                bytea not null check (octet_length(salt) = 16),
  wrapped_dk_owner    bytea not null,
  wrapped_dk_recovery bytea not null,
  dk_version          int  not null default 1 check (dk_version >= 1),
  created_at          timestamptz not null default now()
);
create index if not exists souls_owner_idx on public.souls(owner);

create table if not exists public.devices (
  id          uuid primary key default gen_random_uuid(),
  soul_id     uuid not null references public.souls(id) on delete cascade,
  label       text not null check (char_length(label) <= 80),
  pubkey      bytea not null check (octet_length(pubkey) = 32),
  sealed_dks  jsonb not null default '{}'::jsonb,   -- {"<dk_version>": "<base64 sealed box>"}
  approved_at timestamptz,
  revoked_at  timestamptz,
  created_at  timestamptz not null default now()
);
create index if not exists devices_soul_idx on public.devices(soul_id);

create table if not exists public.events (
  soul_id     uuid not null references public.souls(id) on delete cascade,
  device_id   uuid not null references public.devices(id),
  seq         bigint not null check (seq >= 1),
  dk_version  int not null check (dk_version >= 1),
  nonce       bytea not null check (octet_length(nonce) = 24),
  ciphertext  bytea not null check (octet_length(ciphertext) between 17 and 262144),
  created_at  timestamptz not null default now(),
  primary key (device_id, seq)
);
create index if not exists events_soul_created_idx on public.events(soul_id, created_at);

create table if not exists public.snapshots (
  id          bigint generated always as identity primary key,
  soul_id     uuid not null references public.souls(id) on delete cascade,
  device_id   uuid not null references public.devices(id),
  through     jsonb not null,
  replay_hash text not null check (replay_hash ~ '^[0-9a-f]{64}$'),
  dk_version  int not null,
  nonce       bytea not null check (octet_length(nonce) = 24),
  ciphertext  bytea not null check (octet_length(ciphertext) <= 4194304),
  created_at  timestamptz not null default now()
);
create index if not exists snapshots_soul_created_idx on public.snapshots(soul_id, created_at desc);

create table if not exists public.harness_grants (
  id          uuid primary key default gen_random_uuid(),
  soul_id     uuid not null references public.souls(id) on delete cascade,
  label       text not null check (char_length(label) <= 80),
  scopes      text[] not null check (scopes <@ array['events:read','events:append','snapshots:read','snapshots:write','state:read']::text[]),
  token_hash  bytea not null unique check (octet_length(token_hash) = 32),
  expires_at  timestamptz,
  revoked_at  timestamptz,
  created_at  timestamptz not null default now()
);
create index if not exists grants_soul_idx on public.harness_grants(soul_id);

-- ---------- helpers ----------

create or replace function public.owns_soul(p_soul uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.souls s where s.id = p_soul and s.owner = auth.uid());
$$;

-- ---------- RLS ----------

alter table public.souls          enable row level security;
alter table public.devices        enable row level security;
alter table public.events         enable row level security;
alter table public.snapshots      enable row level security;
alter table public.harness_grants enable row level security;

drop policy if exists souls_owner on public.souls;
create policy souls_owner on public.souls
  for all using (owner = auth.uid()) with check (owner = auth.uid());

drop policy if exists devices_owner on public.devices;
create policy devices_owner on public.devices
  for all using (public.owns_soul(soul_id)) with check (public.owns_soul(soul_id));

drop policy if exists events_owner_read on public.events;
create policy events_owner_read on public.events
  for select using (public.owns_soul(soul_id));
-- no insert/update/delete policy on events: writes go through events_append() only.

drop policy if exists snapshots_owner on public.snapshots;
create policy snapshots_owner on public.snapshots
  for all using (public.owns_soul(soul_id)) with check (public.owns_soul(soul_id));

drop policy if exists grants_owner on public.harness_grants;
create policy grants_owner on public.harness_grants
  for all using (public.owns_soul(soul_id)) with check (public.owns_soul(soul_id));

-- ---------- immutability guards ----------

create or replace function public.forbid_mutation() returns trigger
language plpgsql as $$
begin
  raise exception 'events are append-only' using errcode = '42501';
end $$;

drop trigger if exists events_no_update on public.events;
create trigger events_no_update before update or delete on public.events
  for each row execute function public.forbid_mutation();

-- revoked_at and approved_at are monotonic
create or replace function public.devices_guard() returns trigger
language plpgsql as $$
begin
  if old.revoked_at is not null and new.revoked_at is distinct from old.revoked_at then
    raise exception 'device already revoked' using errcode = '42501';
  end if;
  if old.approved_at is not null and new.approved_at is distinct from old.approved_at then
    raise exception 'approved_at is immutable' using errcode = '42501';
  end if;
  if new.pubkey is distinct from old.pubkey then
    raise exception 'pubkey is immutable' using errcode = '42501';
  end if;
  return new;
end $$;

drop trigger if exists devices_guard_tg on public.devices;
create trigger devices_guard_tg before update on public.devices
  for each row execute function public.devices_guard();

-- ---------- RPCs ----------

-- Per-device heads for a soul.
create or replace function public.soul_heads(p_soul uuid)
returns table (device_id uuid, head bigint)
language sql stable security invoker as $$
  select e.device_id, max(e.seq) from public.events e where e.soul_id = p_soul group by e.device_id;
$$;

-- Atomic append of a batch. Validates: device belongs to soul, approved, not revoked, seq = head+1 with no gaps or dups.
-- security definer: events has no insert policy (writes must come through here), so the function itself must be able
-- to insert; it enforces ownership (owns_soul / service_role) and device state before every row.
create or replace function public.events_append(p_events jsonb)
returns int
language plpgsql security definer set search_path = public as $$
declare
  r record;
  v_head bigint;
  v_count int := 0;
begin
  if jsonb_typeof(p_events) <> 'array' then raise exception 'p_events must be an array'; end if;

  -- lock the devices involved to serialise concurrent appends per device
  perform 1 from public.devices d
   where d.id in (select (x->>'device_id')::uuid from jsonb_array_elements(p_events) x)
   for update;

  for r in
    select (x->>'soul_id')::uuid as soul_id,
           (x->>'device_id')::uuid as device_id,
           (x->>'seq')::bigint as seq,
           (x->>'dk_version')::int as dk_version,
           decode(x->>'nonce','base64') as nonce,
           decode(x->>'ciphertext','base64') as ciphertext
      from jsonb_array_elements(p_events) x
     order by (x->>'device_id'), (x->>'seq')::bigint
  loop
    if not public.owns_soul(r.soul_id) and current_setting('request.jwt.claim.role', true) is distinct from 'service_role' then
      raise exception 'forbidden' using errcode = '42501';
    end if;
    if not exists (select 1 from public.devices d where d.id = r.device_id and d.soul_id = r.soul_id and d.approved_at is not null and d.revoked_at is null) then
      raise exception 'device not approved for soul' using errcode = '42501';
    end if;
    select coalesce(max(seq),0) into v_head from public.events where device_id = r.device_id;
    if r.seq <= v_head then
      raise exception 'duplicate seq % for device %', r.seq, r.device_id using errcode = '23505';
    end if;
    if r.seq <> v_head + 1 then
      raise exception 'gap: have % got % for device %', v_head, r.seq, r.device_id using errcode = 'P0001';
    end if;
    insert into public.events(soul_id, device_id, seq, dk_version, nonce, ciphertext)
    values (r.soul_id, r.device_id, r.seq, r.dk_version, r.nonce, r.ciphertext);
    v_count := v_count + 1;
  end loop;
  return v_count;
end $$;

-- Events after a per-device vector of heads. p_since = {"<device_id>": <seq>, ...}; missing devices start at 0.
create or replace function public.events_since(p_soul uuid, p_since jsonb, p_limit int default 1000)
returns setof public.events
language sql stable security invoker as $$
  select e.* from public.events e
   where e.soul_id = p_soul
     and e.seq > coalesce((p_since ->> e.device_id::text)::bigint, 0)
   order by e.created_at, e.device_id, e.seq
   limit least(greatest(p_limit,1), 5000);
$$;

-- Merge sealed DKs into a device and mark approved (idempotent).
create or replace function public.device_approve(p_device uuid, p_sealed jsonb)
returns void
language plpgsql security invoker as $$
begin
  update public.devices
     set sealed_dks = sealed_dks || p_sealed,
         approved_at = coalesce(approved_at, now())
   where id = p_device and revoked_at is null;
  if not found then raise exception 'device not found or revoked' using errcode = '42501'; end if;
end $$;

-- Rotate owner/recovery wraps; version must increase.
create or replace function public.soul_rotate_keys(p_soul uuid, p_wrapped_owner bytea, p_wrapped_recovery bytea, p_dk_version int)
returns void
language plpgsql security invoker as $$
begin
  update public.souls
     set wrapped_dk_owner = p_wrapped_owner,
         wrapped_dk_recovery = p_wrapped_recovery,
         dk_version = p_dk_version
   where id = p_soul and p_dk_version > dk_version;
  if not found then raise exception 'rotate failed: not owner or version not increasing' using errcode = '23505'; end if;
end $$;

-- Gateway lookup. Service role only.
create or replace function public.grant_by_token_hash(p_hash bytea)
returns setof public.harness_grants
language sql stable security definer set search_path = public as $$
  select g.* from public.harness_grants g
   where g.token_hash = p_hash
     and current_setting('request.jwt.claim.role', true) = 'service_role';
$$;
revoke all on function public.grant_by_token_hash(bytea) from public, anon, authenticated;

-- Realtime: let owners subscribe to their events (ciphertext only).
do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    alter publication supabase_realtime add table public.events;
  end if;
exception when duplicate_object then null; end $$;
