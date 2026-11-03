-- Pro Smash Attendance: shared register on Supabase (free plan).
-- Everything lives in the private schema "ps". The app can only call public.api(),
-- which checks the academy code, the 4-digit PIN and a 12-hour session token.
-- Forgot the PIN?  Run:  select ps.reset_pin();   (Supabase dashboard → SQL editor)

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;
create schema if not exists ps;

create table if not exists ps.secrets (k text primary key, v text not null);
create table if not exists ps.settings (k text primary key, v jsonb not null);
create table if not exists ps.students (
  id text primary key, name text not null, batch text not null default '', parent_name text not null default '',
  phone text not null default '', joined text not null default '', removed boolean not null default false,
  updated timestamptz not null default now());
create table if not exists ps.attendance (date text primary key, marks jsonb not null default '{}'::jsonb, updated timestamptz not null default now());
create table if not exists ps.reports (month text primary key, notes jsonb not null default '{}'::jsonb, sent jsonb not null default '{}'::jsonb);
create table if not exists ps.fails (id int primary key default 1, cnt int not null default 0, since timestamptz not null default now());

alter table ps.secrets enable row level security;
alter table ps.settings enable row level security;
alter table ps.students enable row level security;
alter table ps.attendance enable row level security;
alter table ps.reports enable row level security;
alter table ps.fails enable row level security;

create or replace function ps.sec(key text) returns text language sql stable as $$ select v from ps.secrets where k = key $$;

create or replace function ps.make_token() returns text language plpgsql as $$
declare body text := (extract(epoch from now())::bigint + 12 * 3600)::text || '.' || coalesce(ps.sec('pin_ver'), '0');
begin
  return body || '.' || encode(extensions.hmac(body, ps.sec('token_secret'), 'sha256'), 'hex');
end $$;

create or replace function ps.check_token(t text) returns boolean language plpgsql as $$
declare p text[];
begin
  if t is null or ps.sec('token_secret') is null then return false; end if;
  p := string_to_array(t, '.');
  if coalesce(array_length(p, 1), 0) <> 3 or p[1] !~ '^\d{9,12}$' then return false; end if;
  if p[1]::bigint < extract(epoch from now())::bigint or p[2] <> coalesce(ps.sec('pin_ver'), '0') then return false; end if;
  return p[3] = encode(extensions.hmac(p[1] || '.' || p[2], ps.sec('token_secret'), 'sha256'), 'hex');
end $$;

create or replace function ps.new_pin(pin text) returns int language plpgsql as $$
declare ver int := coalesce(ps.sec('pin_ver'), '0')::int + 1;
begin
  insert into ps.secrets values ('pin_hash', extensions.crypt(pin, extensions.gen_salt('bf', 8))) on conflict (k) do update set v = excluded.v;
  insert into ps.secrets values ('pin_ver', ver::text) on conflict (k) do update set v = excluded.v;
  insert into ps.secrets values ('token_secret', encode(extensions.gen_random_bytes(32), 'hex')) on conflict (k) do update set v = excluded.v;
  return ver;
end $$;

create or replace function ps.reset_pin() returns text language plpgsql as $$
begin
  delete from ps.secrets where k in ('pin_hash', 'token_secret');
  insert into ps.secrets values ('pin_ver', (coalesce(ps.sec('pin_ver'), '0')::int + 1)::text) on conflict (k) do update set v = excluded.v;
  delete from ps.fails;
  return 'PIN removed. Open the app and create a new 4-digit PIN.';
end $$;

create or replace function ps.settings_obj() returns jsonb language sql stable as $$
  select jsonb_build_object(
    'academy', coalesce((select v #>> '{}' from ps.settings where k = 'academy'), 'Pro Smash Badminton Academy'),
    'batches', coalesce((select v from ps.settings where k = 'batches'),
      '[{"id":"b1","name":"Beginner","time":""},{"id":"b2","name":"Intermediate","time":""},{"id":"b3","name":"Advance 1","time":""},{"id":"b4","name":"Advance pro","time":""}]'::jsonb),
    'lang', coalesce((select v #>> '{}' from ps.settings where k = 'lang'), 'en'))
$$;

create or replace function ps.save_settings(d jsonb) returns void language plpgsql as $$
declare b jsonb := '[]'::jsonb; e jsonb;
begin
  if jsonb_typeof(d->'batches') = 'array' then
    for e in select * from jsonb_array_elements(d->'batches') limit 40 loop
      if coalesce(e->>'id', '') <> '' and btrim(coalesce(e->>'name', '')) <> '' then
        b := b || jsonb_build_array(jsonb_build_object('id', left(e->>'id', 40), 'name', left(btrim(e->>'name'), 60), 'time', left(coalesce(e->>'time', ''), 60)));
      end if;
    end loop;
  end if;
  insert into ps.settings values ('academy', to_jsonb(left(coalesce(nullif(btrim(d->>'academy'), ''), 'My academy'), 120))) on conflict (k) do update set v = excluded.v;
  insert into ps.settings values ('batches', b) on conflict (k) do update set v = excluded.v;
  insert into ps.settings values ('lang', to_jsonb(case when d->>'lang' = 'hi' then 'hi' else 'en' end)) on conflict (k) do update set v = excluded.v;
end $$;

create or replace function ps.save_students(list jsonb) returns int language plpgsql as $$
declare e jsonb; n int := 0;
begin
  if jsonb_typeof(list) <> 'array' then return 0; end if;
  for e in select * from jsonb_array_elements(list) limit 500 loop
    if coalesce(e->>'id', '') = '' or btrim(coalesce(e->>'name', '')) = '' then continue; end if;
    insert into ps.students (id, name, batch, parent_name, phone, joined, removed, updated)
    values (left(e->>'id', 40), left(btrim(e->>'name'), 100), left(coalesce(e->>'batch', ''), 40), left(coalesce(e->>'parentName', ''), 100),
            left(coalesce(e->>'phone', ''), 30), case when coalesce(e->>'joined', '') ~ '^\d{4}-\d{2}-\d{2}$' then e->>'joined' else '' end, false, now())
    on conflict (id) do update set name = excluded.name, batch = excluded.batch, parent_name = excluded.parent_name,
      phone = excluded.phone, joined = excluded.joined, removed = false, updated = now();
    n := n + 1;
  end loop;
  return n;
end $$;

create or replace function ps.apply_marks(cur jsonb, ch jsonb) returns jsonb language plpgsql immutable as $$
declare k text; val text; r jsonb := coalesce(cur, '{}'::jsonb);
begin
  if jsonb_typeof(ch) <> 'object' then return r; end if;
  for k, val in select key, value #>> '{}' from jsonb_each(ch) loop
    if val in ('P', 'A') then r := r || jsonb_build_object(left(k, 40), val); else r := r - k; end if;
  end loop;
  return r;
end $$;

create or replace function ps.snapshot(frm text) returns jsonb language sql stable as $$
  select ps.settings_obj() || jsonb_build_object(
    'students', coalesce((select jsonb_agg(jsonb_build_object('id', id, 'name', name, 'batch', batch, 'parentName', parent_name, 'phone', phone, 'joined', joined) order by name)
                          from ps.students where not removed), '[]'::jsonb),
    'att', coalesce((select jsonb_object_agg(date, marks) from ps.attendance where left(date, 7) >= frm), '{}'::jsonb),
    'notes', coalesce((select jsonb_object_agg(month, notes) from ps.reports where month >= frm), '{}'::jsonb),
    'sent', coalesce((select jsonb_object_agg(month, sent) from ps.reports where month >= frm), '{}'::jsonb))
$$;

create or replace function public.api(req jsonb) returns jsonb
language plpgsql security definer set search_path = ps, extensions, pg_temp as $$
declare
  a text := coalesce(req->>'action', '');
  d jsonb := coalesce(req->'data', '{}'::jsonb);
  v int; f record; dt text; mo text; sid text; cur jsonb; frm text; n int; k text; val jsonb;
begin
  if coalesce(req->>'key', '') = '' or req->>'key' is distinct from ps.sec('academy_key') then
    return '{"ok":false,"error":"bad_key"}';
  end if;

  if a = 'hello' then
    return jsonb_build_object('ok', true, 'hasPin', ps.sec('pin_hash') is not null, 'academy', ps.settings_obj()->>'academy',
                              'empty', not exists (select 1 from ps.students));
  elsif a = 'setPin' then
    if ps.sec('pin_hash') is not null then return '{"ok":false,"error":"exists"}'; end if;
    if coalesce(d->>'pin', '') !~ '^\d{4}$' then return '{"ok":false,"error":"pin_format"}'; end if;
    v := ps.new_pin(d->>'pin');
    return jsonb_build_object('ok', true, 'token', ps.make_token(), 'pinVer', v);
  elsif a = 'unlock' then
    if ps.sec('pin_hash') is null then return '{"ok":false,"error":"no_pin"}'; end if;
    select * into f from ps.fails where id = 1;
    if found and f.since > now() - interval '10 minutes' and f.cnt >= 5 then return '{"ok":false,"error":"locked"}'; end if;
    if coalesce(d->>'pin', '') !~ '^\d{4}$' or extensions.crypt(d->>'pin', ps.sec('pin_hash')) <> ps.sec('pin_hash') then
      insert into ps.fails as x (id, cnt, since) values (1, 1, now())
      on conflict (id) do update set
        cnt = case when x.since < now() - interval '10 minutes' then 1 else x.cnt + 1 end,
        since = case when x.since < now() - interval '10 minutes' then now() else x.since end
      returning cnt into v;
      return jsonb_build_object('ok', false, 'error', 'wrong', 'left', greatest(0, 5 - v));
    end if;
    delete from ps.fails;
    return jsonb_build_object('ok', true, 'token', ps.make_token(), 'pinVer', ps.sec('pin_ver')::int);
  end if;

  if not ps.check_token(req->>'token') then return '{"ok":false,"error":"auth"}'; end if;

  if a = 'load' then
    frm := case when coalesce(d->>'from', '') ~ '^\d{4}-\d{2}$' then d->>'from' else '0000-00' end;
    return jsonb_build_object('ok', true, 'from', frm, 'pinVer', ps.sec('pin_ver')::int) || ps.snapshot(frm);
  elsif a = 'attMonth' then
    mo := d->>'month';
    if coalesce(mo, '') !~ '^\d{4}-\d{2}$' then return '{"ok":false,"error":"month"}'; end if;
    return jsonb_build_object('ok', true, 'month', mo,
      'att', coalesce((select jsonb_object_agg(date, marks) from ps.attendance where left(date, 7) = mo), '{}'::jsonb),
      'notes', coalesce((select notes from ps.reports where month = mo), '{}'::jsonb),
      'sent', coalesce((select sent from ps.reports where month = mo), '{}'::jsonb));
  elsif a = 'mark' then
    dt := d->>'date';
    if coalesce(dt, '') !~ '^\d{4}-\d{2}-\d{2}$' then return '{"ok":false,"error":"date"}'; end if;
    select marks into cur from ps.attendance where date = dt for update;
    cur := ps.apply_marks(cur, d->'changes');
    insert into ps.attendance (date, marks, updated) values (dt, cur, now())
    on conflict (date) do update set marks = excluded.marks, updated = now();
    return jsonb_build_object('ok', true, 'date', dt, 'marks', cur);
  elsif a = 'saveStudents' then
    return jsonb_build_object('ok', true, 'saved', ps.save_students(d->'students'));
  elsif a = 'removeStudent' then
    update ps.students set removed = true, updated = now() where id = d->>'id';
    return '{"ok":true}';
  elsif a = 'saveSettings' then
    perform ps.save_settings(d);
    return jsonb_build_object('ok', true, 'settings', ps.settings_obj());
  elsif a in ('note', 'sent') then
    mo := d->>'month'; sid := left(coalesce(d->>'sid', ''), 40);
    if coalesce(mo, '') !~ '^\d{4}-\d{2}$' or sid = '' then return '{"ok":false,"error":"bad"}'; end if;
    insert into ps.reports (month) values (mo) on conflict (month) do nothing;
    if a = 'note' then
      update ps.reports set notes = case when coalesce(d->>'text', '') = '' then notes - sid else notes || jsonb_build_object(sid, left(d->>'text', 1500)) end where month = mo;
    else
      update ps.reports set sent = sent || jsonb_build_object(sid, left(coalesce(d->>'date', ''), 10)) where month = mo;
    end if;
    return '{"ok":true}';
  elsif a = 'exportAll' then
    return jsonb_build_object('ok', true, 'data', ps.snapshot('0000-00'));
  elsif a = 'importAll' then
    if exists (select 1 from ps.students where not removed) and coalesce((d->>'replace')::boolean, false) is not true then
      return '{"ok":false,"error":"not_empty"}';
    end if;
    perform ps.save_settings(coalesce(d->'data', '{}'::jsonb));
    perform ps.save_students(d->'data'->'students');
    n := 0;
    if jsonb_typeof(d->'data'->'att') = 'object' then
      for k, val in select key, value from jsonb_each(d->'data'->'att') loop
        if k ~ '^\d{4}-\d{2}-\d{2}$' then
          insert into ps.attendance (date, marks) values (k, ps.apply_marks('{}'::jsonb, val))
          on conflict (date) do update set marks = ps.apply_marks(ps.attendance.marks, val), updated = now();
          n := n + 1;
        end if;
      end loop;
    end if;
    if jsonb_typeof(d->'data'->'notes') = 'object' then
      for k, val in select key, value from jsonb_each(d->'data'->'notes') loop
        if k ~ '^\d{4}-\d{2}$' and jsonb_typeof(val) = 'object' then
          insert into ps.reports (month, notes) values (k, val) on conflict (month) do update set notes = ps.reports.notes || excluded.notes;
        end if;
      end loop;
    end if;
    if jsonb_typeof(d->'data'->'sent') = 'object' then
      for k, val in select key, value from jsonb_each(d->'data'->'sent') loop
        if k ~ '^\d{4}-\d{2}$' and jsonb_typeof(val) = 'object' then
          insert into ps.reports (month, sent) values (k, val) on conflict (month) do update set sent = ps.reports.sent || excluded.sent;
        end if;
      end loop;
    end if;
    return jsonb_build_object('ok', true, 'students', coalesce(jsonb_array_length(d->'data'->'students'), 0), 'days', n);
  elsif a = 'changePin' then
    if coalesce(d->>'oldPin', '') !~ '^\d{4}$' or extensions.crypt(d->>'oldPin', ps.sec('pin_hash')) <> ps.sec('pin_hash') then return '{"ok":false,"error":"wrong"}'; end if;
    if coalesce(d->>'newPin', '') !~ '^\d{4}$' then return '{"ok":false,"error":"pin_format"}'; end if;
    v := ps.new_pin(d->>'newPin');
    return jsonb_build_object('ok', true, 'token', ps.make_token(), 'pinVer', v);
  end if;
  return '{"ok":false,"error":"unknown"}';
end $$;

-- Only public.api() is reachable from the app.
revoke all on schema ps from public;
revoke all on all tables in schema ps from public;
revoke execute on all functions in schema ps from public;
revoke execute on function public.api(jsonb) from public;
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then
    execute 'revoke all on schema ps from anon, authenticated';
    execute 'revoke all on all tables in schema ps from anon, authenticated';
    execute 'revoke execute on all functions in schema ps from anon, authenticated';
    execute 'grant execute on function public.api(jsonb) to anon, authenticated';
  end if;
end $$;
