-- LoFo role-based access migration
-- Run once in Supabase SQL Editor after checking the project backup.
-- New Supabase Auth users are Members by default. Promote your own account
-- to Admin only after signing in once and receiving its role row.

begin;

create table if not exists public.lofo_user_roles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null default 'member' check (role in ('admin', 'member')),
  created_at timestamptz not null default now()
);

insert into public.lofo_user_roles (user_id, role)
select id, 'member' from auth.users
on conflict (user_id) do nothing;

alter table public.lofo_user_roles enable row level security;
revoke all on table public.lofo_user_roles from anon, authenticated;
grant select on table public.lofo_user_roles to authenticated;

drop policy if exists "Users can read their own LoFo role" on public.lofo_user_roles;
create policy "Users can read their own LoFo role"
  on public.lofo_user_roles for select to authenticated
  using (user_id = auth.uid());

create or replace function public.is_lofo_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.lofo_user_roles
    where user_id = auth.uid() and role = 'admin'
  );
$$;
revoke all on function public.is_lofo_admin() from public, anon;
grant execute on function public.is_lofo_admin() to authenticated;

create or replace function public.assign_lofo_member_role()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.lofo_user_roles (user_id, role)
  values (new.id, 'member')
  on conflict (user_id) do nothing;
  return new;
end;
$$;
revoke all on function public.assign_lofo_member_role() from public, anon, authenticated;

drop trigger if exists assign_lofo_member_role_after_signup on auth.users;
create trigger assign_lofo_member_role_after_signup
  after insert on auth.users
  for each row execute function public.assign_lofo_member_role();

alter table public.items enable row level security;
revoke all on table public.items from anon;
grant select, insert, update, delete on table public.items to authenticated;

drop policy if exists "Public can read items" on public.items;
drop policy if exists "Public can add items" on public.items;
drop policy if exists "Public can update items" on public.items;
drop policy if exists "Public can delete items" on public.items;
drop policy if exists "Authenticated users can read LoFo items" on public.items;
drop policy if exists "Admins can add LoFo items" on public.items;
drop policy if exists "Authenticated users can update LoFo items" on public.items;
drop policy if exists "Authenticated users can delete LoFo items" on public.items;

create policy "Authenticated users can read LoFo items"
  on public.items for select to authenticated using (true);
create policy "Admins can add LoFo items"
  on public.items for insert to authenticated with check (public.is_lofo_admin());
create policy "Authenticated users can update LoFo items"
  on public.items for update to authenticated using (true) with check (true);
create policy "Authenticated users can delete LoFo items"
  on public.items for delete to authenticated using (true);

-- The bucket remains public for displaying item photos. Only signed-in users
-- may upload, replace, or delete photo objects.
drop policy if exists "Public can upload LoFo photos" on storage.objects;
drop policy if exists "Public can update LoFo photos" on storage.objects;
drop policy if exists "Public can delete LoFo photos" on storage.objects;
drop policy if exists "Authenticated users can upload LoFo photos" on storage.objects;
drop policy if exists "Authenticated users can update LoFo photos" on storage.objects;
drop policy if exists "Authenticated users can delete LoFo photos" on storage.objects;

create policy "Authenticated users can upload LoFo photos"
  on storage.objects for insert to authenticated
  with check (bucket_id = 'lofo-images');
create policy "Authenticated users can update LoFo photos"
  on storage.objects for update to authenticated
  using (bucket_id = 'lofo-images')
  with check (bucket_id = 'lofo-images');
create policy "Authenticated users can delete LoFo photos"
  on storage.objects for delete to authenticated
  using (bucket_id = 'lofo-images');

commit;

-- After creating your account and signing in once, promote that account by
-- replacing ADMIN_EMAIL with its email address and running this separately:
-- update public.lofo_user_roles
-- set role = 'admin'
-- where user_id = (select id from auth.users where lower(email) = lower('ADMIN_EMAIL'));
