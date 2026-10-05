-- Restore public write access required by the older browser-password LoFo app.
-- This does not delete item rows or role records. The old password prompt is
-- client-side only and does not secure these public policies.

begin;

alter table public.items enable row level security;
grant select, insert, update, delete on table public.items to anon;

drop policy if exists "Public can read items" on public.items;
drop policy if exists "Public can add items" on public.items;
drop policy if exists "Public can update items" on public.items;
drop policy if exists "Public can delete items" on public.items;

create policy "Public can read items"
  on public.items for select to anon using (true);
create policy "Public can add items"
  on public.items for insert to anon with check (true);
create policy "Public can update items"
  on public.items for update to anon using (true) with check (true);
create policy "Public can delete items"
  on public.items for delete to anon using (true);

drop policy if exists "Public can upload LoFo photos" on storage.objects;
drop policy if exists "Public can update LoFo photos" on storage.objects;
drop policy if exists "Public can delete LoFo photos" on storage.objects;

create policy "Public can upload LoFo photos"
  on storage.objects for insert to anon
  with check (bucket_id = 'lofo-images');
create policy "Public can update LoFo photos"
  on storage.objects for update to anon
  using (bucket_id = 'lofo-images')
  with check (bucket_id = 'lofo-images');
create policy "Public can delete LoFo photos"
  on storage.objects for delete to anon
  using (bucket_id = 'lofo-images');

commit;
