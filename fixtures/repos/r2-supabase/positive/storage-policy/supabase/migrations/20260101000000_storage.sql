create policy owned_objects on storage.objects
for select to authenticated
using (owner_id = auth.uid()::text);
