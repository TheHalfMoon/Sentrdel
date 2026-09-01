export async function updateProfile(elevatedClient, req, userId) {
  return elevatedClient
    .from("profiles")
    .update(req.body)
    .eq("user_id", userId);
}
