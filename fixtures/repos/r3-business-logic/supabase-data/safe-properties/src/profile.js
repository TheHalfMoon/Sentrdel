export async function updateProfile(supabase, req, userId) {
  const { display_name, timezone } = req.body;
  return supabase
    .from("profiles")
    .update({ display_name, timezone })
    .eq("user_id", userId);
}
