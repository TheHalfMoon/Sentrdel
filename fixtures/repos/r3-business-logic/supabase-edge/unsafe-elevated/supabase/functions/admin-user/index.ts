const SERVICE_ROLE_CANARY = "SENTRDEL_CANARY_R3_ELEVATED_SERVICE_ROLE_NOT_A_SECRET";
const elevated = createClient(SUPABASE_URL, SERVICE_ROLE_CANARY);

Deno.serve(async (request) => {
  const body = await request.json();
  const { error } = await elevated.from("users").delete().eq("id", body.user_id);
  return new Response(null, { status: error ? 500 : 204 });
});
