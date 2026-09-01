Deno.serve(async (request) => {
  const token = request.headers.get("Authorization") ?? "";
  const userResult = await supabase.auth.getUser(token.replace("Bearer ", ""));
  const user = userResult.data.user;
  if (!user) return new Response(null, { status: 401 });

  const { data, error } = await supabase
    .from("documents")
    .select("id,owner_id,title")
    .eq("owner_id", user.id);

  return Response.json(error ? { error: "query_failed" } : data, {
    status: error ? 500 : 200,
  });
});
