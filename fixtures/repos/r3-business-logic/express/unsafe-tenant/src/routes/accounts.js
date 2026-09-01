export function registerAccountRoutes(app, supabase, requireAuth) {
  app.get("/accounts/:id", requireAuth, async (req, res) => {
    const { data, error } = await supabase
      .from("accounts")
      .select("id,name,user_id")
      .eq("id", req.params.id);

    if (error) return res.status(500).json({ error: "query_failed" });
    return res.json(data);
  });
}
