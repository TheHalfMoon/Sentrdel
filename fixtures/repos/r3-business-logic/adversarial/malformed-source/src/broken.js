export function registerBrokenRoute(app) {
  app.get("/broken/:id", async (req, res) => {
    const query = client.from("accounts").select("id,user_id");
    if (req.params.id) {
      return res.json(await query.eq("id", req.params.id));
  });
}
