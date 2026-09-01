export default async function handler(req, res) {
  const selectedGuard = await loadGuard(req.query.guard);
  const allowed = await selectedGuard(req);
  if (!allowed) return res.status(403).end();

  const { data } = await serviceClient
    .from("accounts")
    .select("id,user_id")
    .eq("id", req.query.id);
  return res.json(data);
}
