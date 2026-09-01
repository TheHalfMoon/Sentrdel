export function install(app, client, request) {
  const method = request.query.method;
  const route = request.query.route;
  const table = request.query.table;
  const field = request.query.field;

  app[method](route, async (req, res) => {
    const query = client.from(table).select("*");
    const { data } = await query.eq(field, req.query.value);
    return res.json(data);
  });
}
