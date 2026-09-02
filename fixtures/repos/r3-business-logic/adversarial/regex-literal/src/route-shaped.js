const routeLike = /app.get('x', handler)/;
const delimiterLike = /[)]callback[(]/;
app.get('/real', (req, res) => delimiterLike.test(req.path) ? handler(req, res) : res.end());
