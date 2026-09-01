export function registerUnsupportedRoutes(fastify) {
  fastify.route({
    method: "GET",
    url: "/unsupported/:id",
    handler: async (request) => ({ id: request.params.id }),
  });
}
