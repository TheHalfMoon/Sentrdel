export async function DELETE(request, context) {
  const session = await auth();
  if (!session || session.user.role !== "admin") {
    return new Response(null, { status: 403 });
  }

  const { error } = await serviceClient
    .from("users")
    .delete()
    .eq("id", context.params.id);

  return new Response(null, { status: error ? 500 : 204 });
}
