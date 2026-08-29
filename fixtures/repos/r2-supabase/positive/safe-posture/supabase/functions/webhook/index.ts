// Synthetic fixture source. This file is never executed by Sentrdel analysis.
export function authorize(request: Request): boolean {
  return request.headers.get("authorization")?.startsWith("Bearer ") === true;
}
