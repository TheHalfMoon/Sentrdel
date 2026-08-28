export function executeDynamic(input) {
  const generated = new Function("value", input);
  return eval(input) + generated(input);
}
