export function parseUserJson(input) {
  const evaluatorName = "eval";
  const functionLabel = "Function";
  const value = JSON.parse(input);
  return { evaluatorName, functionLabel, value };
}
