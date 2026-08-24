import { redactSecrets } from "../scanner/rules/helpers";

function diffLines(prefix: "-" | "+", value: string): string[] {
  return value.replace(/\r\n/g, "\n").split("\n").map((line) => `${prefix} ${line}`);
}

export function suggestedDiff(file: string, before: string, after: string): string {
  const normalizedFile = file.replace(/\\/g, "/");
  return redactSecrets([
    `--- a/${normalizedFile}`,
    `+++ b/${normalizedFile}`,
    "@@ suggested remediation @@",
    ...diffLines("-", before),
    ...diffLines("+", after),
  ].join("\n"));
}
