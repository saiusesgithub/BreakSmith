import { redactSecrets } from "../scanner/rules/helpers";
import type { FindingEnrichment } from "./types";

const MAX_LENGTHS = { description: 1_000, impact: 1_000, remediation: 1_500 } as const;

function validatedText(value: unknown, maxLength: number): string | null {
  if (typeof value !== "string") return null;
  const text = value.trim();
  if (!text || text.length > maxLength) return null;
  return redactSecrets(text);
}

export function parseEnrichment(value: string): FindingEnrichment | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;

  const candidate = parsed as Record<string, unknown>;
  const expectedKeys = ["description", "impact", "remediation"];
  const actualKeys = Object.keys(candidate);
  if (actualKeys.length !== expectedKeys.length || actualKeys.some((key) => !expectedKeys.includes(key))) return null;
  const description = validatedText(candidate.description, MAX_LENGTHS.description);
  const impact = validatedText(candidate.impact, MAX_LENGTHS.impact);
  const remediation = validatedText(candidate.remediation, MAX_LENGTHS.remediation);
  if (!description || !impact || !remediation) return null;
  return { description, impact, remediation };
}
