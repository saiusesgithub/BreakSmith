import { redactSecrets } from "../scanner/rules/helpers";
import {
  FINDING_CATEGORIES,
  type Confidence,
  type Finding,
  type FindingCategory,
  type Severity,
} from "../scanner/types";
import type { FixContent, FixRequest } from "./types";

const SEVERITIES = new Set<Severity>(["critical", "high", "medium", "low", "info"]);
const CATEGORIES = new Set<FindingCategory>(FINDING_CATEGORIES);
const CONFIDENCES = new Set<Confidence>(["high", "medium", "low"]);

const REQUEST_STRING_LIMITS = {
  id: 200,
  ruleId: 160,
  title: 300,
  file: 1_000,
  snippet: 2_000,
  description: 4_000,
  impact: 4_000,
  remediation: 4_000,
  cwe: 80,
  language: 80,
} as const;

const OUTPUT_LIMITS = {
  summary: 1_000,
  step: 1_000,
  after: 8_000,
  note: 1_000,
  maxSteps: 8,
  maxNotes: 8,
} as const;

type ValidationResult<T> = { value: T } | { error: string };

function requiredString(
  value: unknown,
  field: string,
  maximum: number,
): ValidationResult<string> {
  if (typeof value !== "string" || value.trim().length === 0) {
    return { error: `${field} must be a non-empty string.` };
  }
  if (value.length > maximum) return { error: `${field} is too long.` };
  return { value };
}

function optionalString(
  value: unknown,
  field: string,
  maximum: number,
): ValidationResult<string | undefined> {
  if (value === undefined) return { value: undefined };
  return requiredString(value, field, maximum);
}

function safeRepositoryPath(file: string): boolean {
  if (/^[a-zA-Z]:[\\/]/.test(file) || file.startsWith("/") || file.startsWith("\\")) return false;
  if (file.includes("\0") || /[\r\n]/.test(file)) return false;
  return !file.split(/[\\/]/).includes("..");
}

export function validateFixRequest(body: unknown): ValidationResult<FixRequest> {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return { error: "Request body must be a JSON object." };
  }
  const request = body as Record<string, unknown>;
  if (!request.finding || typeof request.finding !== "object" || Array.isArray(request.finding)) {
    return { error: "finding must be a JSON object." };
  }
  const input = request.finding as Record<string, unknown>;

  const idResult = requiredString(input.id, "finding.id", REQUEST_STRING_LIMITS.id);
  if ("error" in idResult) return idResult;
  const id = idResult.value;
  const ruleIdResult = requiredString(input.ruleId, "finding.ruleId", REQUEST_STRING_LIMITS.ruleId);
  if ("error" in ruleIdResult) return ruleIdResult;
  const ruleId = ruleIdResult.value;
  const titleResult = requiredString(input.title, "finding.title", REQUEST_STRING_LIMITS.title);
  if ("error" in titleResult) return titleResult;
  const title = titleResult.value;
  const fileResult = requiredString(input.file, "finding.file", REQUEST_STRING_LIMITS.file);
  if ("error" in fileResult) return fileResult;
  const file = fileResult.value;
  if (!safeRepositoryPath(file)) return { error: "finding.file must be a safe repository-relative path." };
  const descriptionResult = requiredString(
    input.description,
    "finding.description",
    REQUEST_STRING_LIMITS.description,
  );
  if ("error" in descriptionResult) return descriptionResult;
  const description = descriptionResult.value;
  const impactResult = requiredString(input.impact, "finding.impact", REQUEST_STRING_LIMITS.impact);
  if ("error" in impactResult) return impactResult;
  const impact = impactResult.value;
  const remediationResult = requiredString(
    input.remediation,
    "finding.remediation",
    REQUEST_STRING_LIMITS.remediation,
  );
  if ("error" in remediationResult) return remediationResult;
  const remediation = remediationResult.value;

  if (typeof input.severity !== "string" || !SEVERITIES.has(input.severity as Severity)) {
    return { error: "finding.severity is invalid." };
  }
  if (typeof input.category !== "string" || !CATEGORIES.has(input.category as FindingCategory)) {
    return { error: "finding.category is invalid." };
  }
  if (typeof input.confidence !== "string" || !CONFIDENCES.has(input.confidence as Confidence)) {
    return { error: "finding.confidence is invalid." };
  }
  if (input.line !== undefined && (!Number.isInteger(input.line) || (input.line as number) < 1)) {
    return { error: "finding.line must be a positive integer." };
  }

  const snippetResult = optionalString(input.snippet, "finding.snippet", REQUEST_STRING_LIMITS.snippet);
  if ("error" in snippetResult) return snippetResult;
  const snippet = snippetResult.value;
  const cweResult = optionalString(input.cwe, "finding.cwe", REQUEST_STRING_LIMITS.cwe);
  if ("error" in cweResult) return cweResult;
  const cwe = cweResult.value;
  const languageResult = optionalString(request.language, "language", REQUEST_STRING_LIMITS.language);
  if ("error" in languageResult) return languageResult;
  const language = languageResult.value;

  const finding: Finding = {
    id,
    ruleId,
    title,
    severity: input.severity as Severity,
    category: input.category as FindingCategory,
    file,
    line: input.line as number | undefined,
    snippet,
    description,
    impact,
    remediation,
    confidence: input.confidence as Confidence,
    cwe,
  };
  return { value: { finding, language } };
}

function outputArray(
  value: unknown,
  maximumItems: number,
  maximumLength: number,
): string[] | null {
  if (!Array.isArray(value) || value.length === 0 || value.length > maximumItems) return null;
  if (value.some((item) => typeof item !== "string" || item.trim().length === 0 || item.length > maximumLength)) {
    return null;
  }
  return value.map((item) => redactSecrets(item));
}

export function parseFixContent(value: unknown): FixContent | null {
  let parsed: unknown = value;
  if (typeof value === "string") {
    try {
      parsed = JSON.parse(value);
    } catch {
      return null;
    }
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const candidate = parsed as Record<string, unknown>;
  const expectedKeys = ["summary", "steps", "after", "notes", "confidence"];
  const actualKeys = Object.keys(candidate);
  if (actualKeys.length !== expectedKeys.length || actualKeys.some((key) => !expectedKeys.includes(key))) return null;

  const summary = requiredString(candidate.summary, "summary", OUTPUT_LIMITS.summary);
  const after = requiredString(candidate.after, "after", OUTPUT_LIMITS.after);
  const steps = outputArray(candidate.steps, OUTPUT_LIMITS.maxSteps, OUTPUT_LIMITS.step);
  const notes = outputArray(candidate.notes, OUTPUT_LIMITS.maxNotes, OUTPUT_LIMITS.note);
  if ("error" in summary || "error" in after || !steps || !notes) return null;
  if (typeof candidate.confidence !== "string" || !CONFIDENCES.has(candidate.confidence as Confidence)) return null;

  return {
    summary: redactSecrets(summary.value.trim()),
    steps,
    after: redactSecrets(after.value.trim()),
    notes,
    confidence: candidate.confidence as Confidence,
  };
}
