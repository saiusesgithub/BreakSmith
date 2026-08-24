import { redactSecrets } from "../scanner/rules/helpers";
import {
  FINDING_CATEGORIES,
  type Confidence,
  type Finding,
  type FindingCategory,
  type Severity,
} from "../scanner/types";
import type { InsightsScanInput } from "./types";

const SEVERITIES = new Set<Severity>(["critical", "high", "medium", "low", "info"]);
const CATEGORIES = new Set<FindingCategory>(FINDING_CATEGORIES);
const CONFIDENCES = new Set<Confidence>(["high", "medium", "low"]);
const RISK_LEVELS = new Set(["LOW", "GUARDED", "MODERATE", "HIGH", "CRITICAL"]);
const MAX_FINDINGS = 5_000;

type ValidationResult = { value: InsightsScanInput } | { error: string };

function objectValue(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function stringValue(value: unknown, field: string, maximum: number): string {
  if (typeof value !== "string" || value.trim().length === 0) throw new Error(`${field} must be a non-empty string.`);
  if (value.length > maximum) throw new Error(`${field} is too long.`);
  return value.trim();
}

function nonNegativeInteger(value: unknown, field: string): number {
  if (!Number.isInteger(value) || (value as number) < 0) throw new Error(`${field} must be a non-negative integer.`);
  return value as number;
}

function safeRepositoryPath(value: string): boolean {
  if (/^[a-zA-Z]:[\\/]/.test(value) || value.startsWith("/") || value.startsWith("\\")) return false;
  if (value.includes("\0") || /[\r\n]/.test(value)) return false;
  return !value.split(/[\\/]/).includes("..");
}

function parseFinding(value: unknown, index: number): Finding {
  const finding = objectValue(value);
  if (!finding) throw new Error(`findings[${index}] must be a JSON object.`);
  const prefix = `findings[${index}]`;
  const id = stringValue(finding.id, `${prefix}.id`, 200);
  const ruleId = stringValue(finding.ruleId, `${prefix}.ruleId`, 160);
  const title = stringValue(finding.title, `${prefix}.title`, 300);
  const file = stringValue(finding.file, `${prefix}.file`, 1_000);
  if (!safeRepositoryPath(file)) throw new Error(`${prefix}.file must be a safe repository-relative path.`);
  if (typeof finding.severity !== "string" || !SEVERITIES.has(finding.severity as Severity)) {
    throw new Error(`${prefix}.severity is invalid.`);
  }
  if (typeof finding.category !== "string" || !CATEGORIES.has(finding.category as FindingCategory)) {
    throw new Error(`${prefix}.category is invalid.`);
  }
  if (typeof finding.confidence !== "string" || !CONFIDENCES.has(finding.confidence as Confidence)) {
    throw new Error(`${prefix}.confidence is invalid.`);
  }
  if (finding.line !== undefined && (!Number.isInteger(finding.line) || (finding.line as number) < 1)) {
    throw new Error(`${prefix}.line must be a positive integer.`);
  }

  return {
    id,
    ruleId,
    title: redactSecrets(title),
    severity: finding.severity as Severity,
    category: finding.category as FindingCategory,
    file: redactSecrets(file),
    line: finding.line as number | undefined,
    description: stringValue(finding.description, `${prefix}.description`, 4_000),
    impact: stringValue(finding.impact, `${prefix}.impact`, 4_000),
    remediation: stringValue(finding.remediation, `${prefix}.remediation`, 4_000),
    confidence: finding.confidence as Confidence,
    cwe: finding.cwe === undefined ? undefined : stringValue(finding.cwe, `${prefix}.cwe`, 80),
  };
}

export function validateInsightsRequest(body: unknown): ValidationResult {
  try {
    const input = objectValue(body);
    if (!input) return { error: "Request body must be a JSON object." };
    const repo = objectValue(input.repo);
    if (!repo) return { error: "repo must be a JSON object." };
    const summary = objectValue(input.summary);
    if (!summary) return { error: "summary must be a JSON object." };
    const categories = objectValue(input.categories);
    if (!categories) return { error: "categories must be a JSON object." };
    if (!Array.isArray(input.findings)) return { error: "findings must be an array." };
    if (input.findings.length > MAX_FINDINGS) return { error: `findings may contain at most ${MAX_FINDINGS} items.` };

    if (typeof input.score !== "number" || !Number.isFinite(input.score) || input.score < 0 || input.score > 100) {
      return { error: "score must be a number from 0 to 100." };
    }
    const riskLevel = stringValue(input.riskLevel, "riskLevel", 40).toUpperCase();
    if (!RISK_LEVELS.has(riskLevel)) return { error: "riskLevel is invalid." };

    const parsedCategories = {} as Record<FindingCategory, number>;
    for (const category of FINDING_CATEGORIES) {
      parsedCategories[category] = nonNegativeInteger(categories[category], `categories.${category}`);
    }

    return {
      value: {
        repo: {
          url: stringValue(repo.url, "repo.url", 2_000),
          name: redactSecrets(stringValue(repo.name, "repo.name", 200)),
          owner: redactSecrets(stringValue(repo.owner, "repo.owner", 200)),
        },
        score: input.score,
        riskLevel,
        summary: {
          total: nonNegativeInteger(summary.total, "summary.total"),
          critical: nonNegativeInteger(summary.critical, "summary.critical"),
          high: nonNegativeInteger(summary.high, "summary.high"),
          medium: nonNegativeInteger(summary.medium, "summary.medium"),
          low: nonNegativeInteger(summary.low, "summary.low"),
        },
        categories: parsedCategories,
        scannedFiles: nonNegativeInteger(input.scannedFiles, "scannedFiles"),
        findings: input.findings.map(parseFinding),
      },
    };
  } catch (error) {
    return { error: error instanceof Error ? error.message : "Request validation failed." };
  }
}
