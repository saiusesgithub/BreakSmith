import { FINDING_CATEGORIES, type Finding, type FindingCategory, type Severity } from "../scanner/types";

export type RiskLevel = "LOW" | "GUARDED" | "MODERATE" | "HIGH" | "CRITICAL";

export type FindingSummary = {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
};

export type ScoreResult = {
  score: number;
  riskLevel: RiskLevel;
  summary: FindingSummary;
  categories: Record<FindingCategory, number>;
};

const PENALTIES: Record<Severity, number> = {
  critical: 20,
  high: 10,
  medium: 5,
  low: 2,
  info: 0,
};

function riskLevelForScore(score: number): RiskLevel {
  if (score >= 90) return "LOW";
  if (score >= 75) return "GUARDED";
  if (score >= 50) return "MODERATE";
  if (score >= 25) return "HIGH";
  return "CRITICAL";
}

export function calculateScore(findings: Finding[]): ScoreResult {
  const summary: FindingSummary = { total: findings.length, critical: 0, high: 0, medium: 0, low: 0 };
  const categories = Object.fromEntries(FINDING_CATEGORIES.map((category) => [category, 0])) as Record<FindingCategory, number>;
  const penaltyByRule = new Map<string, number>();

  for (const finding of findings) {
    if (finding.severity !== "info") summary[finding.severity] += 1;
    categories[finding.category] += 1;

    const currentRulePenalty = penaltyByRule.get(finding.ruleId) ?? 0;
    const availablePenalty = Math.max(0, 40 - currentRulePenalty);
    penaltyByRule.set(finding.ruleId, currentRulePenalty + Math.min(PENALTIES[finding.severity], availablePenalty));
  }

  const totalPenalty = [...penaltyByRule.values()].reduce((total, penalty) => total + penalty, 0);
  const score = Math.max(0, Math.min(100, 100 - totalPenalty));
  return { score, riskLevel: riskLevelForScore(score), summary, categories };
}
