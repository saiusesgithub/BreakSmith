import type { AnalyticsRiskLevel, SeverityBreakdown } from "./types";
import type { Severity } from "../scanner/types";

export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 10,
  high: 6,
  medium: 3,
  low: 1,
  info: 0.25,
};

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const DOMINANT_SEVERITY_FLOOR: Record<Severity, number> = {
  critical: 80,
  high: 60,
  medium: 40,
  low: 15,
  info: 2,
};

const ADDITIONAL_CONTRIBUTION_CAP: Record<Severity, number> = {
  critical: 20,
  high: 24,
  medium: 15,
  low: 5,
  info: 1,
};

export function emptySeverityBreakdown(): SeverityBreakdown {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

export function clampScore(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}

export function riskLevelForScore(score: number): AnalyticsRiskLevel {
  if (score >= 80) return "CRITICAL";
  if (score >= 60) return "HIGH";
  if (score >= 40) return "MODERATE";
  if (score >= 20) return "GUARDED";
  return "LOW";
}

export function weightedSeverity(breakdown: SeverityBreakdown): number {
  const weighted = (Object.keys(SEVERITY_WEIGHTS) as Severity[])
    .reduce((total, severity) => total + breakdown[severity] * SEVERITY_WEIGHTS[severity], 0);
  return Math.round(weighted * 100) / 100;
}

/**
 * Analytics risk uses the most severe finding as an explicit floor, then adds
 * the suggested 10/6/3/1/0.25 weights for remaining findings with per-severity
 * caps. This keeps one critical finding (80) above any number of low-only
 * findings (maximum 20), while still rewarding concentrated mixed-severity risk.
 */
export function analyticsRiskScore(breakdown: SeverityBreakdown): number {
  const severities = (Object.keys(SEVERITY_ORDER) as Severity[])
    .sort((a, b) => SEVERITY_ORDER[a] - SEVERITY_ORDER[b]);
  const dominant = severities.find((severity) => breakdown[severity] > 0);
  if (!dominant) return 0;

  let score = DOMINANT_SEVERITY_FLOOR[dominant];
  for (const severity of severities) {
    const remainingCount = Math.max(0, breakdown[severity] - (severity === dominant ? 1 : 0));
    score += Math.min(
      remainingCount * SEVERITY_WEIGHTS[severity],
      ADDITIONAL_CONTRIBUTION_CAP[severity],
    );
  }
  return clampScore(score);
}

export function percentage(part: number, total: number): number {
  return total === 0 ? 0 : Math.round((part / total) * 1_000) / 10;
}
