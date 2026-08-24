import { redactSecrets } from "../scanner/rules/helpers";
import { FINDING_CATEGORIES, type Confidence, type Finding, type FindingCategory, type Severity } from "../scanner/types";
import {
  analyticsRiskScore,
  clampScore,
  emptySeverityBreakdown,
  percentage,
  riskLevelForScore,
  SEVERITY_ORDER,
  weightedSeverity,
} from "./scoring";
import type {
  CategoryRisk,
  FileHotspot,
  InsightsScanInput,
  PriorityItem,
  RepositoryInsights,
  SeverityBreakdown,
} from "./types";

const CONFIDENCE_ORDER: Record<Confidence, number> = { high: 0, medium: 1, low: 2 };
const CONFIDENCE_MODIFIER: Record<Confidence, number> = { high: 10, medium: 5, low: 0 };
const PRIORITY_BASE: Record<Severity, number> = { critical: 100, high: 70, medium: 40, low: 15, info: 5 };
const CATEGORY_MODIFIER: Record<FindingCategory, number> = {
  secrets: 8,
  injection: 8,
  authentication: 6,
  authorization: 6,
  "api-security": 4,
  cryptography: 4,
  configuration: 2,
  dependencies: 0,
  other: 0,
};
const RULE_MODIFIER: Record<string, number> = {
  "injection.command-execution": 5,
  "injection.sql-user-input": 4,
  "secrets.hardcoded-credential": 5,
  "secrets.sensitive-file": 4,
  "authentication.plaintext-password": 4,
  "authorization.security-disabled": 4,
  "authentication.jwt-no-expiry": 2,
};

function categoryOrder(category: FindingCategory): number {
  return FINDING_CATEGORIES.indexOf(category);
}

function addSeverity(breakdown: SeverityBreakdown, severity: Severity): void {
  breakdown[severity] += 1;
}

function uniqueFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    if (seen.has(finding.id)) return false;
    seen.add(finding.id);
    return true;
  });
}

function buildHotspots(findings: Finding[]): FileHotspot[] {
  const files = new Map<string, {
    breakdown: SeverityBreakdown;
    count: number;
    categories: Set<FindingCategory>;
    ruleIds: Set<string>;
  }>();

  for (const finding of findings) {
    const state = files.get(finding.file) ?? {
      breakdown: emptySeverityBreakdown(),
      count: 0,
      categories: new Set<FindingCategory>(),
      ruleIds: new Set<string>(),
    };
    state.count += 1;
    addSeverity(state.breakdown, finding.severity);
    state.categories.add(finding.category);
    state.ruleIds.add(finding.ruleId);
    files.set(finding.file, state);
  }

  return [...files.entries()].map(([file, state]) => {
    const riskScore = analyticsRiskScore(state.breakdown);
    const ruleIds = [...state.ruleIds].sort();
    return {
      file,
      findingCount: state.count,
      ...state.breakdown,
      riskScore,
      riskLevel: riskLevelForScore(riskScore),
      categories: [...state.categories].sort((a, b) => categoryOrder(a) - categoryOrder(b)),
      uniqueRuleCount: ruleIds.length,
      ruleIds,
    };
  }).sort((a, b) =>
    b.riskScore - a.riskScore
    || b.critical - a.critical
    || b.high - a.high
    || b.findingCount - a.findingCount
    || a.file.localeCompare(b.file));
}

function buildCategoryRisk(findings: Finding[]): CategoryRisk[] {
  const categories = new Map<FindingCategory, SeverityBreakdown>();
  for (const finding of findings) {
    const breakdown = categories.get(finding.category) ?? emptySeverityBreakdown();
    addSeverity(breakdown, finding.severity);
    categories.set(finding.category, breakdown);
  }

  return [...categories.entries()].map(([category, severity]) => {
    const count = Object.values(severity).reduce((total, value) => total + value, 0);
    const riskScore = analyticsRiskScore(severity);
    return {
      category,
      count,
      percentage: percentage(count, findings.length),
      severity,
      weightedRisk: weightedSeverity(severity),
      riskScore,
      riskLevel: riskLevelForScore(riskScore),
    };
  }).sort((a, b) =>
    b.riskScore - a.riskScore
    || b.weightedRisk - a.weightedRisk
    || b.count - a.count
    || categoryOrder(a.category) - categoryOrder(b.category));
}

function priorityScore(
  finding: Finding,
  fileFindingCount: number,
  categoryRiskScore: number,
): number {
  const hotspotModifier = Math.min(5, Math.max(0, fileFindingCount - 1));
  const categoryConcentrationModifier = Math.min(5, Math.floor(categoryRiskScore / 20));
  return clampScore(
    PRIORITY_BASE[finding.severity]
    + CONFIDENCE_MODIFIER[finding.confidence]
    + CATEGORY_MODIFIER[finding.category]
    + hotspotModifier
    + categoryConcentrationModifier
    + (RULE_MODIFIER[finding.ruleId] ?? 0),
  );
}

function buildPriorityQueue(
  findings: Finding[],
  hotspots: FileHotspot[],
  categoryRisk: CategoryRisk[],
): PriorityItem[] {
  const fileCounts = new Map(hotspots.map((hotspot) => [hotspot.file, hotspot.findingCount]));
  const categoryScores = new Map(categoryRisk.map((risk) => [risk.category, risk.riskScore]));

  return findings.map((finding) => ({
    rank: 0,
    findingId: redactSecrets(finding.id),
    title: redactSecrets(finding.title),
    severity: finding.severity,
    file: redactSecrets(finding.file),
    line: finding.line,
    category: finding.category,
    confidence: finding.confidence,
    priorityScore: priorityScore(
      finding,
      fileCounts.get(finding.file) ?? 1,
      categoryScores.get(finding.category) ?? 0,
    ),
    ruleId: finding.ruleId,
    originalId: finding.id,
  })).sort((a, b) =>
    b.priorityScore - a.priorityScore
    || SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
    || CONFIDENCE_ORDER[a.confidence] - CONFIDENCE_ORDER[b.confidence]
    || a.file.localeCompare(b.file)
    || (a.line ?? Number.MAX_SAFE_INTEGER) - (b.line ?? Number.MAX_SAFE_INTEGER)
    || a.ruleId.localeCompare(b.ruleId)
    || a.originalId.localeCompare(b.originalId))
    .slice(0, 10)
    .map(({ ruleId: _ruleId, originalId: _originalId, ...item }, index) => ({ ...item, rank: index + 1 }));
}

function priorityReason(finding: Finding): string {
  const severity = finding.severity === "info"
    ? "Informational"
    : `${finding.severity[0].toUpperCase()}${finding.severity.slice(1)}-severity`;
  const confidence = `${finding.confidence}-confidence`;

  if (finding.ruleId === "injection.command-execution") {
    return `${severity} command-execution risk with ${confidence} user-controlled input.`;
  }
  if (finding.ruleId === "injection.sql-user-input") {
    return `${severity} SQL-injection risk detected with ${finding.confidence} confidence.`;
  }
  if (finding.ruleId === "secrets.hardcoded-credential") {
    return `${severity} credential exposure in application source detected with ${finding.confidence} confidence.`;
  }
  if (finding.ruleId === "authentication.plaintext-password") {
    return `${severity} plaintext-password weakness detected with ${finding.confidence} confidence.`;
  }
  const category = finding.category.replace(/-/g, " ");
  return `${severity} ${category} risk detected with ${finding.confidence} confidence.`;
}

export function generateRepositoryInsights(input: InsightsScanInput): RepositoryInsights {
  const findings = uniqueFindings(input.findings).map((finding) => ({
    ...finding,
    title: redactSecrets(finding.title),
    file: redactSecrets(finding.file),
  }));
  const hotspots = buildHotspots(findings);
  const categoryRisk = buildCategoryRisk(findings);
  const priorityQueue = buildPriorityQueue(findings, hotspots, categoryRisk);
  const topPriority = priorityQueue[0];
  const topFinding = topPriority
    ? findings.find((finding) => redactSecrets(finding.id) === topPriority.findingId)
    : undefined;
  const mostVulnerable = hotspots[0];
  const primaryCategory = categoryRisk[0];
  const highOrCriticalCount = findings.filter((finding) =>
    finding.severity === "critical" || finding.severity === "high").length;
  const topThreeFindingCount = hotspots.slice(0, 3)
    .reduce((total, hotspot) => total + hotspot.findingCount, 0);

  return {
    repo: { name: redactSecrets(input.repo.name), owner: redactSecrets(input.repo.owner) },
    overview: {
      score: input.score,
      riskLevel: input.riskLevel,
      totalFindings: findings.length,
      primaryAttackSurface: primaryCategory ? {
        category: primaryCategory.category,
        count: primaryCategory.count,
        weightedRisk: primaryCategory.weightedRisk,
        percentage: primaryCategory.percentage,
      } : null,
      mostVulnerableFile: mostVulnerable ? {
        file: mostVulnerable.file,
        findingCount: mostVulnerable.findingCount,
        riskScore: mostVulnerable.riskScore,
        riskLevel: mostVulnerable.riskLevel,
      } : null,
    },
    topPriorityFinding: topPriority && topFinding ? {
      findingId: topPriority.findingId,
      title: topPriority.title,
      severity: topPriority.severity,
      file: topPriority.file,
      line: topPriority.line,
      category: topPriority.category,
      priorityScore: topPriority.priorityScore,
      reason: priorityReason(topFinding),
    } : null,
    priorityQueue,
    hotspots,
    categoryRisk,
    metrics: {
      affectedFiles: hotspots.length,
      findingsPerAffectedFile: hotspots.length === 0
        ? 0
        : Math.round((findings.length / hotspots.length) * 10) / 10,
      highOrCriticalPercentage: percentage(highOrCriticalCount, findings.length),
      uniqueRuleCount: new Set(findings.map((finding) => finding.ruleId)).size,
      uniqueCategoryCount: categoryRisk.length,
      criticalFileCount: hotspots.filter((hotspot) => hotspot.critical > 0).length,
      filesWithMultipleCategories: hotspots.filter((hotspot) => hotspot.categories.length > 1).length,
      findingConcentration: {
        topFilePercentage: percentage(mostVulnerable?.findingCount ?? 0, findings.length),
        topThreeFilesPercentage: percentage(topThreeFindingCount, findings.length),
      },
    },
  };
}
