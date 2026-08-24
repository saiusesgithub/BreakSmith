import type { Confidence, Finding, FindingCategory, Severity } from "../scanner/types";

export type AnalyticsRiskLevel = "LOW" | "GUARDED" | "MODERATE" | "HIGH" | "CRITICAL";

export type SeverityBreakdown = Record<Severity, number>;

export type InsightsScanInput = {
  repo: { url: string; name: string; owner: string };
  score: number;
  riskLevel: string;
  summary: { total: number; critical: number; high: number; medium: number; low: number };
  categories: Record<FindingCategory, number>;
  scannedFiles: number;
  findings: Finding[];
};

export type FileHotspot = {
  file: string;
  findingCount: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  riskScore: number;
  riskLevel: AnalyticsRiskLevel;
  categories: FindingCategory[];
  uniqueRuleCount: number;
  ruleIds: string[];
};

export type CategoryRisk = {
  category: FindingCategory;
  count: number;
  percentage: number;
  severity: SeverityBreakdown;
  weightedRisk: number;
  riskScore: number;
  riskLevel: AnalyticsRiskLevel;
};

export type PriorityItem = {
  rank: number;
  findingId: string;
  title: string;
  severity: Severity;
  file: string;
  line?: number;
  category: FindingCategory;
  confidence: Confidence;
  priorityScore: number;
};

export type RepositoryInsights = {
  repo: { name: string; owner: string };
  overview: {
    score: number;
    riskLevel: string;
    totalFindings: number;
    primaryAttackSurface: {
      category: FindingCategory;
      count: number;
      weightedRisk: number;
      percentage: number;
    } | null;
    mostVulnerableFile: {
      file: string;
      findingCount: number;
      riskScore: number;
      riskLevel: AnalyticsRiskLevel;
    } | null;
  };
  topPriorityFinding: (Omit<PriorityItem, "rank" | "priorityScore" | "confidence"> & {
    priorityScore: number;
    reason: string;
  }) | null;
  priorityQueue: PriorityItem[];
  hotspots: FileHotspot[];
  categoryRisk: CategoryRisk[];
  metrics: {
    affectedFiles: number;
    findingsPerAffectedFile: number;
    highOrCriticalPercentage: number;
    uniqueRuleCount: number;
    uniqueCategoryCount: number;
    criticalFileCount: number;
    filesWithMultipleCategories: number;
    findingConcentration: {
      topFilePercentage: number;
      topThreeFilesPercentage: number;
    };
  };
};
