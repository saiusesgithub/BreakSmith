import assert from "node:assert/strict";
import test from "node:test";
import { generateRepositoryInsights } from "../lib/analytics/repository-insights";
import { analyticsRiskScore, emptySeverityBreakdown } from "../lib/analytics/scoring";
import type { InsightsScanInput } from "../lib/analytics/types";
import { FINDING_CATEGORIES, type Finding, type FindingCategory } from "../lib/scanner/types";

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding-1",
    ruleId: "configuration.debug-enabled",
    title: "Debug mode enabled",
    severity: "medium",
    category: "configuration",
    file: "src/server.ts",
    line: 10,
    description: "Debug mode is enabled.",
    impact: "Production details may be exposed.",
    remediation: "Disable debug mode in production.",
    confidence: "medium",
    ...overrides,
  };
}

function scan(findings: Finding[]): InsightsScanInput {
  const categories = Object.fromEntries(
    FINDING_CATEGORIES.map((category) => [category, 0]),
  ) as Record<FindingCategory, number>;
  for (const item of findings) categories[item.category] += 1;
  return {
    repo: { url: "https://github.com/example/northstar-finance", name: "northstar-finance", owner: "example" },
    score: 45,
    riskLevel: "HIGH",
    summary: {
      total: findings.length,
      critical: findings.filter((item) => item.severity === "critical").length,
      high: findings.filter((item) => item.severity === "high").length,
      medium: findings.filter((item) => item.severity === "medium").length,
      low: findings.filter((item) => item.severity === "low").length,
    },
    categories,
    scannedFiles: 20,
    findings,
  };
}

test("empty findings return useful clean repository intelligence", () => {
  const result = generateRepositoryInsights(scan([]));
  assert.equal(result.overview.totalFindings, 0);
  assert.equal(result.overview.primaryAttackSurface, null);
  assert.equal(result.overview.mostVulnerableFile, null);
  assert.equal(result.topPriorityFinding, null);
  assert.deepEqual(result.priorityQueue, []);
  assert.deepEqual(result.hotspots, []);
  assert.deepEqual(result.categoryRisk, []);
  assert.deepEqual(result.metrics.findingConcentration, { topFilePercentage: 0, topThreeFilesPercentage: 0 });
});

test("one critical finding creates a critical hotspot", () => {
  const result = generateRepositoryInsights(scan([finding({ severity: "critical", confidence: "high" })]));
  assert.equal(result.hotspots[0].riskScore, 80);
  assert.equal(result.hotspots[0].riskLevel, "CRITICAL");
  assert.equal(result.metrics.criticalFileCount, 1);
  assert.equal(result.priorityQueue[0].priorityScore, 100);
});

test("mixed severities produce complete breakdowns and bounded scores", () => {
  const findings = [
    finding({ id: "critical", severity: "critical" }),
    finding({ id: "high", severity: "high" }),
    finding({ id: "medium", severity: "medium" }),
    finding({ id: "low", severity: "low" }),
    finding({ id: "info", severity: "info" }),
  ];
  const result = generateRepositoryInsights(scan(findings));
  assert.deepEqual(
    (({ critical, high, medium, low, info }) => ({ critical, high, medium, low, info }))(result.hotspots[0]),
    { critical: 1, high: 1, medium: 1, low: 1, info: 1 },
  );
  assert.ok(result.hotspots[0].riskScore >= 0 && result.hotspots[0].riskScore <= 100);
});

test("multiple files are aggregated independently", () => {
  const result = generateRepositoryInsights(scan([
    finding({ id: "a", file: "src/auth.ts", severity: "high" }),
    finding({ id: "b", file: "src/auth.ts", severity: "medium", category: "authentication" }),
    finding({ id: "c", file: "src/config.ts", severity: "low" }),
  ]));
  assert.equal(result.metrics.affectedFiles, 2);
  assert.equal(result.hotspots.find((item) => item.file === "src/auth.ts")?.findingCount, 2);
  assert.equal(result.metrics.filesWithMultipleCategories, 1);
});

test("multiple categories include severity breakdowns and stable percentages", () => {
  const result = generateRepositoryInsights(scan([
    finding({ id: "a", category: "secrets", severity: "high" }),
    finding({ id: "b", category: "secrets", severity: "medium" }),
    finding({ id: "c", category: "injection", severity: "low" }),
  ]));
  const secrets = result.categoryRisk.find((item) => item.category === "secrets");
  assert.equal(secrets?.count, 2);
  assert.equal(secrets?.percentage, 66.7);
  assert.equal(secrets?.severity.high, 1);
  assert.equal(result.metrics.uniqueCategoryCount, 2);
});

test("one critical hotspot outranks any number of low-only findings", () => {
  const lows = Array.from({ length: 100 }, (_, index) => finding({
    id: `low-${index}`,
    severity: "low",
    file: "package.json",
    category: "dependencies",
  }));
  const result = generateRepositoryInsights(scan([
    ...lows,
    finding({ id: "critical", severity: "critical", file: "src/exec.ts", category: "injection" }),
  ]));
  assert.equal(result.hotspots[0].file, "src/exec.ts");
  assert.equal(result.hotspots[0].riskScore, 80);
  assert.equal(result.hotspots[1].riskScore, 20);
});

test("primary attack surface uses severity weighting instead of raw count", () => {
  const dependencies = Array.from({ length: 5 }, (_, index) => finding({
    id: `dependency-${index}`,
    category: "dependencies",
    severity: "low",
  }));
  const injection = [0, 1].map((index) => finding({
    id: `injection-${index}`,
    category: "injection",
    severity: "critical",
  }));
  const result = generateRepositoryInsights(scan([...dependencies, ...injection]));
  assert.equal(result.overview.primaryAttackSurface?.category, "injection");
  assert.equal(result.overview.primaryAttackSurface?.weightedRisk, 20);
  assert.equal(result.overview.primaryAttackSurface?.percentage, 28.6);
});

test("hotspot ordering uses deterministic severity-aware tie breakers", () => {
  const result = generateRepositoryInsights(scan([
    finding({ id: "medium-a", file: "b.ts", severity: "medium" }),
    finding({ id: "medium-b", file: "a.ts", severity: "medium" }),
    finding({ id: "high", file: "z.ts", severity: "high" }),
  ]));
  assert.deepEqual(result.hotspots.map((item) => item.file), ["z.ts", "a.ts", "b.ts"]);
});

test("priority queue orders by priority then requested deterministic tie breakers", () => {
  const result = generateRepositoryInsights(scan([
    finding({ id: "low", severity: "low", confidence: "high", file: "a.ts" }),
    finding({ id: "high-b", severity: "high", confidence: "medium", file: "b.ts" }),
    finding({ id: "high-a", severity: "high", confidence: "medium", file: "a.ts" }),
  ]));
  assert.deepEqual(result.priorityQueue.map((item) => item.findingId), ["high-a", "high-b", "low"]);
  assert.deepEqual(result.priorityQueue.map((item) => item.rank), [1, 2, 3]);
});

test("confidence modifier raises otherwise identical priority", () => {
  const result = generateRepositoryInsights(scan([
    finding({ id: "low-confidence", confidence: "low", file: "b.ts" }),
    finding({ id: "high-confidence", confidence: "high", file: "a.ts" }),
  ]));
  const high = result.priorityQueue.find((item) => item.findingId === "high-confidence");
  const low = result.priorityQueue.find((item) => item.findingId === "low-confidence");
  assert.ok((high?.priorityScore ?? 0) > (low?.priorityScore ?? 0));
  assert.equal(result.priorityQueue[0].findingId, "high-confidence");
});

test("duplicate finding IDs are counted only once", () => {
  const duplicate = finding({ id: "same-id", severity: "high" });
  const result = generateRepositoryInsights(scan([duplicate, { ...duplicate }]));
  assert.equal(result.overview.totalFindings, 1);
  assert.equal(result.hotspots[0].findingCount, 1);
  assert.equal(result.priorityQueue.length, 1);
});

test("analytics risk scores always clamp to 0-100", () => {
  const huge = emptySeverityBreakdown();
  huge.critical = 100_000;
  huge.high = 100_000;
  huge.medium = 100_000;
  huge.low = 100_000;
  huge.info = 100_000;
  assert.equal(analyticsRiskScore(huge), 100);
  assert.equal(analyticsRiskScore(emptySeverityBreakdown()), 0);
});

test("repository percentages and concentration are correct", () => {
  const result = generateRepositoryInsights(scan([
    finding({ id: "a", file: "a.ts", severity: "critical" }),
    finding({ id: "b", file: "a.ts", severity: "high" }),
    finding({ id: "c", file: "a.ts", severity: "medium" }),
    finding({ id: "d", file: "b.ts", severity: "low" }),
  ]));
  assert.equal(result.metrics.highOrCriticalPercentage, 50);
  assert.equal(result.metrics.findingsPerAffectedFile, 2);
  assert.equal(result.metrics.findingConcentration.topFilePercentage, 75);
  assert.equal(result.metrics.findingConcentration.topThreeFilesPercentage, 100);
});

test("priority reason is deterministic and rule-specific", () => {
  const result = generateRepositoryInsights(scan([finding({
    id: "command",
    ruleId: "injection.command-execution",
    title: "User-controlled command execution",
    severity: "critical",
    category: "injection",
    confidence: "high",
  })]));
  assert.match(result.topPriorityFinding?.reason ?? "", /Critical-severity command-execution risk.*high-confidence/);
});
