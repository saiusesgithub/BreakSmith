import assert from "node:assert/strict";
import test from "node:test";
import { calculateScore } from "../lib/scoring/score";
import type { Finding, Severity } from "../lib/scanner/types";

function makeFinding(index: number, severity: Severity, ruleId = `rule-${index}`): Finding {
  return {
    id: String(index),
    ruleId,
    title: "Test",
    severity,
    category: "configuration",
    file: "test.ts",
    description: "Test",
    impact: "Test",
    remediation: "Test",
    confidence: "high",
  };
}

test("score uses severity weights and returns complete statistics", () => {
  const result = calculateScore([
    makeFinding(1, "critical"),
    makeFinding(2, "high"),
    makeFinding(3, "medium"),
    makeFinding(4, "low"),
  ]);
  assert.equal(result.score, 63);
  assert.equal(result.riskLevel, "MODERATE");
  assert.deepEqual(result.summary, { total: 4, critical: 1, high: 1, medium: 1, low: 1 });
  assert.equal(result.categories.configuration, 4);
  assert.equal(result.categories.secrets, 0);
});

test("duplicate rule penalties are capped", () => {
  const findings = Array.from({ length: 20 }, (_, index) => makeFinding(index, "critical", "same-rule"));
  assert.equal(calculateScore(findings).score, 60);
});
