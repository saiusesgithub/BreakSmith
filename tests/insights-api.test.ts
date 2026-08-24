import assert from "node:assert/strict";
import test from "node:test";
import { handleInsightsRequest } from "../app/api/insights/route";
import { FINDING_CATEGORIES, type FindingCategory } from "../lib/scanner/types";

function cleanScan(): Record<string, unknown> {
  return {
    scanId: "ignored-extra-field",
    durationMs: 12,
    repo: { url: "https://github.com/example/clean", name: "clean", owner: "example" },
    score: 100,
    riskLevel: "LOW",
    summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
    categories: Object.fromEntries(
      FINDING_CATEGORIES.map((category) => [category, 0]),
    ) as Record<FindingCategory, number>,
    scannedFiles: 12,
    findings: [],
  };
}

function request(body: unknown): Request {
  return new Request("http://localhost/api/insights", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

test("invalid insights request returns clean 400 JSON", async () => {
  const response = await handleInsightsRequest(request({ findings: [] }));
  assert.equal(response.status, 400);
  const body = await response.json() as { error?: unknown };
  assert.equal(typeof body.error, "string");
});

test("malformed insights JSON returns 400", async () => {
  const response = await handleInsightsRequest(new Request("http://localhost/api/insights", {
    method: "POST",
    body: "{",
  }));
  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { error: "Request body must be valid JSON." });
});

test("clean repository returns 200 analytics with no hotspots", async () => {
  const response = await handleInsightsRequest(request(cleanScan()));
  assert.equal(response.status, 200);
  const body = await response.json() as Record<string, unknown>;
  assert.deepEqual(Object.keys(body).sort(), [
    "categoryRisk", "hotspots", "metrics", "overview", "priorityQueue", "repo", "topPriorityFinding",
  ]);
  assert.equal(body.topPriorityFinding, null);
  assert.deepEqual(body.hotspots, []);
  assert.deepEqual(body.priorityQueue, []);
});

test("insights endpoint ignores scan extras and never returns snippets", async () => {
  const body = cleanScan();
  body.score = 60;
  body.riskLevel = "MODERATE";
  body.summary = { total: 1, critical: 0, high: 1, medium: 0, low: 0 };
  (body.categories as Record<string, number>).secrets = 1;
  body.findings = [{
    id: "secret-finding",
    ruleId: "secrets.hardcoded-credential",
    title: "Hardcoded token ghp_abcdefghijklmnopqrstuvwxyz",
    severity: "high",
    category: "secrets",
    file: "src/config.ts",
    line: 4,
    snippet: "const TOKEN = \"ghp_abcdefghijklmnopqrstuvwxyz\";",
    description: "Credential in source.",
    impact: "Credential misuse.",
    remediation: "Move it to protected configuration.",
    confidence: "high",
  }];

  const response = await handleInsightsRequest(request(body));
  assert.equal(response.status, 200);
  const serialized = JSON.stringify(await response.json());
  assert.equal(serialized.includes("snippet"), false);
  assert.equal(serialized.includes("ghp_abcdefghijklmnopqrstuvwxyz"), false);
  assert.match(serialized, /REDACTED/);
});
