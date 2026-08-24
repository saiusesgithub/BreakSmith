import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { handleScanRequest, POST } from "../app/api/scan/route";

test("scan API returns JSON validation errors", async () => {
  const response = await POST(new Request("http://localhost/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repoUrl: "https://example.com/not/github" }),
  }));
  assert.equal(response.status, 400);
  assert.match((await response.json() as { error: string }).error, /GitHub/i);
});

test("scan API rejects malformed JSON", async () => {
  const response = await POST(new Request("http://localhost/api/scan", { method: "POST", body: "{" }));
  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { error: "Request body must be valid JSON." });
});

test("successful scan response preserves the frozen frontend contract", async () => {
  const originalEnabled = process.env.BREAKSMITH_AI_ENABLED;
  process.env.BREAKSMITH_AI_ENABLED = "false";
  try {
    const fixture = path.resolve("tests", "fixtures", "vulnerable-app");
    const response = await handleScanRequest(new Request("http://localhost/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repoUrl: "https://github.com/example/vulnerable-app" }),
    }), async (_repository, operation) => operation(fixture));

    assert.equal(response.status, 200);
    const body = await response.json() as Record<string, unknown>;
    assert.deepEqual(Object.keys(body).sort(), [
      "categories", "durationMs", "findings", "repo", "riskLevel",
      "scanId", "scannedFiles", "score", "summary",
    ]);
    assert.equal(typeof body.scanId, "string");
    assert.equal(typeof body.score, "number");
    assert.equal(typeof body.riskLevel, "string");
    assert.equal(typeof body.scannedFiles, "number");
    assert.equal(typeof body.durationMs, "number");
    assert.ok(Array.isArray(body.findings));

    const repo = body.repo as Record<string, unknown>;
    assert.deepEqual(Object.keys(repo).sort(), ["name", "owner", "url"]);
    assert.equal(Object.values(repo).every((value) => typeof value === "string"), true);

    const summary = body.summary as Record<string, unknown>;
    assert.deepEqual(Object.keys(summary).sort(), ["critical", "high", "low", "medium", "total"]);
    assert.equal(Object.values(summary).every((value) => typeof value === "number"), true);

    const categories = body.categories as Record<string, unknown>;
    assert.deepEqual(Object.keys(categories).sort(), [
      "api-security", "authentication", "authorization", "configuration", "cryptography",
      "dependencies", "injection", "other", "secrets",
    ]);
    assert.equal(Object.values(categories).every((value) => typeof value === "number"), true);
  } finally {
    if (originalEnabled === undefined) delete process.env.BREAKSMITH_AI_ENABLED;
    else process.env.BREAKSMITH_AI_ENABLED = originalEnabled;
  }
});

test("scan API succeeds when both AI providers throw", async () => {
  const originalFetch = globalThis.fetch;
  const originalGroqKey = process.env.GROQ_API_KEY;
  const originalGeminiKey = process.env.GEMINI_API_KEY;
  const originalEnabled = process.env.BREAKSMITH_AI_ENABLED;
  let providerCalls = 0;
  globalThis.fetch = async () => {
    providerCalls += 1;
    throw new Error("simulated provider outage");
  };
  process.env.GROQ_API_KEY = "groq-test";
  process.env.GEMINI_API_KEY = "gemini-test";
  delete process.env.BREAKSMITH_AI_ENABLED;

  try {
    const fixture = path.resolve("tests", "fixtures", "vulnerable-app");
    const response = await handleScanRequest(new Request("http://localhost/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repoUrl: "https://github.com/example/vulnerable-app" }),
    }), async (_repository, operation) => operation(fixture));

    assert.equal(response.status, 200);
    const body = await response.json() as { findings: Array<{ metadata?: { aiEnriched?: boolean } }> };
    assert.ok(body.findings.length > 0);
    assert.equal(body.findings.some((finding) => finding.metadata?.aiEnriched), false);
    assert.ok(providerCalls >= 2);
  } finally {
    globalThis.fetch = originalFetch;
    if (originalGroqKey === undefined) delete process.env.GROQ_API_KEY;
    else process.env.GROQ_API_KEY = originalGroqKey;
    if (originalGeminiKey === undefined) delete process.env.GEMINI_API_KEY;
    else process.env.GEMINI_API_KEY = originalGeminiKey;
    if (originalEnabled === undefined) delete process.env.BREAKSMITH_AI_ENABLED;
    else process.env.BREAKSMITH_AI_ENABLED = originalEnabled;
  }
});
