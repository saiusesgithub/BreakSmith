import assert from "node:assert/strict";
import test from "node:test";
import { handleFixRequest } from "../app/api/fix/route";
import type { Finding } from "../lib/scanner/types";

const finding: Finding = {
  id: "api-fix-1",
  ruleId: "configuration.debug-enabled",
  title: "Debug mode enabled",
  severity: "medium",
  category: "configuration",
  file: "server.ts",
  line: 8,
  snippet: "startApplication({ debug: true });",
  description: "Debug behavior appears enabled.",
  impact: "Production errors may expose details.",
  remediation: "Disable debug behavior in production.",
  confidence: "high",
};

function request(body: unknown): Request {
  return new Request("http://localhost/api/fix", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

test("invalid fix request returns clean 400 JSON", async () => {
  const response = await handleFixRequest(request({ finding: { id: "missing-fields" } }));
  assert.equal(response.status, 400);
  const body = await response.json() as { error?: unknown };
  assert.equal(typeof body.error, "string");
});

test("unsafe finding path is rejected", async () => {
  const response = await handleFixRequest(request({ finding: { ...finding, file: "../../secret.txt" } }));
  assert.equal(response.status, 400);
});

test("successful deterministic fix response is frontend-friendly", async () => {
  const originalEnabled = process.env.BREAKSMITH_AI_ENABLED;
  process.env.BREAKSMITH_AI_ENABLED = "false";
  try {
    const response = await handleFixRequest(request({ finding, language: "TypeScript" }));
    assert.equal(response.status, 200);
    const body = await response.json() as Record<string, unknown>;
    assert.deepEqual(Object.keys(body).sort(), [
      "after", "before", "confidence", "diff", "findingId", "notes",
      "provider", "status", "steps", "summary",
    ]);
    assert.equal(body.findingId, finding.id);
    assert.equal(body.status, "suggested");
    assert.equal(body.provider, "deterministic");
    assert.equal(typeof body.diff, "string");
    assert.equal(Array.isArray(body.steps), true);
    assert.equal(Array.isArray(body.notes), true);
  } finally {
    if (originalEnabled === undefined) delete process.env.BREAKSMITH_AI_ENABLED;
    else process.env.BREAKSMITH_AI_ENABLED = originalEnabled;
  }
});

test("AI provider failures never fail the fix endpoint", async () => {
  const originalFetch = globalThis.fetch;
  const originalGroqKey = process.env.GROQ_API_KEY;
  const originalGeminiKey = process.env.GEMINI_API_KEY;
  const originalEnabled = process.env.BREAKSMITH_AI_ENABLED;
  globalThis.fetch = async () => { throw new Error("provider network failure"); };
  process.env.GROQ_API_KEY = "groq-test";
  process.env.GEMINI_API_KEY = "gemini-test";
  delete process.env.BREAKSMITH_AI_ENABLED;
  try {
    const response = await handleFixRequest(request({ finding, language: "TypeScript" }));
    assert.equal(response.status, 200);
    const body = await response.json() as { provider?: unknown; status?: unknown; findingId?: unknown };
    assert.equal(body.provider, "deterministic");
    assert.equal(body.status, "suggested");
    assert.equal(body.findingId, finding.id);
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
