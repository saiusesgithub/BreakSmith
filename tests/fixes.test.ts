import assert from "node:assert/strict";
import test from "node:test";
import { generateFixSuggestion } from "../lib/fixes/generator";
import { deterministicFix } from "../lib/fixes/templates";
import type { Finding } from "../lib/scanner/types";

const MANAGED_ENV = [
  "GROQ_API_KEY", "GROQ_MODEL", "GEMINI_API_KEY", "GEMINI_MODEL",
  "BREAKSMITH_AI_ENABLED", "BREAKSMITH_AI_TIMEOUT_MS",
] as const;

const baseFinding: Finding = {
  id: "finding-fix-1",
  ruleId: "secrets.hardcoded-credential",
  title: "Hardcoded credential",
  severity: "high",
  category: "secrets",
  file: "src/auth.ts",
  line: 12,
  snippet: "const API_KEY = \"sk-abcdefghijklmnopqrstuvwxyz\";",
  description: "A credential appears in source code.",
  impact: "Anyone with source access could use it.",
  remediation: "Load the credential from a secret manager.",
  confidence: "high",
  cwe: "CWE-798",
};

const aiFix = {
  summary: "Use deployment configuration for the credential.",
  steps: ["Create a protected secret.", "Fail startup when it is absent."],
  after: "const API_KEY = process.env.API_KEY;\nif (!API_KEY) throw new Error(\"API_KEY is required\");",
  notes: ["Rotate the exposed value."],
  confidence: "high",
};

function groqResponse(value: unknown): Response {
  return new Response(JSON.stringify({ choices: [{ message: { content: JSON.stringify(value) } }] }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function geminiResponse(value: unknown): Response {
  return new Response(JSON.stringify({ candidates: [{ content: { parts: [{ text: JSON.stringify(value) }] } }] }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

async function withAiEnvironment(
  environment: Partial<Record<(typeof MANAGED_ENV)[number], string>>,
  mockFetch: typeof fetch,
  callback: () => Promise<void>,
): Promise<void> {
  const originalFetch = globalThis.fetch;
  const originalEnvironment = Object.fromEntries(MANAGED_ENV.map((name) => [name, process.env[name]]));
  globalThis.fetch = mockFetch;
  for (const name of MANAGED_ENV) delete process.env[name];
  Object.assign(process.env, environment);
  try {
    await callback();
  } finally {
    globalThis.fetch = originalFetch;
    for (const name of MANAGED_ENV) {
      const originalValue = originalEnvironment[name];
      if (originalValue === undefined) delete process.env[name];
      else process.env[name] = originalValue;
    }
  }
}

test("hardcoded-secret deterministic fix never reconstructs the credential", async () => {
  await withAiEnvironment({}, async () => { throw new Error("network must not be called"); }, async () => {
    const result = await generateFixSuggestion(baseFinding, "TypeScript");
    assert.equal(result.provider, "deterministic");
    assert.match(result.before, /REDACTED/);
    assert.equal(result.before.includes("sk-abcdefghijklmnopqrstuvwxyz"), false);
    assert.match(result.after, /process\.env\.API_KEY/);
    assert.match(result.diff, /^--- a\/src\/auth\.ts/m);
    assert.match(result.diff, /@@ suggested remediation @@/);
  });
});

test("AI disabled returns a deterministic fix without network calls", async () => {
  let calls = 0;
  await withAiEnvironment({
    BREAKSMITH_AI_ENABLED: "false",
    GROQ_API_KEY: "groq-test",
    GEMINI_API_KEY: "gemini-test",
  }, async () => {
    calls += 1;
    throw new Error("network must not be called");
  }, async () => {
    const result = await generateFixSuggestion(baseFinding);
    assert.equal(result.provider, "deterministic");
  });
  assert.equal(calls, 0);
});

test("SQL-injection deterministic fix uses a parameterized query", () => {
  const result = deterministicFix({
    ...baseFinding,
    ruleId: "injection.sql-user-input",
    category: "injection",
  });
  assert.match(result.after, /WHERE id = \?/);
  assert.match(result.after, /\[userId\]/);
  assert.match(result.notes.join(" "), /illustrative/i);
});

test("CORS deterministic fix replaces wildcard origin with an allowlist", () => {
  const result = deterministicFix({
    ...baseFinding,
    ruleId: "api-security.permissive-cors",
    category: "api-security",
  });
  assert.match(result.after, /trustedOrigins/);
  assert.doesNotMatch(result.after, /origin:\s*["']\*["']/);
  assert.match(result.notes.join(" "), /real trusted production origins/i);
});

test("weak-hash deterministic fix recommends password hashing, not SHA-256", () => {
  const result = deterministicFix({
    ...baseFinding,
    ruleId: "cryptography.weak-hash",
    category: "cryptography",
  });
  assert.match(result.after, /argon2/i);
  assert.match(result.notes.join(" "), /Do not replace.*SHA-256/i);
});

test("Groq success is returned without calling Gemini", async () => {
  const urls: string[] = [];
  await withAiEnvironment({ GROQ_API_KEY: "groq-test", GEMINI_API_KEY: "gemini-test" }, async (input) => {
    urls.push(String(input));
    return groqResponse(aiFix);
  }, async () => {
    const result = await generateFixSuggestion(baseFinding);
    assert.equal(result.provider, "groq");
    assert.equal(result.summary, aiFix.summary);
    assert.match(result.diff, /process\.env\.API_KEY/);
  });
  assert.equal(urls.length, 1);
  assert.match(urls[0], /api\.groq\.com/);
});

test("Groq failure falls back to Gemini", async () => {
  const urls: string[] = [];
  await withAiEnvironment({ GROQ_API_KEY: "groq-test", GEMINI_API_KEY: "gemini-test" }, async (input) => {
    urls.push(String(input));
    return String(input).includes("groq.com")
      ? new Response("rate limited", { status: 429 })
      : geminiResponse(aiFix);
  }, async () => {
    const result = await generateFixSuggestion(baseFinding);
    assert.equal(result.provider, "gemini");
  });
  assert.equal(urls.length, 2);
  assert.match(urls[0], /groq/);
  assert.match(urls[1], /googleapis/);
});

test("Groq and Gemini failures return deterministic output", async () => {
  await withAiEnvironment({ GROQ_API_KEY: "groq-test", GEMINI_API_KEY: "gemini-test" }, async () =>
    new Response("unavailable", { status: 503 }), async () => {
    const result = await generateFixSuggestion(baseFinding);
    assert.equal(result.provider, "deterministic");
    assert.match(result.after, /process\.env\.API_KEY/);
  });
});

test("malformed Groq output falls back to Gemini", async () => {
  let calls = 0;
  await withAiEnvironment({ GROQ_API_KEY: "groq-test", GEMINI_API_KEY: "gemini-test" }, async () => {
    calls += 1;
    return calls === 1
      ? groqResponse({ ...aiFix, steps: [] })
      : geminiResponse(aiFix);
  }, async () => {
    const result = await generateFixSuggestion(baseFinding);
    assert.equal(result.provider, "gemini");
  });
});

test("malformed Gemini output after Groq failure returns deterministic output", async () => {
  let calls = 0;
  await withAiEnvironment({ GROQ_API_KEY: "groq-test", GEMINI_API_KEY: "gemini-test" }, async () => {
    calls += 1;
    return calls === 1
      ? new Response("unavailable", { status: 503 })
      : geminiResponse({ ...aiFix, confidence: "certain" });
  }, async () => {
    const result = await generateFixSuggestion(baseFinding);
    assert.equal(result.provider, "deterministic");
  });
});

test("secret-like AI content is redacted across returned fields", async () => {
  const leaked = "ghp_abcdefghijklmnopqrstuvwxyz";
  await withAiEnvironment({ GROQ_API_KEY: "groq-test" }, async () => groqResponse({
    ...aiFix,
    summary: `Do not expose ${leaked}`,
    steps: [`Remove ${leaked}`],
    after: `const token = \"${leaked}\";`,
    notes: [`Rotate ${leaked}`],
  }), async () => {
    const result = await generateFixSuggestion(baseFinding);
    const serialized = JSON.stringify(result);
    assert.equal(serialized.includes(leaked), false);
    assert.match(serialized, /REDACTED/);
  });
});
