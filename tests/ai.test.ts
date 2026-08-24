import assert from "node:assert/strict";
import test from "node:test";
import { enrichFindings } from "../lib/ai/analyst";
import type { Finding } from "../lib/scanner/types";

const MANAGED_ENV = [
  "GROQ_API_KEY", "GROQ_MODEL", "GEMINI_API_KEY", "GEMINI_MODEL",
  "BREAKSMITH_AI_ENABLED", "BREAKSMITH_AI_MAX_FINDINGS", "BREAKSMITH_AI_TIMEOUT_MS",
] as const;

const baseFinding: Finding = {
  id: "finding-1", ruleId: "test.rule", title: "Test finding", severity: "high",
  category: "configuration", file: "src/test.ts", snippet: "unsafe()",
  description: "Original description", impact: "Original impact",
  remediation: "Original remediation", confidence: "medium",
};

const enrichment = {
  description: "Improved description",
  impact: "Improved impact",
  remediation: "Improved remediation",
};

function groqResponse(value: unknown): Response {
  return new Response(JSON.stringify({ choices: [{ message: { content: JSON.stringify(value) } }] }), {
    status: 200, headers: { "Content-Type": "application/json" },
  });
}

function geminiResponse(value: unknown): Response {
  return new Response(JSON.stringify({ candidates: [{ content: { parts: [{ text: JSON.stringify(value) }] } }] }), {
    status: 200, headers: { "Content-Type": "application/json" },
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

test("AI disabled returns deterministic output without network calls", async () => {
  let calls = 0;
  await withAiEnvironment(
    { BREAKSMITH_AI_ENABLED: "false", GROQ_API_KEY: "groq-test", GEMINI_API_KEY: "gemini-test" },
    async () => { calls += 1; throw new Error("must not be called"); },
    async () => assert.deepEqual(await enrichFindings([baseFinding]), [baseFinding]),
  );
  assert.equal(calls, 0);
});

test("no provider keys returns deterministic output", async () => {
  let calls = 0;
  await withAiEnvironment({}, async () => { calls += 1; throw new Error("must not be called"); }, async () => {
    assert.deepEqual(await enrichFindings([baseFinding]), [baseFinding]);
  });
  assert.equal(calls, 0);
});

test("Groq success enriches without calling Gemini", async () => {
  const urls: string[] = [];
  await withAiEnvironment({ GROQ_API_KEY: "groq-test", GEMINI_API_KEY: "gemini-test" }, async (input) => {
    urls.push(String(input));
    return groqResponse(enrichment);
  }, async () => {
    const [finding] = await enrichFindings([baseFinding]);
    assert.equal(finding.description, enrichment.description);
    assert.equal(finding.metadata?.aiProvider, "groq");
  });
  assert.equal(urls.length, 1);
  assert.match(urls[0], /api\.groq\.com/);
});

test("Groq failure falls back to Gemini with the same redacted context", async () => {
  const contexts: string[] = [];
  await withAiEnvironment({ GROQ_API_KEY: "groq-test", GEMINI_API_KEY: "gemini-test" }, async (input, init) => {
    const requestBody = JSON.parse(String(init?.body)) as {
      messages?: Array<{ content: string }>;
      contents?: Array<{ parts: Array<{ text: string }> }>;
    };
    if (String(input).includes("groq.com")) {
      contexts.push(requestBody.messages?.[1]?.content ?? "");
      return new Response("rate limited", { status: 429 });
    }
    contexts.push(requestBody.contents?.[0]?.parts?.[0]?.text ?? "");
    return geminiResponse(enrichment);
  }, async () => {
    const [finding] = await enrichFindings([baseFinding]);
    assert.equal(finding.metadata?.aiProvider, "gemini");
    assert.equal(finding.impact, enrichment.impact);
  });
  assert.equal(contexts.length, 2);
  assert.equal(contexts[0], contexts[1]);
});

test("both provider failures preserve deterministic output", async () => {
  let calls = 0;
  await withAiEnvironment({ GROQ_API_KEY: "groq-test", GEMINI_API_KEY: "gemini-test" }, async () => {
    calls += 1;
    if (calls === 1) throw new Error("Groq unavailable");
    return new Response("Gemini unavailable", { status: 503 });
  }, async () => assert.deepEqual(await enrichFindings([baseFinding]), [baseFinding]));
  assert.equal(calls, 2);
});

test("malformed Groq JSON triggers Gemini fallback", async () => {
  let calls = 0;
  await withAiEnvironment({ GROQ_API_KEY: "groq-test", GEMINI_API_KEY: "gemini-test" }, async () => {
    calls += 1;
    return calls === 1
      ? new Response(JSON.stringify({ choices: [{ message: { content: "{" } }] }), { status: 200 })
      : geminiResponse(enrichment);
  }, async () => {
    const [finding] = await enrichFindings([baseFinding]);
    assert.equal(finding.metadata?.aiProvider, "gemini");
  });
});

test("malformed Gemini JSON after Groq failure preserves deterministic output", async () => {
  let calls = 0;
  await withAiEnvironment({ GROQ_API_KEY: "groq-test", GEMINI_API_KEY: "gemini-test" }, async () => {
    calls += 1;
    return calls === 1
      ? new Response("Groq unavailable", { status: 500 })
      : new Response(JSON.stringify({ candidates: [{ content: { parts: [{ text: "{" }] } }] }), { status: 200 });
  }, async () => assert.deepEqual(await enrichFindings([baseFinding]), [baseFinding]));
});

test("secret-like AI output is redacted before returning", async () => {
  await withAiEnvironment({ GROQ_API_KEY: "groq-test" }, async () => groqResponse({
    ...enrichment,
    description: "Leaked ghp_abcdefghijklmnopqrstuvwxyz in generated prose",
  }), async () => {
    const [finding] = await enrichFindings([baseFinding]);
    assert.match(finding.description, /REDACTED/);
    assert.equal(finding.description.includes("ghp_abcdefghijklmnopqrstuvwxyz"), false);
  });
});

test("invalid non-empty-field output is treated as provider failure", async () => {
  await withAiEnvironment({ GROQ_API_KEY: "groq-test", GEMINI_API_KEY: "gemini-test" }, async (input) =>
    String(input).includes("groq.com")
      ? groqResponse({ ...enrichment, impact: "" })
      : geminiResponse(enrichment), async () => {
    const [finding] = await enrichFindings([baseFinding]);
    assert.equal(finding.metadata?.aiProvider, "gemini");
  });
});

test("maximum finding selection is preserved", async () => {
  const findings = [
    { ...baseFinding, id: "low", severity: "low" as const },
    { ...baseFinding, id: "critical", severity: "critical" as const },
    { ...baseFinding, id: "medium", severity: "medium" as const },
  ];
  let calls = 0;
  await withAiEnvironment({ GROQ_API_KEY: "groq-test", BREAKSMITH_AI_MAX_FINDINGS: "1" }, async () => {
    calls += 1;
    return groqResponse(enrichment);
  }, async () => {
    const result = await enrichFindings(findings);
    assert.equal(result.find((finding) => finding.id === "critical")?.metadata?.aiProvider, "groq");
    assert.equal(result.find((finding) => finding.id === "low")?.metadata?.aiProvider, undefined);
  });
  assert.equal(calls, 1);
});

test("timed out Groq request falls back to Gemini", async () => {
  let calls = 0;
  await withAiEnvironment({
    GROQ_API_KEY: "groq-test",
    GEMINI_API_KEY: "gemini-test",
    BREAKSMITH_AI_TIMEOUT_MS: "500",
  }, async (_input, init) => {
    calls += 1;
    if (calls === 2) return geminiResponse(enrichment);
    return await new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
    });
  }, async () => {
    const [finding] = await enrichFindings([baseFinding]);
    assert.equal(finding.metadata?.aiProvider, "gemini");
  });
  assert.equal(calls, 2);
});

test("Gemini fallback phase starts only after all Groq attempts finish", async () => {
  let activeGroqCalls = 0;
  let geminiStartedDuringGroq = false;
  const findings = [baseFinding, { ...baseFinding, id: "finding-2" }];
  await withAiEnvironment({ GROQ_API_KEY: "groq-test", GEMINI_API_KEY: "gemini-test" }, async (input) => {
    if (String(input).includes("groq.com")) {
      activeGroqCalls += 1;
      await new Promise<void>((resolve) => setTimeout(resolve, 10));
      activeGroqCalls -= 1;
      return new Response("Groq unavailable", { status: 503 });
    }
    if (activeGroqCalls > 0) geminiStartedDuringGroq = true;
    return geminiResponse(enrichment);
  }, async () => {
    const result = await enrichFindings(findings);
    assert.equal(result.every((finding) => finding.metadata?.aiProvider === "gemini"), true);
  });
  assert.equal(geminiStartedDuringGroq, false);
});
