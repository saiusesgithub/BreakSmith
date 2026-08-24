import { redactSecrets } from "../scanner/rules/helpers";
import type { Finding } from "../scanner/types";
import type { ProviderFixResult } from "../fixes/types";
import { parseFixContent } from "../fixes/validation";
import { DEFAULT_GEMINI_MODEL, GEMINI_API_ROOT } from "./providers/gemini";
import { DEFAULT_GROQ_MODEL, GROQ_API_URL } from "./providers/groq";
import { aiTimeoutMs, fetchJson } from "./providers/request";

export const FIX_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["summary", "steps", "after", "notes", "confidence"],
  properties: {
    summary: { type: "string", minLength: 1, maxLength: 1_000 },
    steps: {
      type: "array",
      minItems: 1,
      maxItems: 8,
      items: { type: "string", minLength: 1, maxLength: 1_000 },
    },
    after: { type: "string", minLength: 1, maxLength: 8_000 },
    notes: {
      type: "array",
      minItems: 1,
      maxItems: 8,
      items: { type: "string", minLength: 1, maxLength: 1_000 },
    },
    confidence: { type: "string", enum: ["high", "medium", "low"] },
  },
} as const;

const FIX_SYSTEM_PROMPT = `You improve a remediation suggestion for one finding already detected by BreakSmith.
The deterministic finding is the source of truth. Do not discover or invent a different vulnerability.
Do not change severity, category, rule ID, file path, or line number. Do not claim a patch was applied.
Never reconstruct, infer, or guess redacted credentials. Never include a real credential or environment value.
Return concise, safe replacement code suitable for review. If framework context is missing, be explicit and lower confidence.
Return JSON only with exactly: summary, steps, after, notes, confidence.`;

type FixContext = {
  ruleId: string;
  title: string;
  severity: Finding["severity"];
  category: Finding["category"];
  confidence: Finding["confidence"];
  file: string;
  line?: number;
  cwe?: string;
  snippet?: string;
  description: string;
  impact: string;
  remediation: string;
  language?: string;
};

function fixContext(finding: Finding, language?: string): FixContext {
  return {
    ruleId: finding.ruleId,
    title: redactSecrets(finding.title),
    severity: finding.severity,
    category: finding.category,
    confidence: finding.confidence,
    file: redactSecrets(finding.file),
    line: finding.line,
    cwe: finding.cwe,
    snippet: finding.snippet ? redactSecrets(finding.snippet.slice(0, 2_000)) : undefined,
    description: redactSecrets(finding.description),
    impact: redactSecrets(finding.impact),
    remediation: redactSecrets(finding.remediation),
    language: language ? redactSecrets(language) : undefined,
  };
}

async function fixWithGroq(
  context: FixContext,
  apiKey: string,
  timeoutMs: number,
): Promise<ProviderFixResult | null> {
  const body = await fetchJson(GROQ_API_URL, {
    method: "POST",
    headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      model: process.env.GROQ_MODEL ?? DEFAULT_GROQ_MODEL,
      messages: [
        { role: "system", content: FIX_SYSTEM_PROMPT },
        { role: "user", content: JSON.stringify(context) },
      ],
      max_completion_tokens: 1_200,
      response_format: {
        type: "json_schema",
        json_schema: { name: "breaksmith_fix_suggestion", strict: true, schema: FIX_SCHEMA },
      },
    }),
  }, timeoutMs);
  if (!body || typeof body !== "object") return null;
  const output = (body as { choices?: Array<{ message?: { content?: unknown } }> })
    .choices?.[0]?.message?.content;
  const content = parseFixContent(output);
  return content ? { provider: "groq", content } : null;
}

async function fixWithGemini(
  context: FixContext,
  apiKey: string,
  timeoutMs: number,
): Promise<ProviderFixResult | null> {
  const model = process.env.GEMINI_MODEL ?? DEFAULT_GEMINI_MODEL;
  const body = await fetchJson(`${GEMINI_API_ROOT}/${encodeURIComponent(model)}:generateContent`, {
    method: "POST",
    headers: { "x-goog-api-key": apiKey, "Content-Type": "application/json" },
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: FIX_SYSTEM_PROMPT }] },
      contents: [{ role: "user", parts: [{ text: JSON.stringify(context) }] }],
      generationConfig: {
        maxOutputTokens: 1_200,
        responseFormat: { text: { mimeType: "application/json", schema: FIX_SCHEMA } },
      },
    }),
  }, timeoutMs);
  if (!body || typeof body !== "object") return null;
  const output = (body as { candidates?: Array<{ content?: { parts?: Array<{ text?: unknown }> } }> })
    .candidates?.[0]?.content?.parts?.[0]?.text;
  const content = parseFixContent(output);
  return content ? { provider: "gemini", content } : null;
}

export async function suggestFixWithAi(
  finding: Finding,
  language?: string,
): Promise<ProviderFixResult | null> {
  if (process.env.BREAKSMITH_AI_ENABLED?.toLowerCase() === "false") return null;
  const context = fixContext(finding, language);
  const timeoutMs = aiTimeoutMs();

  if (process.env.GROQ_API_KEY) {
    const groq = await fixWithGroq(context, process.env.GROQ_API_KEY, timeoutMs);
    if (groq) return groq;
  }
  if (process.env.GEMINI_API_KEY) {
    return await fixWithGemini(context, process.env.GEMINI_API_KEY, timeoutMs);
  }
  return null;
}
