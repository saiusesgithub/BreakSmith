import { ENRICHMENT_SCHEMA, ENRICHMENT_SYSTEM_PROMPT, type FindingEnrichmentContext, type ProviderEnrichmentResult } from "../types";
import { parseEnrichment } from "../validation";
import { fetchJson } from "./request";

const GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions";
const DEFAULT_GROQ_MODEL = "openai/gpt-oss-20b";

export async function enrichWithGroq(
  context: FindingEnrichmentContext,
  apiKey: string,
  timeoutMs: number,
): Promise<ProviderEnrichmentResult | null> {
  const body = await fetchJson(GROQ_API_URL, {
    method: "POST",
    headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      model: process.env.GROQ_MODEL ?? DEFAULT_GROQ_MODEL,
      messages: [
        { role: "system", content: ENRICHMENT_SYSTEM_PROMPT },
        { role: "user", content: JSON.stringify(context) },
      ],
      max_completion_tokens: 750,
      response_format: {
        type: "json_schema",
        json_schema: { name: "security_finding_enrichment", strict: true, schema: ENRICHMENT_SCHEMA },
      },
    }),
  }, timeoutMs);

  if (!body || typeof body !== "object") return null;
  const content = (body as { choices?: Array<{ message?: { content?: unknown } }> })
    .choices?.[0]?.message?.content;
  if (typeof content !== "string") return null;
  const enrichment = parseEnrichment(content);
  return enrichment ? { provider: "groq", enrichment } : null;
}
