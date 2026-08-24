import { ENRICHMENT_SCHEMA, ENRICHMENT_SYSTEM_PROMPT, type FindingEnrichmentContext, type ProviderEnrichmentResult } from "../types";
import { parseEnrichment } from "../validation";
import { fetchJson } from "./request";

export const GEMINI_API_ROOT = "https://generativelanguage.googleapis.com/v1beta/models";
export const DEFAULT_GEMINI_MODEL = "gemini-3.5-flash-lite";

export async function enrichWithGemini(
  context: FindingEnrichmentContext,
  apiKey: string,
  timeoutMs: number,
): Promise<ProviderEnrichmentResult | null> {
  const model = process.env.GEMINI_MODEL ?? DEFAULT_GEMINI_MODEL;
  const body = await fetchJson(`${GEMINI_API_ROOT}/${encodeURIComponent(model)}:generateContent`, {
    method: "POST",
    headers: { "x-goog-api-key": apiKey, "Content-Type": "application/json" },
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: ENRICHMENT_SYSTEM_PROMPT }] },
      contents: [{ role: "user", parts: [{ text: JSON.stringify(context) }] }],
      generationConfig: {
        maxOutputTokens: 750,
        responseFormat: { text: { mimeType: "application/json", schema: ENRICHMENT_SCHEMA } },
      },
    }),
  }, timeoutMs);

  if (!body || typeof body !== "object") return null;
  const content = (body as { candidates?: Array<{ content?: { parts?: Array<{ text?: unknown }> } }> })
    .candidates?.[0]?.content?.parts?.[0]?.text;
  if (typeof content !== "string") return null;
  const enrichment = parseEnrichment(content);
  return enrichment ? { provider: "gemini", enrichment } : null;
}
