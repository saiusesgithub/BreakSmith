import type { Finding } from "../scanner/types";

export type AiProviderName = "groq" | "gemini" | "deterministic";

export type FindingEnrichmentContext = Pick<
  Finding,
  | "title"
  | "ruleId"
  | "severity"
  | "category"
  | "confidence"
  | "file"
  | "snippet"
  | "description"
  | "impact"
  | "remediation"
>;

export type FindingEnrichment = {
  description: string;
  impact: string;
  remediation: string;
};

export type ProviderEnrichmentResult = {
  provider: Exclude<AiProviderName, "deterministic">;
  enrichment: FindingEnrichment;
};

export const ENRICHMENT_SCHEMA = {
  type: "object",
  properties: {
    description: { type: "string", description: "A concise explanation supported by the deterministic evidence." },
    impact: { type: "string", description: "A concise realistic impact without overstating certainty." },
    remediation: { type: "string", description: "Specific, actionable remediation guidance." },
  },
  required: ["description", "impact", "remediation"],
  additionalProperties: false,
} as const;

export const ENRICHMENT_SYSTEM_PROMPT = [
  "You edit explanations for findings produced by a deterministic security scanner.",
  "The scanner is the source of truth. Do not discover new vulnerabilities or change severity, confidence, file path, line number, or other metadata.",
  "Improve only description, impact, and remediation. Keep each field concise and grounded in the supplied evidence.",
  "Never reconstruct, infer, or guess redacted credentials or secret values.",
  "Return only the requested JSON object.",
].join(" ");
