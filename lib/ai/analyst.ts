import { redactSecrets } from "../scanner/rules/helpers";
import type { Finding } from "../scanner/types";
import { enrichWithGemini } from "./providers/gemini";
import { enrichWithGroq } from "./providers/groq";
import { aiTimeoutMs } from "./providers/request";
import type { AiProviderName, FindingEnrichmentContext, ProviderEnrichmentResult } from "./types";

const DEFAULT_MAX_FINDINGS = 8;
const MAX_FINDINGS_CAP = 20;
const ENRICHMENT_CONCURRENCY = 5;
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;

function boundedInteger(value: string | undefined, fallback: number, minimum: number, maximum: number): number {
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isFinite(parsed) ? Math.max(minimum, Math.min(parsed, maximum)) : fallback;
}

function findingContext(finding: Finding): FindingEnrichmentContext {
  return {
    title: finding.title,
    ruleId: finding.ruleId,
    severity: finding.severity,
    category: finding.category,
    confidence: finding.confidence,
    file: redactSecrets(finding.file),
    snippet: finding.snippet ? redactSecrets(finding.snippet.slice(0, 300)) : undefined,
    description: redactSecrets(finding.description),
    impact: redactSecrets(finding.impact),
    remediation: redactSecrets(finding.remediation),
  };
}

type EnrichmentOutcome = { finding: Finding; provider: AiProviderName };
type ConfiguredProvider = Exclude<AiProviderName, "deterministic">;

async function enrichFindingWithProvider(
  finding: Finding,
  provider: ConfiguredProvider,
  apiKey: string,
  timeoutMs: number,
): Promise<EnrichmentOutcome> {
  const context = findingContext(finding);
  const result: ProviderEnrichmentResult | null = provider === "groq"
    ? await enrichWithGroq(context, apiKey, timeoutMs)
    : await enrichWithGemini(context, apiKey, timeoutMs);
  if (!result) return { finding, provider: "deterministic" };

  return {
    provider: result.provider,
    finding: {
      ...finding,
      ...result.enrichment,
      metadata: { ...finding.metadata, aiEnriched: true, aiProvider: result.provider },
    },
  };
}

async function mapWithConcurrency<T, R>(
  values: T[],
  concurrency: number,
  operation: (value: T) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(values.length);
  let nextIndex = 0;
  async function worker(): Promise<void> {
    while (nextIndex < values.length) {
      const index = nextIndex;
      nextIndex += 1;
      results[index] = await operation(values[index]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, values.length) }, () => worker()));
  return results;
}

export async function enrichFindings(findings: Finding[]): Promise<Finding[]> {
  if (process.env.BREAKSMITH_AI_ENABLED?.toLowerCase() === "false") return findings;
  const groqApiKey = process.env.GROQ_API_KEY;
  const geminiApiKey = process.env.GEMINI_API_KEY;
  if (!groqApiKey && !geminiApiKey) return findings;

  const maxFindings = boundedInteger(
    process.env.BREAKSMITH_AI_MAX_FINDINGS,
    DEFAULT_MAX_FINDINGS,
    1,
    MAX_FINDINGS_CAP,
  );
  const timeoutMs = aiTimeoutMs();
  const selected = [...findings]
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])
    .slice(0, maxFindings);
  if (selected.length === 0) return findings;

  let outcomes: EnrichmentOutcome[] = groqApiKey
    ? await mapWithConcurrency(selected, ENRICHMENT_CONCURRENCY, (finding) =>
        enrichFindingWithProvider(finding, "groq", groqApiKey, timeoutMs))
    : selected.map((finding) => ({ finding, provider: "deterministic" }));

  if (geminiApiKey) {
    const fallbackIndexes = outcomes
      .map((outcome, index) => outcome.provider === "deterministic" ? index : -1)
      .filter((index) => index >= 0);
    const fallbacks = await mapWithConcurrency(fallbackIndexes, ENRICHMENT_CONCURRENCY, (index) =>
      enrichFindingWithProvider(outcomes[index].finding, "gemini", geminiApiKey, timeoutMs));
    outcomes = [...outcomes];
    fallbackIndexes.forEach((outcomeIndex, index) => {
      outcomes[outcomeIndex] = fallbacks[index];
    });
  }

  const byId = new Map(outcomes.map((outcome) => [outcome.finding.id, outcome.finding]));
  return findings.map((finding) => byId.get(finding.id) ?? finding);
}
