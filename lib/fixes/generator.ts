import { suggestFixWithAi } from "../ai/fix-analyst";
import { redactSecrets } from "../scanner/rules/helpers";
import type { Finding } from "../scanner/types";
import { suggestedDiff } from "./diff";
import { deterministicFix } from "./templates";
import type { FixContent, FixSuggestion } from "./types";

function redactContent(content: FixContent): FixContent {
  return {
    summary: redactSecrets(content.summary),
    steps: content.steps.map((step) => redactSecrets(step)),
    after: redactSecrets(content.after),
    notes: content.notes.map((note) => redactSecrets(note)),
    confidence: content.confidence,
  };
}

export async function generateFixSuggestion(finding: Finding, language?: string): Promise<FixSuggestion> {
  const deterministic = redactContent(deterministicFix(finding, language));
  let ai: Awaited<ReturnType<typeof suggestFixWithAi>> = null;
  try {
    ai = await suggestFixWithAi(finding, language);
  } catch {
    ai = null;
  }
  if (ai && ai.content.after.trim() === redactSecrets(finding.snippet ?? "").trim()) ai = null;
  const content = redactContent(ai?.content ?? deterministic);
  const before = redactSecrets(
    finding.snippet?.trim() || "// Original code was not included in the finding.",
  );
  const after = redactSecrets(content.after);

  return {
    findingId: finding.id,
    status: "suggested",
    provider: ai?.provider ?? "deterministic",
    summary: redactSecrets(content.summary),
    steps: content.steps.map((step) => redactSecrets(step)),
    before,
    after,
    diff: suggestedDiff(finding.file, before, after),
    notes: content.notes.map((note) => redactSecrets(note)),
    confidence: content.confidence,
  };
}
