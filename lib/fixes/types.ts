import type { Confidence, Finding } from "../scanner/types";

export type FixProvider = "groq" | "gemini" | "deterministic";

export type FixRequest = {
  finding: Finding;
  language?: string;
};

export type FixContent = {
  summary: string;
  steps: string[];
  after: string;
  notes: string[];
  confidence: Confidence;
};

export type FixSuggestion = FixContent & {
  findingId: string;
  status: "suggested";
  provider: FixProvider;
  before: string;
  diff: string;
};

export type ProviderFixResult = {
  provider: Exclude<FixProvider, "deterministic">;
  content: FixContent;
};
