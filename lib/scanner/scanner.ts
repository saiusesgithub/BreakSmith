import { createHash } from "node:crypto";
import { DEFAULT_SCAN_LIMITS, walkSourceFiles } from "./file-walker";
import { DEFAULT_RULES } from "./rules";
import { redactSecrets } from "./rules/helpers";
import type { Finding, ScanLimits, ScannerRule, ScanResult } from "./types";

const MAX_FINDINGS = 500;
const MAX_FINDINGS_PER_RULE_PER_FILE = 20;

function findingId(finding: Omit<Finding, "id">): string {
  const input = `${finding.ruleId}\0${finding.file}\0${finding.line ?? 0}\0${finding.title}`;
  return createHash("sha256").update(input).digest("hex").slice(0, 24);
}

export async function scanRepository(
  root: string,
  options: { rules?: ScannerRule[]; limits?: Partial<ScanLimits> } = {},
): Promise<ScanResult> {
  const limits = { ...DEFAULT_SCAN_LIMITS, ...options.limits };
  const { files, scannedBytes, truncated: fileWalkTruncated } = await walkSourceFiles(root, limits);
  const findings: Finding[] = [];
  const seen = new Set<string>();
  let truncated = fileWalkTruncated;

  for (const file of files) {
    for (const rule of options.rules ?? DEFAULT_RULES) {
      let ruleFindings: Omit<Finding, "id">[];
      try {
        ruleFindings = rule.scan(file).slice(0, MAX_FINDINGS_PER_RULE_PER_FILE);
      } catch {
        continue;
      }

      for (const candidate of ruleFindings) {
        const sanitizedCandidate = candidate.snippet
          ? { ...candidate, snippet: redactSecrets(candidate.snippet) }
          : candidate;
        const id = findingId(sanitizedCandidate);
        if (seen.has(id)) continue;
        seen.add(id);
        findings.push({ id, ...sanitizedCandidate });
        if (findings.length >= MAX_FINDINGS) {
          truncated = true;
          break;
        }
      }
      if (findings.length >= MAX_FINDINGS) break;
    }
    if (findings.length >= MAX_FINDINGS) break;
  }

  return { findings, scannedFiles: files.length, scannedBytes, truncated };
}
