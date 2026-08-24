import type { ScannerRule } from "../types";
import { finding, getLines, snippet } from "./helpers";

const WILDCARD_CORS = /(?:\borigin\s*:\s*["']\*["']|allow_origins\s*=\s*\[\s*["']\*["']\s*\]|Access-Control-Allow-Origin["']?\s*[,=:]\s*["']\*["'])/i;

export const permissiveCorsRule: ScannerRule = {
  id: "api-security.permissive-cors",
  scan(file) {
    const lines = getLines(file);
    const credentialsEnabled = /(?:credentials\s*:\s*true|allow_credentials\s*=\s*True)/i.test(file.content);
    const results = [];

    for (let index = 0; index < lines.length; index += 1) {
      if (!WILDCARD_CORS.test(lines[index])) continue;
      results.push(
        finding(file, {
          ruleId: "api-security.permissive-cors",
          title: credentialsEnabled ? "Wildcard CORS with credentials" : "Permissive wildcard CORS",
          severity: credentialsEnabled ? "high" : "medium",
          category: "api-security",
          line: index + 1,
          snippet: snippet(lines[index]),
          description: "The application appears to allow cross-origin requests from any origin.",
          impact: credentialsEnabled
            ? "Untrusted sites may be able to issue credentialed requests and access sensitive responses."
            : "Any website can call the exposed browser-facing endpoint, increasing the risk of unintended data access.",
          remediation: "Replace the wildcard with an explicit allowlist of trusted origins and avoid cross-origin credentials unless required.",
          confidence: "high",
          cwe: "CWE-942",
        }),
      );
    }
    return results;
  },
};
