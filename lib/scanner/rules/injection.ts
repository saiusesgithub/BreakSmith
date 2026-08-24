import type { ScannerRule } from "../types";
import { finding, getLines, snippet } from "./helpers";

const SQL_WORDS = /\b(?:select|insert|update|delete|drop|alter)\b/i;
const QUERY_CALL = /\b(?:query|execute|raw|executescript|createNativeQuery)\s*\(/i;
const DYNAMIC_VALUE = /(?:\+\s*(?:req(?:uest)?\.|ctx\.|params\b|userInput\b|input\b)|\$\{\s*(?:req(?:uest)?\.|ctx\.|params\b|userInput\b|input\b)|%\s*(?:request\.|req\.|params\b|input\b)|\.format\([^)]*(?:request\.|req\.|params\b|input\b))/i;

export const sqlInjectionRule: ScannerRule = {
  id: "injection.sql-user-input",
  scan(file) {
    const results = [];
    const lines = getLines(file);

    for (let index = 0; index < lines.length; index += 1) {
      if (!QUERY_CALL.test(lines[index])) continue;
      const window = lines.slice(index, index + 3).join(" ");
      if (!SQL_WORDS.test(window) || !DYNAMIC_VALUE.test(window)) continue;

      results.push(
        finding(file, {
          ruleId: "injection.sql-user-input",
          title: "Potential SQL injection",
          severity: "high",
          category: "injection",
          line: index + 1,
          snippet: snippet(window),
          description: "A SQL statement appears to incorporate a request-controlled value through string construction.",
          impact: "An attacker may be able to alter the query, read or modify data, or bypass application checks.",
          remediation: "Use parameterized queries or prepared statements and pass untrusted values separately from SQL text.",
          confidence: "medium",
          cwe: "CWE-89",
        }),
      );
      index += 2;
    }

    return results;
  },
};
