import type { ScannerRule } from "../types";
import { finding, getLines, snippet } from "./helpers";

const EXECUTION_API = /(?:\b(?:exec|execSync|spawn|spawnSync)\s*\(|Runtime\.getRuntime\(\)\.exec\s*\(|\bos\.system\s*\(|\bsubprocess\.(?:call|run|Popen|check_output)\s*\()/;
const SHELL_TRUE = /\bshell\s*=\s*True\b|\bshell\s*:\s*true\b/i;
const USER_CONTROLLED = /\b(?:req(?:uest)?\.(?:body|query|params)|ctx\.(?:request|params)|request\.(?:args|form|json)|userInput|userCommand|input)\b/i;

export const dangerousExecutionRule: ScannerRule = {
  id: "injection.command-execution",
  scan(file) {
    const results = [];
    const lines = getLines(file);

    for (let index = 0; index < lines.length; index += 1) {
      if (!EXECUTION_API.test(lines[index]) && !SHELL_TRUE.test(lines[index])) continue;
      const window = lines.slice(index, index + 3).join(" ");

      const directlyControlled = USER_CONTROLLED.test(window);
      results.push(
        finding(file, {
          ruleId: "injection.command-execution",
          title: directlyControlled ? "User-controlled command execution" : "Potentially dangerous command execution",
          severity: directlyControlled ? "critical" : "medium",
          category: "injection",
          line: index + 1,
          snippet: snippet(window),
          description: directlyControlled
            ? "A process execution API appears to receive request-controlled data."
            : "A shell or process execution API is used and requires careful input handling.",
          impact: "Unsafe command construction can allow attackers to execute operating-system commands with the application's privileges.",
          remediation: "Avoid shell execution for untrusted input. Use fixed argument arrays, strict allowlists, and APIs that do not invoke a shell.",
          confidence: directlyControlled ? "high" : "low",
          cwe: "CWE-78",
        }),
      );
      index += 2;
    }

    return results;
  },
};
