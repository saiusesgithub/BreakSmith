import type { ScannerRule } from "../types";
import { finding, getLines, redactLine } from "./helpers";

const ASSIGNMENT_PATTERN =
  /\b(?:aws[_-]?(?:access[_-]?key[_-]?id|secret[_-]?access[_-]?key)|jwt[_-]?secret|api[_-]?key|apikey|client[_-]?secret|database[_-]?password|db[_-]?(?:password|passwd)|password|passwd|auth[_-]?token|access[_-]?token|secret[_-]?key)\b["']?\s*[=:]\s*["']([^"'\r\n]{6,})["']/i;
const GENERIC_PLACEHOLDER =
  /^(?:changeme|replace[_-]?me|your[_-]|example|sample|dummy|fake|test|todo|xxx|\*+|<[^>]+>|\$\{)/i;

export const hardcodedSecretsRule: ScannerRule = {
  id: "secrets.hardcoded-credential",
  scan(file) {
    const results = [];
    const lines = getLines(file);

    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];
      const aws = line.match(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/);
      const privateKey = line.match(/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/);
      const bearer = line.match(/\bBearer\s+([A-Za-z0-9._~+/=-]{16,})/i);
      const providerToken = line.match(/\b((?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{12,}))\b/);
      const databaseUrl = line.match(/\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s/:"']+:([^\s/@"']+)@/i);
      const assignment = line.match(ASSIGNMENT_PATTERN);

      let value: string | undefined;
      let title = "Hardcoded credential";
      let severity: "critical" | "high" = "high";
      let confidence: "high" | "medium" = "high";

      if (privateKey) {
        value = privateKey[0];
        title = "Private key embedded in source";
        severity = "critical";
      } else if (aws) {
        value = aws[0];
        title = "AWS access key embedded in source";
        severity = "critical";
      } else if (bearer) {
        value = bearer[1];
        title = "Hardcoded bearer token";
      } else if (providerToken) {
        value = providerToken[1];
        title = "Hardcoded API token";
      } else if (databaseUrl) {
        value = databaseUrl[1];
        title = "Database credential embedded in URL";
      } else if (assignment && !GENERIC_PLACEHOLDER.test(assignment[1].trim())) {
        value = assignment[1];
        confidence = assignment[1].length >= 12 ? "high" : "medium";
      } else {
        continue;
      }

      results.push(
        finding(file, {
          ruleId: "secrets.hardcoded-credential",
          title,
          severity,
          category: "secrets",
          line: index + 1,
          snippet: redactLine(line, value),
          description: "A credential-like value appears to be stored directly in the repository.",
          impact: "Anyone who can read the source may be able to impersonate the application or access protected services.",
          remediation: "Revoke the exposed value, store its replacement in a secret manager or environment variable, and remove it from version history.",
          confidence,
          cwe: "CWE-798",
        }),
      );
    }

    return results;
  },
};

export const sensitiveFilesRule: ScannerRule = {
  id: "secrets.sensitive-file",
  scan(file) {
    const path = file.relativePath.toLowerCase();
    const name = path.split("/").at(-1) ?? path;
    const isExample = /\.env\.(?:example|sample|template)$|\.env\.example$/.test(name);
    const isEnvironment = /^\.env(?:\..+)?$/.test(name) && !isExample;
    const isCredentialJson = /(?:credentials?|service[-_]?account)[^/]*\.json$/.test(name);
    const isPrivateKeyFile = /\.(?:pem|key|p12|pfx)$/.test(name);
    const serviceAccount = /"type"\s*:\s*"service_account"/.test(file.content) && /"private_key"\s*:/.test(file.content);

    if (!isEnvironment && !isCredentialJson && !isPrivateKeyFile && !serviceAccount) return [];

    return [
      finding(file, {
        ruleId: "secrets.sensitive-file",
        title: serviceAccount ? "Service account credential file committed" : "Sensitive file committed",
        severity: serviceAccount || isPrivateKeyFile ? "critical" : "high",
        category: "secrets",
        description: "A file commonly used to hold credentials or production secrets is present in the repository.",
        impact: "Committed secrets can be recovered from repository history even after the file is deleted.",
        remediation: "Remove the file from version control and history, rotate all contained credentials, and commit only a redacted example file.",
        confidence: serviceAccount || isEnvironment ? "high" : "medium",
        cwe: "CWE-538",
      }),
    ];
  },
};
