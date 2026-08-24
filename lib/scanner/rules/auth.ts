import type { ScannerRule } from "../types";
import { finding, getLines, snippet } from "./helpers";

const JWT_SIGN = /\b(?:jwt\.)?sign\s*\(/i;
const EXPIRY = /\b(?:expiresIn|exp)\b/;
const PLAINTEXT_PASSWORD_COMPARE = /\bpassword\b[^\r\n]{0,50}(?:===?|==|\.equals\s*\()[^\r\n]{0,60}\b(?:password|passwd|req(?:uest)?\.(?:body|form)|input)\b/i;

export const jwtConfigurationRule: ScannerRule = {
  id: "authentication.jwt-no-expiry",
  scan(file) {
    const lines = getLines(file);
    const results = [];
    for (let index = 0; index < lines.length; index += 1) {
      if (!JWT_SIGN.test(lines[index])) continue;
      const window = lines.slice(index, index + 5).join(" ");
      if (EXPIRY.test(window)) continue;
      results.push(
        finding(file, {
          ruleId: "authentication.jwt-no-expiry",
          title: "JWT may be issued without expiration",
          severity: "medium",
          category: "authentication",
          line: index + 1,
          snippet: snippet(window),
          description: "A JWT signing call was found without a nearby expiration claim or expiresIn option.",
          impact: "A stolen token may remain usable indefinitely if expiration is not applied elsewhere.",
          remediation: "Set a short, explicit token lifetime and implement refresh-token rotation or reauthentication as appropriate.",
          confidence: "medium",
          cwe: "CWE-613",
        }),
      );
      index += 4;
    }
    return results;
  },
};

export const plaintextPasswordRule: ScannerRule = {
  id: "authentication.plaintext-password",
  scan(file) {
    const results = [];
    for (const [index, line] of getLines(file).entries()) {
      if (!PLAINTEXT_PASSWORD_COMPARE.test(line) || /(?:bcrypt|argon2|scrypt|pbkdf2|verify|compareHash)/i.test(line)) continue;
      results.push(
        finding(file, {
          ruleId: "authentication.plaintext-password",
          title: "Potential plaintext password comparison",
          severity: "high",
          category: "authentication",
          line: index + 1,
          snippet: snippet(line),
          description: "Password-like values appear to be compared directly rather than verified with a password-hashing function.",
          impact: "This can indicate plaintext password storage or an authentication flow that does not use a slow password hash.",
          remediation: "Store passwords with Argon2id, scrypt, or bcrypt and use the library's constant-time verification function.",
          confidence: "low",
          cwe: "CWE-256",
        }),
      );
    }
    return results;
  },
};
