import type { ScannerRule } from "../types";
import { finding, getLines, snippet } from "./helpers";

const WEAK_HASH = /(?:createHash\s*\(\s*["'](?:md5|sha-?1)["']|hashlib\.(?:md5|sha1)\s*\(|MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-?1)["']|Digest::(?:MD5|SHA1)|md5\s*\()/i;
const SECURITY_CONTEXT = /password|passwd|token|secret|signature|credential|auth|integrity/i;

export const weakCryptographyRule: ScannerRule = {
  id: "cryptography.weak-hash",
  scan(file) {
    const lines = getLines(file);
    const results = [];
    for (let index = 0; index < lines.length; index += 1) {
      if (!WEAK_HASH.test(lines[index])) continue;
      const context = lines.slice(Math.max(0, index - 2), index + 3).join(" ");
      const securitySensitive = SECURITY_CONTEXT.test(context);
      results.push(
        finding(file, {
          ruleId: "cryptography.weak-hash",
          title: "Weak cryptographic hash function",
          severity: securitySensitive ? "high" : "medium",
          category: "cryptography",
          line: index + 1,
          snippet: snippet(lines[index]),
          description: "MD5 or SHA-1 is used in code, and these algorithms are not collision resistant.",
          impact: securitySensitive
            ? "Using a broken hash for credentials, signatures, or integrity checks can permit forgery or credential compromise."
            : "Collision attacks can undermine integrity checks that rely on this digest.",
          remediation: "Use SHA-256 or SHA-3 for integrity; use Argon2id, scrypt, or bcrypt for password hashing.",
          confidence: securitySensitive ? "high" : "medium",
          cwe: "CWE-328",
        }),
      );
    }
    return results;
  },
};
