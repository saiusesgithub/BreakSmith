import type { ScannerRule } from "../types";
import { finding } from "./helpers";

const RISKY_PACKAGES: Record<string, { severity: "high" | "low"; reason: string }> = {
  "node-serialize": { severity: "high", reason: "This package is associated with unsafe deserialization patterns and is unmaintained." },
  request: { severity: "low", reason: "This HTTP client has been deprecated and is no longer maintained." },
  "node-uuid": { severity: "low", reason: "This package is deprecated in favor of uuid." },
};

export const dependencyConfigurationRule: ScannerRule = {
  id: "dependencies.risky-package",
  scan(file) {
    if (!/(^|\/)package\.json$/i.test(file.relativePath)) return [];

    let manifest: Record<string, unknown>;
    try {
      manifest = JSON.parse(file.content) as Record<string, unknown>;
    } catch {
      return [];
    }

    const sections = ["dependencies", "devDependencies", "optionalDependencies"];
    const results = [];
    for (const section of sections) {
      const dependencies = manifest[section];
      if (!dependencies || typeof dependencies !== "object" || Array.isArray(dependencies)) continue;
      for (const [name, rawVersion] of Object.entries(dependencies as Record<string, unknown>)) {
        const version = String(rawVersion);
        const risky = RISKY_PACKAGES[name];
        if (risky) {
          results.push(
            finding(file, {
              ruleId: "dependencies.risky-package",
              title: `Risky or deprecated dependency: ${name}`,
              severity: risky.severity,
              category: "dependencies",
              description: risky.reason,
              impact: "Unmaintained or security-sensitive packages may contain vulnerabilities that will not receive fixes.",
              remediation: `Remove or replace ${name} with a maintained alternative, then run the ecosystem's dependency audit tooling.`,
              confidence: "high",
              cwe: "CWE-1104",
              metadata: { package: name, declaredVersion: version, section },
            }),
          );
        }

        if (/^(?:\*|latest|https?:|git\+|github:)/i.test(version)) {
          results.push(
            finding(file, {
              ruleId: "dependencies.unpinned-source",
              title: `Unpinned dependency source: ${name}`,
              severity: "low",
              category: "dependencies",
              description: "A dependency uses a wildcard, moving tag, URL, or Git source instead of a constrained registry version.",
              impact: "Future installs may resolve to unexpected or compromised code, reducing build reproducibility.",
              remediation: "Pin the dependency to a reviewed release and commit the package manager lockfile.",
              confidence: "high",
              cwe: "CWE-829",
              metadata: { package: name, declaredVersion: version, section },
            }),
          );
        }
      }
    }
    return results;
  },
};
