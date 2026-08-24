import type { ScannerRule } from "../types";
import { finding, getLines, snippet } from "./helpers";

const DEBUG_ENABLED = /(?:\bDEBUG\s*=\s*(?:true|1)\b|\bdebug\s*[:=]\s*(?:true|True)\b|app\.run\s*\([^)]*debug\s*=\s*True)/;
const DISABLED_SECURITY = /\b(?:auth(?:entication)?_?enabled\s*[:=]\s*false|disable_?(?:auth|authentication|security|csrf)\s*[:=]\s*true|security_?checks?\s*[:=]\s*false|permitAll\s*\(\s*\))/i;
const INSECURE_HTTP = /["'](http:\/\/([^/"']+)[^"']*)["']/gi;
const SECURITY_URL_CONTEXT = /\b(?:api|backend|base[_-]?url|endpoint|webhook|auth|oauth|server|service)\b/i;

export const debugConfigurationRule: ScannerRule = {
  id: "configuration.debug-enabled",
  scan(file) {
    if (/(?:^|\/)(?:test|tests|spec|examples?|samples?)(?:\/|$)/i.test(file.relativePath)) return [];
    const results = [];
    for (const [index, line] of getLines(file).entries()) {
      if (!DEBUG_ENABLED.test(line)) continue;
      results.push(
        finding(file, {
          ruleId: "configuration.debug-enabled",
          title: "Debug mode enabled",
          severity: "medium",
          category: "configuration",
          line: index + 1,
          snippet: snippet(line),
          description: "A development or debug setting appears to be enabled in committed configuration or application startup code.",
          impact: "Debug modes can disclose stack traces, configuration, source details, or interactive debugging capabilities.",
          remediation: "Disable debug mode by default and enable it only through an explicit local-development configuration.",
          confidence: "medium",
          cwe: "CWE-489",
        }),
      );
    }
    return results;
  },
};

export const insecureHttpRule: ScannerRule = {
  id: "configuration.insecure-http",
  scan(file) {
    const results = [];
    for (const [index, line] of getLines(file).entries()) {
      if (!SECURITY_URL_CONTEXT.test(line)) continue;
      INSECURE_HTTP.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = INSECURE_HTTP.exec(line))) {
        const host = match[2].split(":")[0].toLowerCase();
        if (["localhost", "127.0.0.1", "0.0.0.0", "::1"].includes(host) || host.endsWith(".local")) continue;
        results.push(
          finding(file, {
            ruleId: "configuration.insecure-http",
            title: "Security-sensitive endpoint uses HTTP",
            severity: "medium",
            category: "configuration",
            line: index + 1,
            snippet: snippet(line),
            description: "A service or API endpoint is configured with unencrypted HTTP.",
            impact: "Network attackers may be able to observe or modify credentials and application data in transit.",
            remediation: "Use HTTPS with certificate validation for all non-local service endpoints.",
            confidence: "medium",
            cwe: "CWE-319",
          }),
        );
      }
    }
    return results;
  },
};

export const disabledSecurityRule: ScannerRule = {
  id: "authorization.security-disabled",
  scan(file) {
    const results = [];
    for (const [index, line] of getLines(file).entries()) {
      if (!DISABLED_SECURITY.test(line)) continue;
      results.push(
        finding(file, {
          ruleId: "authorization.security-disabled",
          title: "Security control explicitly disabled",
          severity: "high",
          category: "authorization",
          line: index + 1,
          snippet: snippet(line),
          description: "Configuration or code appears to disable an authentication, authorization, CSRF, or general security check.",
          impact: "Protected functionality may become reachable without the expected security enforcement.",
          remediation: "Enable the control in production and scope any development bypass to isolated local environments.",
          confidence: "medium",
          cwe: "CWE-306",
        }),
      );
    }
    return results;
  },
};
