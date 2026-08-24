import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { scanRepository } from "../lib/scanner/scanner";
import { redactSecrets } from "../lib/scanner/rules/helpers";

const fixture = path.resolve("tests", "fixtures", "vulnerable-app");

test("scanner detects representative vulnerabilities and ignores vendor files", async () => {
  const result = await scanRepository(fixture);
  const ruleIds = new Set(result.findings.map((finding) => finding.ruleId));

  for (const expected of [
    "secrets.sensitive-file",
    "secrets.hardcoded-credential",
    "injection.sql-user-input",
    "injection.command-execution",
    "api-security.permissive-cors",
    "configuration.debug-enabled",
    "authentication.jwt-no-expiry",
    "cryptography.weak-hash",
    "configuration.insecure-http",
    "authorization.security-disabled",
    "dependencies.risky-package",
  ]) {
    assert.ok(ruleIds.has(expected), `expected ${expected}`);
  }

  assert.equal(result.scannedFiles, 4);
  assert.equal(result.findings.some((finding) => finding.file.includes("vendor")), false);
});

test("hardcoded secret snippets never contain the complete value", async () => {
  const result = await scanRepository(fixture);
  const secret = result.findings.find((finding) => finding.ruleId === "secrets.hardcoded-credential");
  assert.ok(secret?.snippet?.includes("***REDACTED***"));
  assert.equal(secret?.snippet?.includes("sk-hackathon-placeholder-not-valid"), false);
});

test("findings report source lines", async () => {
  const result = await scanRepository(fixture);
  const sql = result.findings.find((finding) => finding.ruleId === "injection.sql-user-input");
  assert.equal(sql?.file, "src/server.ts");
  assert.equal(sql?.line, 9);
});

test("central redaction removes common token formats from any rule snippet", () => {
  const raw = 'const token = "ghp_abcdefghijklmnopqrstuvwxyz"; fetch("https://admin:password@example.invalid")';
  const redacted = redactSecrets(raw);
  assert.equal(redacted.includes("ghp_abcdefghijklmnopqrstuvwxyz"), false);
  assert.equal(redacted.includes("admin:password"), false);
  assert.match(redacted, /REDACTED/);
});
