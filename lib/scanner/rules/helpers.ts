import type { Finding, SourceFile } from "../types";

export type FindingInput = Omit<Finding, "id" | "file">;

export function finding(file: SourceFile, input: FindingInput): Omit<Finding, "id"> {
  return { ...input, file: file.relativePath };
}

export function getLines(file: SourceFile): string[] {
  return file.content.split(/\r?\n/);
}

export function snippet(line: string, maxLength = 240): string {
  const normalized = line.trim().replace(/\s+/g, " ");
  return normalized.length <= maxLength
    ? normalized
    : `${normalized.slice(0, maxLength - 1)}…`;
}

export function redactValue(value: string): string {
  if (!value) return "***REDACTED***";
  const prefix = value.length >= 8 ? value.slice(0, Math.min(4, value.length - 4)) : "";
  return `${prefix}***REDACTED***`;
}

export function redactSecrets(text: string, secret?: string): string {
  let redacted = text;
  if (secret) {
    redacted = redacted.split(secret).join(redactValue(secret));
  }

  return redacted
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----/g, "-----BEGIN ***REDACTED PRIVATE KEY***-----")
    .replace(/\b(AKIA|ASIA)[A-Z0-9]{16}\b/g, "$1***REDACTED***")
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi, "$1***REDACTED***")
    .replace(/\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{12,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g, "***REDACTED***")
    .replace(/(https?:\/\/)[^\s/:"']+:[^\s/@"']+@/gi, "$1***REDACTED***@")
    .replace(
      /((?:password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret)\s*[=:]\s*["'])[^"']+(["'])/gi,
      "$1***REDACTED***$2",
    );
}

export function redactLine(line: string, secret?: string): string {
  return snippet(redactSecrets(line, secret));
}

export function isLikelyExamplePath(relativePath: string): boolean {
  return /(^|\/)(?:examples?|samples?|fixtures?|testdata)(\/|$)/i.test(relativePath);
}
