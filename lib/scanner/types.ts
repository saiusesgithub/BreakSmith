export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingCategory =
  | "secrets"
  | "authentication"
  | "authorization"
  | "injection"
  | "api-security"
  | "configuration"
  | "dependencies"
  | "cryptography"
  | "other";

export type Confidence = "high" | "medium" | "low";

export type Finding = {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  category: FindingCategory;
  file: string;
  line?: number;
  snippet?: string;
  description: string;
  impact: string;
  remediation: string;
  confidence: Confidence;
  cwe?: string;
  metadata?: Record<string, unknown>;
};

export type SourceFile = {
  absolutePath: string;
  relativePath: string;
  size: number;
  content: string;
};

export type ScannerRule = {
  id: string;
  scan(file: SourceFile): Omit<Finding, "id">[];
};

export type ScanLimits = {
  maxFiles: number;
  maxFileBytes: number;
  maxTotalBytes: number;
};

export type ScanResult = {
  findings: Finding[];
  scannedFiles: number;
  scannedBytes: number;
  truncated: boolean;
};

export const FINDING_CATEGORIES: FindingCategory[] = [
  "secrets",
  "authentication",
  "authorization",
  "injection",
  "api-security",
  "configuration",
  "dependencies",
  "cryptography",
  "other",
];
