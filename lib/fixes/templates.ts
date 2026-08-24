import { redactSecrets } from "../scanner/rules/helpers";
import type { Confidence, Finding } from "../scanner/types";
import type { FixContent } from "./types";

type TemplateContext = { finding: Finding; language?: string };

function content(
  summary: string,
  steps: string[],
  after: string,
  notes: string[],
  confidence: Confidence = "medium",
): FixContent {
  return { summary, steps, after, notes, confidence };
}

function secretVariableName(finding: Finding): string {
  const snippet = redactSecrets(finding.snippet ?? "");
  const match = snippet.match(/\b([A-Z][A-Z0-9_]{2,})\b\s*(?:=|:)/);
  return match?.[1] ?? "SECRET_VALUE";
}

function hardcodedSecret({ finding }: TemplateContext): FixContent {
  const variable = secretVariableName(finding);
  return content(
    `Move ${variable} out of source code and load it from the deployment environment.`,
    [
      `Create a protected environment variable named ${variable}.`,
      "Read it during application startup and fail closed when it is absent.",
      "Remove the committed value from source and repository history where practical.",
      "Rotate the exposed credential before deploying the change.",
    ],
    `const ${variable} = process.env.${variable};\nif (!${variable}) {\n  throw new Error("${variable} is required");\n}`,
    ["Never place the replacement credential in source control.", "Rotate any credential that may already be exposed."],
    "high",
  );
}

const TEMPLATES: Record<string, (context: TemplateContext) => FixContent> = {
  "secrets.hardcoded-credential": hardcodedSecret,
  "secrets.sensitive-file": ({ finding }) => content(
    `Remove ${finding.file} from version control and provide its sensitive values through the deployment secret store.`,
    [
      "Remove the sensitive file from the tracked repository.",
      `Add ${finding.file} to .gitignore when the application does not require it as a tracked template.`,
      "Provide a sanitized example file containing placeholders only.",
      "Rotate every credential that may have been committed.",
    ],
    `# ${finding.file} must not contain deployable credentials in source control.\n# Load secrets from the deployment environment or secret manager instead.`,
    ["Removing the current file does not erase it from Git history; rotate exposed values."],
    "high",
  ),
  "injection.sql-user-input": () => content(
    "Replace SQL string construction with a parameterized query so user input is handled as data.",
    [
      "Keep the SQL statement static.",
      "Pass the user-controlled value through the database driver's parameter API.",
      "Validate the value's expected type before querying.",
      "Confirm the placeholder syntax for the database library in use.",
    ],
    `const userId = String(req.query.id);\ndb.query("SELECT * FROM users WHERE id = ?", [userId]);`,
    ["The `?` placeholder is illustrative; use the parameter syntax documented by the actual database driver."],
  ),
  "injection.command-execution": () => content(
    "Avoid a shell command string and invoke an allowlisted executable with separated arguments.",
    [
      "Reject values outside a strict allowlist or expected format.",
      "Use an argument-array process API instead of a shell command string.",
      "Disable shell interpretation explicitly.",
      "Run the child process with the minimum required permissions.",
    ],
    `const allowedValue = validateAllowedValue(req.query.value);\nexecFile("approved-command", [allowedValue], { shell: false });`,
    ["Replace the illustrative validator and executable with application-specific allowlisted values."],
  ),
  "api-security.permissive-cors": () => content(
    "Restrict cross-origin access to explicitly trusted deployment origins.",
    [
      "List the frontend origins that require API access.",
      "Load the allowlist from deployment configuration.",
      "Reject origins that are absent from the allowlist.",
      "Test credentialed and preflight requests from allowed and denied origins.",
    ],
    `const trustedOrigins = ["https://trusted.example.com"];\napp.use(cors({ origin: trustedOrigins }));`,
    ["Replace the example domain with the real trusted production origins."],
    "high",
  ),
  "configuration.debug-enabled": () => content(
    "Disable debug mode in production and enable it only through an explicit development configuration.",
    [
      "Set the production default to false.",
      "Allow debug mode only in a local development environment.",
      "Verify production error responses do not expose stack traces or configuration details.",
    ],
    `const debugEnabled = process.env.NODE_ENV === "development";\nstartApplication({ debug: debugEnabled });`,
    ["Adapt the startup call to the framework used by the application."],
  ),
  "authentication.jwt-no-expiry": () => content(
    "Issue JWTs with a short, explicit expiration and validate expiry during verification.",
    [
      "Choose an expiration appropriate for the token type.",
      "Set the signing library's expiration option explicitly.",
      "Ensure verification rejects expired tokens.",
      "Use refresh-token rotation when longer sessions are required.",
    ],
    `const token = jwt.sign(claims, JWT_SECRET, { expiresIn: "15m" });`,
    ["Choose the lifetime using the application's threat model and session requirements."],
    "high",
  ),
  "authentication.plaintext-password": () => content(
    "Verify passwords with a password-hashing library instead of comparing plaintext values.",
    [
      "Store only password hashes created with Argon2id, scrypt, or bcrypt.",
      "Use the library's constant-time verification function.",
      "Migrate existing plaintext records safely and invalidate exposed credentials.",
    ],
    `const passwordMatches = await argon2.verify(user.passwordHash, submittedPassword);\nif (!passwordMatches) throw new AuthenticationError();`,
    ["Never log the submitted password or retain plaintext password values."],
    "high",
  ),
  "cryptography.weak-hash": () => content(
    "Replace weak password hashing with a dedicated, salted password-hashing algorithm.",
    [
      "Use Argon2id where available, or scrypt/bcrypt with reviewed parameters.",
      "Let the library generate and encode a unique salt.",
      "Rehash credentials after successful login when stored parameters are outdated.",
    ],
    `const passwordHash = await argon2.hash(password, { type: argon2.argon2id });`,
    ["Do not replace MD5 or SHA-1 with plain SHA-256 for password storage."],
    "high",
  ),
  "configuration.insecure-http": () => content(
    "Use an HTTPS endpoint and reject insecure transport in production configuration.",
    [
      "Change the service URL to its HTTPS endpoint.",
      "Store environment-specific endpoints in deployment configuration.",
      "Verify certificate validation remains enabled.",
    ],
    `const API_BASE_URL = process.env.API_BASE_URL;\nif (!API_BASE_URL?.startsWith("https://")) {\n  throw new Error("A secure API_BASE_URL is required");\n}`,
    ["Confirm the upstream service supports TLS before deployment."],
  ),
  "authorization.security-disabled": () => content(
    "Enable the security check and fail closed when authorization configuration is missing.",
    [
      "Remove the flag that disables authentication or authorization.",
      "Require an authenticated identity before protected handlers run.",
      "Enforce the least-privilege permission needed by each endpoint.",
      "Add a denied-access regression test.",
    ],
    `if (!request.user) throw new AuthenticationError();\nrequirePermission(request.user, "required:permission");`,
    ["Replace the illustrative permission with the endpoint's actual least-privilege policy."],
  ),
  "dependencies.risky-package": () => content(
    "Replace the risky dependency with a maintained alternative and verify the affected behavior.",
    [
      "Identify a maintained package that provides only the required capability.",
      "Pin a reviewed version using the project's lockfile.",
      "Remove the risky package and its unused transitive dependencies.",
      "Run security and application regression tests.",
    ],
    `// package.json (illustrative)\n// Remove the risky package and add a reviewed, maintained replacement at a pinned version.`,
    ["Select the replacement only after checking compatibility and current maintenance status."],
    "low",
  ),
  "dependencies.unpinned-source": () => content(
    "Pin the dependency to an immutable reviewed release or commit and preserve it in the lockfile.",
    [
      "Resolve the source dependency to a reviewed release or full commit hash.",
      "Update and commit the package lockfile.",
      "Verify package integrity and provenance.",
      "Run the application's regression tests.",
    ],
    `// package.json (illustrative)\n// "dependency-name": "git+https://host/repository.git#FULL_REVIEWED_COMMIT_HASH"`,
    ["Do not pin to a mutable branch or tag."],
    "medium",
  ),
};

export function deterministicFix(finding: Finding, language?: string): FixContent {
  const template = TEMPLATES[finding.ruleId];
  if (template) return template({ finding, language });
  return content(
    "Apply the scanner's recommended remediation and review the change in the application's real framework context.",
    [finding.remediation, "Add a regression test for the vulnerable behavior.", "Review and test the suggestion before deployment."],
    `// Suggested remediation\n// ${finding.remediation.replace(/\r?\n/g, "\n// ")}`,
    ["This generic suggestion requires application-specific review before use."],
    "low",
  );
}
