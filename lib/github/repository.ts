import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtemp, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const DEFAULT_CLONE_TIMEOUT_MS = 35_000;
const DEFAULT_MAX_REPOSITORY_BYTES = 100 * 1024 * 1024;

export class RepositoryUrlError extends Error {}
export class CloneTimeoutError extends Error {}
export class CloneError extends Error {}
export class RepositoryTooLargeError extends Error {}

export type GitHubRepository = {
  url: string;
  cloneUrl: string;
  owner: string;
  name: string;
};

export function parseGitHubRepositoryUrl(value: unknown): GitHubRepository {
  if (typeof value !== "string" || value.length > 500) {
    throw new RepositoryUrlError("repoUrl must be a GitHub repository URL.");
  }

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new RepositoryUrlError("repoUrl is not a valid URL.");
  }

  if (
    url.protocol !== "https:" ||
    url.hostname.toLowerCase() !== "github.com" ||
    url.port ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new RepositoryUrlError("Only public https://github.com/owner/repository URLs are supported.");
  }

  const segments = url.pathname.split("/").filter(Boolean);
  if (segments.length !== 2) {
    throw new RepositoryUrlError("GitHub URL must identify one repository, without a branch or file path.");
  }

  const owner = segments[0];
  const name = segments[1].replace(/\.git$/i, "");
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(owner) || !/^[A-Za-z0-9._-]{1,100}$/.test(name)) {
    throw new RepositoryUrlError("GitHub owner or repository name is malformed.");
  }

  const canonicalUrl = `https://github.com/${owner}/${name}`;
  return { url: canonicalUrl, cloneUrl: `${canonicalUrl}.git`, owner, name };
}

async function calculateCheckoutSize(root: string, maxBytes: number): Promise<number> {
  const pending = [root];
  let total = 0;
  while (pending.length) {
    const directory = pending.pop()!;
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name === ".git") continue;
      const entryPath = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) pending.push(entryPath);
      if (entry.isFile()) {
        total += (await stat(entryPath)).size;
        if (total > maxBytes) return total;
      }
    }
  }
  return total;
}

export async function withClonedRepository<T>(
  repository: GitHubRepository,
  operation: (checkoutPath: string) => Promise<T>,
  options: { timeoutMs?: number; maxRepositoryBytes?: number } = {},
): Promise<T> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_CLONE_TIMEOUT_MS;
  const maxRepositoryBytes = options.maxRepositoryBytes ?? DEFAULT_MAX_REPOSITORY_BYTES;
  const temporaryRoot = await mkdtemp(path.join(tmpdir(), "breaksmith-"));
  const checkoutPath = path.join(temporaryRoot, `repository-${randomBytes(6).toString("hex")}`);

  try {
    try {
      await execFileAsync(
        "git",
        ["clone", "--depth", "1", "--single-branch", "--no-tags", "--", repository.cloneUrl, checkoutPath],
        {
          timeout: timeoutMs,
          maxBuffer: 1024 * 1024,
          windowsHide: true,
          env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GCM_INTERACTIVE: "Never" },
        },
      );
    } catch (error) {
      const cloneFailure = error as NodeJS.ErrnoException & { killed?: boolean; signal?: string; stderr?: string };
      if (cloneFailure.killed || cloneFailure.signal === "SIGTERM") {
        throw new CloneTimeoutError(`Repository clone exceeded the ${timeoutMs}ms timeout.`);
      }
      const detail = cloneFailure.code === "ENOENT"
        ? "Git is not installed on the server."
        : "The repository may not exist, may be private, or could not be reached.";
      throw new CloneError(`Unable to clone repository. ${detail}`);
    }

    const repositoryBytes = await calculateCheckoutSize(checkoutPath, maxRepositoryBytes);
    if (repositoryBytes > maxRepositoryBytes) {
      throw new RepositoryTooLargeError(`Repository checkout exceeds the ${Math.floor(maxRepositoryBytes / 1024 / 1024)}MB limit.`);
    }
    return await operation(checkoutPath);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 }).catch(() => undefined);
  }
}
