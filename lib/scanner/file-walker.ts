import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import type { ScanLimits, SourceFile } from "./types";

export const DEFAULT_SCAN_LIMITS: ScanLimits = {
  maxFiles: 5_000,
  maxFileBytes: 512 * 1024,
  maxTotalBytes: 25 * 1024 * 1024,
};

const IGNORED_DIRECTORIES = new Set([
  ".git",
  "node_modules",
  ".next",
  "dist",
  "build",
  "coverage",
  "vendor",
  "target",
  "out",
  ".cache",
  "venv",
  ".venv",
]);

const SOURCE_EXTENSIONS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".java", ".kt",
  ".go", ".rb", ".php", ".properties", ".yml", ".yaml", ".json", ".toml", ".xml",
  ".pem", ".key", ".p12", ".pfx",
]);

function isRelevantFile(fileName: string): boolean {
  const lower = fileName.toLowerCase();
  if (lower === "dockerfile" || lower.startsWith("dockerfile.")) return true;
  if (/^docker-compose(?:\.[^.]+)?\.ya?ml$/.test(lower) || /^compose\.ya?ml$/.test(lower)) return true;
  if (/^\.env(?:\..+)?$/.test(lower)) return true;
  return SOURCE_EXTENSIONS.has(path.extname(lower));
}

function toPortablePath(root: string, absolutePath: string): string {
  return path.relative(root, absolutePath).split(path.sep).join("/");
}

export async function walkSourceFiles(
  root: string,
  limits: ScanLimits = DEFAULT_SCAN_LIMITS,
): Promise<{ files: SourceFile[]; scannedBytes: number; truncated: boolean }> {
  const files: SourceFile[] = [];
  const pending = [root];
  let scannedBytes = 0;
  let truncated = false;

  while (pending.length > 0) {
    const directory = pending.pop()!;
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      continue;
    }

    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const absolutePath = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (!IGNORED_DIRECTORIES.has(entry.name.toLowerCase())) pending.push(absolutePath);
        continue;
      }
      if (!entry.isFile() || !isRelevantFile(entry.name)) continue;
      if (files.length >= limits.maxFiles) {
        truncated = true;
        break;
      }

      let fileStats;
      try {
        fileStats = await stat(absolutePath);
      } catch {
        continue;
      }
      if (fileStats.size > limits.maxFileBytes) {
        truncated = true;
        continue;
      }
      if (scannedBytes + fileStats.size > limits.maxTotalBytes) {
        truncated = true;
        continue;
      }

      let buffer;
      try {
        buffer = await readFile(absolutePath);
      } catch {
        continue;
      }
      const sensitiveBinary = /\.(?:p12|pfx)$/i.test(entry.name);
      if (buffer.includes(0) && !sensitiveBinary) continue;

      files.push({
        absolutePath,
        relativePath: toPortablePath(root, absolutePath),
        size: fileStats.size,
        content: sensitiveBinary ? "" : buffer.toString("utf8"),
      });
      scannedBytes += fileStats.size;
    }
    if (files.length >= limits.maxFiles) break;
  }

  files.sort((a, b) => a.relativePath.localeCompare(b.relativePath));
  return { files, scannedBytes, truncated };
}
