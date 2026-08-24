import path from "node:path";
import { scanRepository } from "../lib/scanner/scanner";
import { calculateScore } from "../lib/scoring/score";

async function main(): Promise<void> {
  const target = process.argv[2];
  if (!target) {
    console.error("Usage: npm run scan:local -- <repository-directory>");
    process.exitCode = 1;
    return;
  }

  const repositoryPath = path.resolve(target);
  const result = await scanRepository(repositoryPath);
  const score = calculateScore(result.findings);
  console.log(JSON.stringify({ ...score, scannedFiles: result.scannedFiles, truncated: result.truncated, findings: result.findings }, null, 2));
}

void main();
