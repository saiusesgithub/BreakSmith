import { randomUUID } from "node:crypto";
import { enrichFindings } from "../../../lib/ai/analyst";
import {
  CloneError,
  CloneTimeoutError,
  parseGitHubRepositoryUrl,
  RepositoryTooLargeError,
  RepositoryUrlError,
  withClonedRepository,
} from "../../../lib/github/repository";
import { scanRepository } from "../../../lib/scanner/scanner";
import { calculateScore } from "../../../lib/scoring/score";

export const runtime = "nodejs";
export const maxDuration = 60;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

export async function handleScanRequest(
  request: Request,
  cloneRepository: typeof withClonedRepository = withClonedRepository,
): Promise<Response> {
  const startedAt = Date.now();
  try {
    const contentLength = Number(request.headers.get("content-length") ?? 0);
    if (contentLength > 10_000) return json({ error: "Request body is too large." }, 413);

    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return json({ error: "Request body must be valid JSON." }, 400);
    }
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return json({ error: "Request body must be a JSON object." }, 400);
    }

    const repository = parseGitHubRepositoryUrl((body as { repoUrl?: unknown }).repoUrl);
    const result = await cloneRepository(repository, async (checkoutPath) => {
      const scan = await scanRepository(checkoutPath);
      const findings = await enrichFindings(scan.findings);
      return { scan, findings, score: calculateScore(findings) };
    });

    return json({
      scanId: randomUUID(),
      repo: { url: repository.url, name: repository.name, owner: repository.owner },
      score: result.score.score,
      riskLevel: result.score.riskLevel,
      summary: result.score.summary,
      categories: result.score.categories,
      scannedFiles: result.scan.scannedFiles,
      durationMs: Date.now() - startedAt,
      findings: result.findings,
    });
  } catch (error) {
    if (error instanceof RepositoryUrlError) return json({ error: error.message }, 400);
    if (error instanceof CloneTimeoutError) return json({ error: error.message }, 504);
    if (error instanceof RepositoryTooLargeError) return json({ error: error.message }, 413);
    if (error instanceof CloneError) return json({ error: error.message }, 422);
    console.error("BreakSmith scan failed", error);
    return json({ error: "The repository scan failed unexpectedly." }, 500);
  }
}

export async function POST(request: Request): Promise<Response> {
  return handleScanRequest(request);
}
