import { generateRepositoryInsights } from "../../../lib/analytics/repository-insights";
import { validateInsightsRequest } from "../../../lib/analytics/validation";

export const runtime = "nodejs";
export const maxDuration = 10;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

export async function handleInsightsRequest(request: Request): Promise<Response> {
  try {
    const contentLength = Number(request.headers.get("content-length") ?? 0);
    if (contentLength > 2_000_000) return json({ error: "Request body is too large." }, 413);

    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return json({ error: "Request body must be valid JSON." }, 400);
    }

    const validation = validateInsightsRequest(body);
    if ("error" in validation) return json({ error: validation.error }, 400);
    return json(generateRepositoryInsights(validation.value));
  } catch {
    return json({ error: "Repository insights could not be generated." }, 500);
  }
}

export async function POST(request: Request): Promise<Response> {
  return handleInsightsRequest(request);
}
