import { generateFixSuggestion } from "../../../lib/fixes/generator";
import { validateFixRequest } from "../../../lib/fixes/validation";

export const runtime = "nodejs";
export const maxDuration = 15;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

export async function handleFixRequest(request: Request): Promise<Response> {
  try {
    const contentLength = Number(request.headers.get("content-length") ?? 0);
    if (contentLength > 25_000) return json({ error: "Request body is too large." }, 413);

    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return json({ error: "Request body must be valid JSON." }, 400);
    }

    const validation = validateFixRequest(body);
    if ("error" in validation) return json({ error: validation.error }, 400);
    const suggestion = await generateFixSuggestion(validation.value.finding, validation.value.language);
    return json(suggestion);
  } catch {
    return json({ error: "The fix suggestion could not be generated." }, 500);
  }
}

export async function POST(request: Request): Promise<Response> {
  return handleFixRequest(request);
}
