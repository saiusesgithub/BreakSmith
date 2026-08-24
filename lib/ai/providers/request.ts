export async function fetchJson(
  url: string,
  init: Omit<RequestInit, "signal">,
  timeoutMs: number,
): Promise<unknown | null> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { ...init, signal: controller.signal });
    if (!response.ok) return null;
    return await response.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

export function aiTimeoutMs(value = process.env.BREAKSMITH_AI_TIMEOUT_MS): number {
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isFinite(parsed) ? Math.max(500, Math.min(parsed, 5_000)) : 3_000;
}
