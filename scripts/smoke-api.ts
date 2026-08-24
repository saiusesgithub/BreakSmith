import { POST } from "../app/api/scan/route";

async function main(): Promise<void> {
  const repoUrl = process.argv[2];
  if (!repoUrl) {
    console.error("Usage: npx tsx scripts/smoke-api.ts <public-github-url>");
    process.exitCode = 1;
    return;
  }

  const response = await POST(new Request("http://localhost/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repoUrl }),
  }));
  console.log(JSON.stringify({ status: response.status, body: await response.json() }, null, 2));
  if (!response.ok) process.exitCode = 1;
}

void main();
