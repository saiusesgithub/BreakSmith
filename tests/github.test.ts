import assert from "node:assert/strict";
import test from "node:test";
import { parseGitHubRepositoryUrl, RepositoryUrlError } from "../lib/github/repository";

test("parses and canonicalizes public GitHub repository URLs", () => {
  assert.deepEqual(parseGitHubRepositoryUrl("https://github.com/openai/openai-node.git"), {
    url: "https://github.com/openai/openai-node",
    cloneUrl: "https://github.com/openai/openai-node.git",
    owner: "openai",
    name: "openai-node",
  });
});

test("rejects non-GitHub, credentialed, and nested URLs", () => {
  for (const url of [
    "http://github.com/openai/openai-node",
    "https://gitlab.com/openai/openai-node",
    "https://token@github.com/openai/openai-node",
    "https://github.com/openai/openai-node/tree/main",
  ]) {
    assert.throws(() => parseGitHubRepositoryUrl(url), RepositoryUrlError);
  }
});
