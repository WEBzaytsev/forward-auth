import { readFileSync } from "node:fs";

const failures = [];

function fail(message) {
  failures.push(message);
}

function assertGithubActionsPinned() {
  const workflow = readFileSync(".github/workflows/docker.yml", "utf8");
  const usesRe = /^\s*uses:\s*([^\s#]+).*$/gm;
  for (const match of workflow.matchAll(usesRe)) {
    const spec = match[1];
    const ref = spec.includes("@") ? spec.split("@").pop() : "";
    if (!/^[0-9a-f]{40}$/i.test(ref)) {
      fail(`GitHub Action is not pinned to a commit SHA: ${spec}`);
    }
  }
}

function assertDockerfileImagesPinned() {
  const dockerfile = readFileSync("Dockerfile", "utf8");
  const stageAliases = new Set();

  for (const line of dockerfile.split("\n")) {
    const match = line.match(/^FROM\s+([^\s]+)(?:\s+AS\s+(\S+))?/i);
    if (!match) continue;

    const image = match[1];
    const alias = match[2];

    // Multi-stage references such as `FROM base AS builder` refer to a local
    // stage, not a registry image.
    if (stageAliases.has(image)) {
      if (alias) stageAliases.add(alias);
      continue;
    }

    if (!image.includes("@sha256:")) {
      fail(`Docker base image is not digest-pinned: ${image}`);
    }
    if (alias) stageAliases.add(alias);
  }
}

function assertRedirectAllowlistDocumented() {
  const envExample = readFileSync(".env.example", "utf8");
  const readme = readFileSync("README.md", "utf8");
  if (!/^ALLOWED_REDIRECT_HOSTS=/m.test(envExample)) {
    fail(".env.example must document ALLOWED_REDIRECT_HOSTS");
  }
  if (!readme.includes("ALLOWED_REDIRECT_HOSTS")) {
    fail("README.md must document ALLOWED_REDIRECT_HOSTS");
  }
}

assertGithubActionsPinned();
assertDockerfileImagesPinned();
assertRedirectAllowlistDocumented();

if (failures.length > 0) {
  console.error("Security checks failed:");
  for (const message of failures) console.error(`- ${message}`);
  process.exit(1);
}

console.log("Security checks passed");
