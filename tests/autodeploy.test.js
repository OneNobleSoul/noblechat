import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const script = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../deploy/autodeploy/noblechat-autodeploy.sh",
);

const git = (cwd, ...args) =>
  execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.com", ...args], { cwd, encoding: "utf8" }).trim();

// Sets up a bare "remote", a checkout, and a fake docker on PATH. The fake only
// fails `compose build` when the marker file exists.
function setup() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ncad-"));
  const remote = path.join(root, "remote.git");
  const work = path.join(root, "work");
  const repo = path.join(root, "repo");
  const bin = path.join(root, "bin");
  fs.mkdirSync(bin);
  git(root, "init", "-q", "--bare", "-b", "main", remote);
  git(root, "clone", "-q", remote, work);
  fs.writeFileSync(path.join(work, "a.txt"), "1");
  git(work, "add", ".");
  git(work, "commit", "-q", "-m", "one");
  git(work, "push", "-q", "origin", "HEAD:main");
  git(root, "clone", "-q", remote, repo);
  fs.writeFileSync(
    path.join(bin, "docker"),
    `#!/bin/sh
echo "docker $*" >> "${root}/docker.log"
case "$1 $2" in
  "compose build") [ -f "${root}/build-fails" ] && exit 1; exit 0 ;;
  "compose config") printf 'noblechat\\ndb\\n'; exit 0 ;;
  "inspect -f") echo true; exit 0 ;;
esac
exit 0
`,
    { mode: 0o755 },
  );
  const env = {
    ...process.env,
    PATH: `${bin}:${process.env.PATH}`,
    REPO_DIR: repo,
    REMOTE_URL: remote,
    LOG: path.join(root, "deploy.log"),
    LOCK: path.join(root, "lock"),
    STATE_FILE: path.join(root, "state"),
    FAIL_FILE: path.join(root, "failed"),
  };
  const run = (extra = {}) => spawnSync("bash", [script], { env: { ...env, ...extra }, encoding: "utf8" });
  const push = (name) => {
    fs.writeFileSync(path.join(work, "a.txt"), name);
    git(work, "commit", "-qam", name);
    git(work, "push", "-q", "origin", "HEAD:main");
    return git(work, "rev-parse", "HEAD");
  };
  const builds = () =>
    (fs.existsSync(path.join(root, "docker.log")) ? fs.readFileSync(path.join(root, "docker.log"), "utf8") : "")
      .split("\n")
      .filter((l) => l === "docker compose build").length;
  return { root, repo, env, run, push, builds, state: env.STATE_FILE };
}

test("autodeploy is a no-op when the deployed revision matches the remote", () => {
  const t = setup();
  const r = t.run();
  assert.equal(r.status, 0);
  assert.equal(t.builds(), 0);
});

test("autodeploy builds a new revision and records it as deployed", () => {
  const t = setup();
  const sha = t.push("two");
  const r = t.run();
  assert.equal(r.status, 0, r.stderr);
  assert.equal(t.builds(), 1);
  assert.equal(fs.readFileSync(t.state, "utf8").trim(), sha);
});

test("autodeploy retries a revision whose build failed instead of treating it as deployed", () => {
  const t = setup();
  const sha = t.push("two");
  fs.writeFileSync(path.join(t.root, "build-fails"), "");
  assert.equal(t.run().status, 1);
  // The checkout already sits on the new revision, but nothing was deployed.
  assert.equal(git(t.repo, "rev-parse", "HEAD"), sha);
  assert.ok(!fs.existsSync(t.state));
  // Inside the backoff window the poller stays quiet.
  assert.equal(t.run().status, 0);
  assert.equal(t.builds(), 1);
  // After the window, with the build fixed, it deploys the same revision.
  fs.rmSync(path.join(t.root, "build-fails"));
  const r = t.run({ RETRY_SECS: "0" });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(t.builds(), 2);
  assert.equal(fs.readFileSync(t.state, "utf8").trim(), sha);
  assert.ok(!fs.existsSync(path.join(t.root, "failed")));
});
