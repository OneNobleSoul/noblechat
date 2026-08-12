import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// server.js is never imported by the test suite: it connects to Postgres and
// starts listening the moment it loads. That left a gap the size of a bus.
// Removing an export from util.js while server.js still imported it produced a
// module that could not load at all - the container crash-looped on boot -
// and every unit test stayed green, because none of them touch server.js.
//
// These checks read the source instead of executing it, so they need no
// database, and they catch exactly that class of mistake.
const dir = path.dirname(fileURLToPath(import.meta.url));
const read = (p) => fs.readFileSync(path.join(dir, "..", p), "utf8");

// Pull the named bindings out of `import { a, b } from "./x.js"`.
function importedNames(source, fromPath) {
  const re = new RegExp(String.raw`import\s*\{([^}]*)\}\s*from\s*["']${fromPath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}["']`, "g");
  const names = [];
  for (const m of source.matchAll(re)) {
    for (const part of m[1].split(",")) {
      const name = part.trim().split(/\s+as\s+/)[0].trim();
      if (name) names.push(name);
    }
  }
  return names;
}

// Every `export const NAME` / `export function NAME` in a module.
function exportedNames(source) {
  const names = [];
  for (const m of source.matchAll(/export\s+(?:async\s+)?(?:const|let|function|class)\s+([A-Za-z0-9_$]+)/g)) names.push(m[1]);
  return new Set(names);
}

test("every binding server.js imports from util.js actually exists", () => {
  const server = read("apps/server/server.js");
  const exported = exportedNames(read("apps/server/util.js"));
  const imported = importedNames(server, "./util.js");
  assert.ok(imported.length > 5, "expected to find the util.js import list");
  const missing = imported.filter((n) => !exported.has(n));
  assert.deepEqual(missing, [], `server.js imports these from util.js, but util.js does not export them: ${missing.join(", ")}`);
});

test("util.js exports nothing that nobody uses", () => {
  // Not a correctness problem, but dead exports are how a removed function
  // quietly stays around with an old, wrong implementation.
  const exported = [...exportedNames(read("apps/server/util.js"))];
  const users = ["apps/server/server.js", "apps/server/store.js", "tests/server-util.test.js", "tests/authsecret.test.js"]
    .map(read).join("\n");
  const unused = exported.filter((n) => !new RegExp(`\\b${n}\\b`).test(users));
  assert.deepEqual(unused, [], `unused exports in util.js: ${unused.join(", ")}`);
});

test("the store's imports resolve too", () => {
  const store = read("apps/server/store.js");
  for (const m of store.matchAll(/from\s+["'](\.[^"']+)["']/g)) {
    const target = path.join(dir, "..", "apps/server", m[1]);
    assert.ok(fs.existsSync(target), `store.js imports ${m[1]}, which does not exist`);
  }
});
