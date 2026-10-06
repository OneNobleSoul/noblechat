import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const html = readFileSync(new URL("../apps/web/public/app.html", import.meta.url), "utf8");

// Every modal card has to announce itself as a dialog and point at an element
// that actually exists, otherwise screen readers just read it as loose text.
test("each modal card is a labelled aria-modal dialog", () => {
  const modals = [...html.matchAll(/<div id="([\w-]+-modal)" class="modal"[^>]*>\s*<div class="modal-card[^"]*"([^>]*)>/g)];
  assert.equal(modals.length, 4);
  for (const [, id, attrs] of modals) {
    assert.match(attrs, /role="dialog"/, `${id} needs role=dialog`);
    assert.match(attrs, /aria-modal="true"/, `${id} needs aria-modal`);
    const ref = attrs.match(/aria-labelledby="([\w-]+)"/);
    assert.ok(ref, `${id} needs aria-labelledby`);
    assert.ok(html.includes(`id="${ref[1]}"`), `${id} points at missing #${ref[1]}`);
  }
});
