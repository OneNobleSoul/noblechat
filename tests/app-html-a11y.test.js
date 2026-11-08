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

// The ringing screen covers the whole page, so it needs to announce itself and
// hand keyboard focus to the accept button instead of leaving it behind the overlay.
test("incoming call overlay is an alertdialog and takes focus", () => {
  const src = readFileSync(new URL("../apps/web/src/main.js", import.meta.url), "utf8");
  const fn = src.slice(src.indexOf("function showIncoming"), src.indexOf("function hideIncoming"));
  assert.match(fn, /setAttribute\("role", "alertdialog"\)/);
  assert.match(fn, /setAttribute\("aria-modal", "true"\)/);
  assert.match(fn, /setAttribute\("aria-label"/);
  assert.match(fn, /\$\("#ci-accept"\)\.focus\(\)/);
});

// Message bubbles open a react/reply/delete menu on click. Keyboard users need
// to reach and open it too, and get back to the bubble when Escape closes it.
test("message bubbles are focusable and open their menu from the keyboard", () => {
  const src = readFileSync(new URL("../apps/web/src/main.js", import.meta.url), "utf8");
  const fn = src.slice(src.indexOf("function renderMessages"), src.indexOf("const QUICK_REACTS"));
  assert.match(fn, /n\.tabIndex = 0/);
  assert.match(fn, /e\.key === "Enter"/);
  assert.match(fn, /openMessageMenu\(state\.active, msgs\[Number\(n\.dataset\.mi\)\], n, true\)/);
  assert.match(src, /if \(viaKeyboard\) pop\.querySelector\("button"\)\?\.focus\(\)/);
  assert.match(src, /msg-menu-pop"\);\s*\n\s*if \(mm && !mm\.hidden\)/);
});

// The sign in / create account switch and the sound button are toggles. Without
// aria-pressed a screen reader cannot tell which side is currently selected.
test("auth tabs and sound toggle expose their state", () => {
  const src = readFileSync(new URL("../apps/web/src/main.js", import.meta.url), "utf8");
  const auth = src.slice(src.indexOf("function showAuth"), src.indexOf("setMode(\"login\");"));
  assert.match(auth, /#tab-login\"\)\.setAttribute\(\"aria-pressed\"/);
  assert.match(auth, /#tab-register\"\)\.setAttribute\(\"aria-pressed\"/);
  const snd = src.slice(src.indexOf("function renderSoundToggle"), src.indexOf("function renderSoundToggle") + 400);
  assert.match(snd, /setAttribute\(\"aria-pressed\", String\(state\.soundOn\)\)/);
});

// The admin page strips the default input outline, so keyboard users need an
// explicit ring on inputs, buttons and links or they lose track of the focus.
test("admin page keeps a visible keyboard focus ring", () => {
  const css = readFileSync(new URL("../apps/web/public/admin.css", import.meta.url), "utf8");
  const rule = css.match(/([^{}]*:focus-visible[^{}]*)\{([^}]*)\}/);
  assert.ok(rule, "admin.css needs a :focus-visible rule");
  for (const sel of ["input", "textarea", ".btn", "a"]) {
    assert.ok(rule[1].includes(`${sel}:focus-visible`), `${sel} needs a focus ring`);
  }
  assert.match(rule[2], /outline:\s*2px solid/);
});
