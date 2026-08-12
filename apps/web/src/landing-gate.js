// Coming-soon curtain in front of the landing page.
//
// The markup ships visible and <html> carries the "locked" class, so a visitor
// without JavaScript sees the teaser and nothing else. This bundle is loaded
// from the <head> without defer: it strips that class before the first paint
// when the tab already unlocked the gate, so the real page never flashes. That
// also means the DOM is not ready yet when it runs, hence the readyState dance
// at the bottom.

import { unlocks, isUnlocked, markUnlocked } from "./gate.js";

const $ = (s) => document.querySelector(s);

function open() {
  document.documentElement.classList.remove("locked");
  const soon = $("#soon");
  if (!soon) return;
  soon.classList.add("gone");
  setTimeout(() => soon.remove(), 420);
}

function reject(soon, input, err) {
  err.hidden = false;
  input.value = "";
  input.focus();
  soon.classList.remove("shake");
  void soon.offsetWidth; // restart the animation
  soon.classList.add("shake");
}

function start() {
  const soon = $("#soon");
  if (!soon) return;

  const reveal = $("#soon-reveal");
  const form = $("#soon-form");
  const input = $("#soon-input");
  const go = $("#soon-go");
  const err = $("#soon-err");

  reveal.addEventListener("click", () => {
    reveal.hidden = true;
    form.hidden = false;
    input.focus();
  });

  async function tryUnlock() {
    const value = input.value;
    if (!value) return;
    go.disabled = true;
    const ok = await unlocks(value);
    go.disabled = false;
    if (!ok) { reject(soon, input, err); return; }
    markUnlocked();
    open();
  }

  go.addEventListener("click", tryUnlock);
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") tryUnlock(); });
}

// Unlock first (before paint), wire up the form once the markup exists.
if (isUnlocked()) {
  document.documentElement.classList.remove("locked");
} else if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", start, { once: true });
} else {
  start();
}
