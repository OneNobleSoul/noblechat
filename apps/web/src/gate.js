// Shared access gate for the landing page and the chat client.
//
// This is a curtain, not a lock. The hash below ships to the browser, so anyone
// who reads the bundle can work around it. It exists to keep the site out of
// casual view while NobleChat is still being tested, nothing more. Everything
// that actually needs protecting sits behind the account login and the
// end-to-end encryption, neither of which depends on this file.
//
// Both entry points share one session flag, so unlocking the landing page also
// opens /app in the same tab (and the other way round).

export const GATE_HASH = "b34f7fb73eea21931199bcd983951029b3df3ef407a7e58d617cf03747014f1a";
export const GATE_OK = "noblechat:gate-ok";

export async function sha256Hex(str) {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

// True when the typed value opens the gate. Never throws: a browser without
// crypto.subtle (an insecure origin, say) just keeps the gate shut.
export async function unlocks(value) {
  if (typeof value !== "string" || value === "") return false;
  try {
    return (await sha256Hex(value)) === GATE_HASH;
  } catch {
    return false;
  }
}

// sessionStorage is unavailable in some privacy modes, so both helpers degrade
// to "locked" rather than breaking the page.
export function isUnlocked() {
  try {
    return sessionStorage.getItem(GATE_OK) === "1";
  } catch {
    return false;
  }
}

export function markUnlocked() {
  try {
    sessionStorage.setItem(GATE_OK, "1");
  } catch {
    /* nothing to do; the visitor just gets asked again next page load */
  }
}
