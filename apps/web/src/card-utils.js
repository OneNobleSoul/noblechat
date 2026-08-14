// Pure filtering helper for bundle responses. Pulled out of main.js (see the
// block comment above cardsForHandle() there for the security rationale) so
// it can be unit tested without a DOM: main.js touches the DOM the moment it
// runs, which makes it awkward to import individual pieces into a test file.

// Keep only the device entries whose handle actually matches the one we asked
// about, case-insensitively (handles are stored lowercase everywhere else).
// Returns the surviving entries plus how many were dropped, so the caller can
// warn the user when a bundle included a card for someone else.
export function ownDevicesOnly(devices, handle) {
  const want = String(handle).toLowerCase();
  const all = Array.isArray(devices) ? devices : [];
  const mine = all.filter((c) => c && String(c.handle || "").toLowerCase() === want);
  return { mine, droppedCount: all.length - mine.length };
}
