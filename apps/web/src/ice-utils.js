// Pure ICE-server helper. Pulled out of main.js (see the block comment above
// isTurnServer() there for the security rationale: calls must be forced onto
// a TURN relay when one exists, so the peer never learns a caller's real IP)
// so it can be unit tested without a DOM: main.js touches the DOM the moment
// it runs, which makes it awkward to import individual pieces into a test
// file.

// True when an RTCIceServer entry has at least one turn: URL. Used to filter
// the ICE server list down to relay-only servers once a TURN relay is known
// to be configured (see newPeerConnection in main.js), and to decide whether
// any relay is available at all (fetchIceServers' hasTurn flag).
export function isTurnServer(s) {
  const arr = Array.isArray(s && s.urls) ? s.urls : [s && s.urls];
  return arr.some((x) => typeof x === "string" && x.toLowerCase().startsWith("turn:"));
}
