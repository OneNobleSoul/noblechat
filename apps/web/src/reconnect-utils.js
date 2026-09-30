// Pure helper for the gateway reconnect backoff (see the close handler in
// connectWS() in main.js). Pulled out so the backoff math can be unit
// tested without a real WebSocket.
//
// A flat 1.5s retry meant every open tab reconnected on the same clock tick
// whenever the gateway restarted (deploy, crash, network blip), all hitting
// the server again the moment it came back up. Backing off exponentially
// per failed attempt, with a little randomness so tabs do not all retry in
// lockstep, spreads that load out instead of piling it onto the first
// second the gateway is reachable again.
export function reconnectDelay(attempts, { base = 1500, max = 30000, rand = Math.random } = {}) {
  const n = Math.max(0, attempts | 0);
  const raw = base * 2 ** n;
  const capped = Math.min(raw, max);
  // +/-20% jitter so many tabs backing off the same way do not stay in sync.
  const jitter = 0.8 + rand() * 0.4;
  return Math.round(capped * jitter);
}
