// Browser-side Nym mixnet client, built as a SEPARATE bundle (it pulls in a
// multi-megabyte WASM SDK) and loaded on demand only when the nym transport is
// actually selected, so users on the internal transport never download it.
//
// It exposes a tiny surface on window.NobleNym; main.js drives it. Sending a
// message means handing our already end-to-end encrypted inner packet to the
// gateway's Nym address; Nym provides the sender anonymity and mixing.
import { createNymMixnetClient } from "@nymproject/sdk-full-fat";

const NYM_API = "https://validator.nymtech.net/api/";

async function create({ onReady = () => {}, onError = () => {} } = {}) {
  let nym = null;
  let ready = false;
  try {
    nym = await createNymMixnetClient();
    nym.events.subscribeToConnected(() => { ready = true; onReady(nym.client.selfAddress()); });
    await nym.client.start({ clientId: "noblechat-" + Math.random().toString(36).slice(2), nymApiUrl: NYM_API, forceTls: true });
  } catch (e) {
    onError(e && e.message ? e.message : String(e));
    return null;
  }
  return {
    isReady: () => ready,
    selfAddress: () => (nym ? nym.client.selfAddress() : null),
    // `text` is the JSON payload string; `recipient` the gateway Nym address.
    async send(text, recipient) {
      await nym.client.send({ payload: { message: text, mimeType: "application/json" }, recipient });
    },
    async stop() { try { await nym.client.stop(); } catch { /* */ } },
  };
}

window.NobleNym = { create };
