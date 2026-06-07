// The mix network topology: layered mix nodes + provider (gateway) nodes.
import { generateNodeKey } from "../../sphinx/src/sphinx.js";
import { randomBytes, toB64 } from "../../crypto/src/util.js";

function makeNode(label) {
  return { id: randomBytes(16), key: generateNodeKey(), label };
}

export function buildTestnet({ layers = 3, perLayer = 2, providers = 2 } = {}) {
  const layerNodes = [];
  for (let l = 0; l < layers; l++) {
    const row = [];
    for (let n = 0; n < perLayer; n++) row.push(makeNode(`mix-L${l}-${n}`));
    layerNodes.push(row);
  }
  const providerNodes = [];
  for (let p = 0; p < providers; p++) providerNodes.push(makeNode(`provider-${p}`));

  const byId = new Map();
  const key = (id) => toB64(id);
  for (const row of layerNodes) for (const n of row) byId.set(key(n.id), n);
  for (const p of providerNodes) byId.set(key(p.id), p);

  return {
    layers: layerNodes,
    providers: providerNodes,
    lookup: (id) => byId.get(key(id)),
    isProvider: (id) => providerNodes.some((p) => key(p.id) === key(id)),

    // choose one mix node per layer, then the recipient's provider
    pickPath(providerId) {
      const path = layerNodes.map((row) => row[Math.floor(Math.random() * row.length)]);
      const provider = byId.get(key(providerId));
      if (!provider) throw new Error("unknown provider");
      path.push(provider);
      return path.map((n) => ({ id: n.id, public: n.key.public }));
    },

    // what a client is allowed to know: ids + public keys, no secrets
    publicView() {
      return {
        layers: layerNodes.map((row) => row.map((n) => ({ id: toB64(n.id), public: toB64(n.key.public) }))),
        providers: providerNodes.map((p) => ({ id: toB64(p.id), public: toB64(p.key.public), label: p.label })),
      };
    },
  };
}
