// The mix network topology: layered mix nodes + provider (gateway) nodes.
import { generateNodeKey } from "../../sphinx/src/sphinx.js";
import { randomBytes, toB64, concatBytes, utf8ToBytes } from "../../crypto/src/util.js";
import { hash } from "../../crypto/src/kdf.js";

// When a `seed` is given the whole topology (node ids AND keys) is derived
// deterministically from it, so restarting the server yields the SAME network.
// That matters because clients bake a provider id into their identity and
// publish it to peers — if the topology were random per boot, every restart
// would orphan existing identities ("unknown provider" when routing back).
function makeNode(label, seed) {
  if (seed) {
    const id = hash(concatBytes(seed, utf8ToBytes("id:" + label))).slice(0, 16);
    const keySeed = hash(concatBytes(seed, utf8ToBytes("key:" + label)));
    return { id, key: generateNodeKey(keySeed), label };
  }
  return { id: randomBytes(16), key: generateNodeKey(), label };
}

export function buildTestnet({ layers = 3, perLayer = 2, providers = 2, seed = null } = {}) {
  const master = seed == null ? null : (typeof seed === "string" ? hash(utf8ToBytes(seed)) : seed);

  const layerNodes = [];
  for (let l = 0; l < layers; l++) {
    const row = [];
    for (let n = 0; n < perLayer; n++) row.push(makeNode(`mix-L${l}-${n}`, master));
    layerNodes.push(row);
  }
  const providerNodes = [];
  for (let p = 0; p < providers; p++) providerNodes.push(makeNode(`provider-${p}`, master));

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
