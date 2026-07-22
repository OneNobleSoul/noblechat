// The mix network topology: layered mix nodes + provider (gateway) nodes.
import { generateNodeKey } from "../../sphinx/src/sphinx.js";
import { randomBytes, toB64, concatBytes, utf8ToBytes, randomIndex } from "../../crypto/src/util.js";
import { hash } from "../../crypto/src/kdf.js";

// A node's network hostname is its label, lower-cased (docker service name).
function urlFor(label, mixPort) {
  return `http://${label.toLowerCase()}:${mixPort}/mix`;
}

function makeNode(label, seed) {
  if (seed) {
    const id = hash(concatBytes(seed, utf8ToBytes("id:" + label))).slice(0, 16);
    const keySeed = hash(concatBytes(seed, utf8ToBytes("key:" + label)));
    return { id, key: generateNodeKey(keySeed), label };
  }
  return { id: randomBytes(16), key: generateNodeKey(), label };
}

export function buildTestnet({ layers = 3, perLayer = 2, providers = 2, seed = null, mixPort = 8890 } = {}) {
  const master = seed == null ? null : (typeof seed === "string" ? hash(utf8ToBytes(seed)) : seed);

  const layerNodes = [];
  for (let l = 0; l < layers; l++) {
    const row = [];
    for (let n = 0; n < perLayer; n++) { const node = makeNode(`mix-L${l}-${n}`, master); node.url = urlFor(node.label, mixPort); row.push(node); }
    layerNodes.push(row);
  }
  const providerNodes = [];
  for (let p = 0; p < providers; p++) { const node = makeNode(`provider-${p}`, master); node.url = urlFor(node.label, mixPort); providerNodes.push(node); }

  const byId = new Map();
  const key = (id) => toB64(id);
  for (const row of layerNodes) for (const n of row) byId.set(key(n.id), n);
  for (const p of providerNodes) byId.set(key(p.id), p);

  return {
    layers: layerNodes,
    providers: providerNodes,
    lookup: (id) => byId.get(key(id)),
    urlOf: (id) => { const n = byId.get(key(id)); return n ? n.url : null; },
    isProvider: (id) => providerNodes.some((p) => key(p.id) === key(id)),

    pickPath(providerId) {
      const path = layerNodes.map((row) => row[randomIndex(row.length)]);
      const provider = byId.get(key(providerId));
      if (!provider) throw new Error("unknown provider");
      path.push(provider);
      return path.map((n) => ({ id: n.id, public: n.key.public }));
    },

    publicView() {
      return {
        layers: layerNodes.map((row) => row.map((n) => ({ id: toB64(n.id), public: toB64(n.key.public) }))),
        providers: providerNodes.map((p) => ({ id: toB64(p.id), public: toB64(p.key.public), label: p.label })),
      };
    },
  };
}
