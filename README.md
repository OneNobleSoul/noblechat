# NobleChat

Private messaging that protects **what** you say *and* **who** you talk to.

Most "encrypted" messengers only hide message content. The metadata — who talks
to whom, when, how often, from where — usually leaks more than the words do, and
it's exactly what mass surveillance and "chat control" style scanning feed on.
NobleChat is built around two independent layers from day one:

1. **Content** — hybrid **post-quantum** end-to-end encryption. Keys are derived
   from **X25519 *and* ML-KEM-768** together (the Signal PQXDH approach), so a
   future quantum computer that breaks elliptic-curve crypto can't read messages
   it recorded today ("harvest now, decrypt later"). Identities are signed with
   **Ed25519 + ML-DSA-65**.
2. **Metadata** — a real **mix network**. Messages travel as fixed-size,
   layered "onion" packets through several independent mix nodes that delay and
   reorder them, hidden inside a constant stream of **cover traffic** (indistin-
   guishable dummy packets). An observer watching the whole network can't tell
   which incoming packet becomes which outgoing one, or even whether you're
   talking at all.

The server never sees plaintext and never sees a clean "A → B" link. There is
nothing to scan and nothing to hand over — which is the point.

## Status

Early, built in the open. Cryptographic core first, and every piece is tested.

| Component | What it does | State |
|-----------|--------------|-------|
| `packages/crypto` | hybrid X25519+ML-KEM exchange, XChaCha20-Poly1305, Ed25519+ML-DSA signatures | ✅ tested |
| `packages/sphinx` | Sphinx-style onion packet: fixed size, per-hop key blinding, per-hop MAC, payload onion | ✅ tested |
| `apps/mixnode` | mix node: peel a layer, Poisson delay, forward | ⏳ next |
| `apps/provider` | gateway / mailbox for offline delivery | ⏳ next |
| `apps/directory` | network directory: mix nodes, layers, keys | ⏳ next |
| `apps/client` | build packets, run cover-traffic loops, send/receive | ⏳ next |
| `apps/web` | the actual chat UI + a live view of the mixnet | ⏳ next |

Run the tests:

```bash
npm install
node packages/crypto/test.js
node packages/sphinx/test.js
```

## Honest scope

This is a self-hosted **demonstrator of the real principles**, not a drop-in
replacement for a hardened production network. Specifically:

- **"Quantum" means post-quantum cryptography (PQC), not QKD.** True quantum key
  distribution needs special hardware. What actually protects you against future
  quantum computers is PQC — and that's what's implemented (hybrid, never
  PQ-only, so a weakness in a young lattice scheme can't sink you alone).
- **The mix layer is real Sphinx-style onion routing with key blinding**, but a
  small private network gives weaker anonymity than a large one. Unlinkability is
  **statistical** and grows with the number of simultaneous users, the mixing
  delay, and the cover-traffic rate. For serious use you'd route over an
  established mixnet (e.g. Nym) rather than a handful of your own nodes.
- Latency is traded for privacy on purpose (seconds, not milliseconds) — fine for
  chat, not for live video.

## Design references

Based on the project's own research notes: Loopix / Nym (Sphinx packet format,
Poisson mixing, cover traffic, provider model), Signal PQXDH and the Sparse
Post-Quantum Ratchet, MLS (RFC 9420) for group chats, and the FIPS 203/204
post-quantum standards (ML-KEM, ML-DSA).

## License

AGPL-3.0 — self-host it, change it, but keep it free and open.
