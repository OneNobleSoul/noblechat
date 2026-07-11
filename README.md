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

Working end to end, built in the open. Every layer is tested.

| Component | What it does | State |
|-----------|--------------|-------|
| `packages/crypto` | hybrid X25519+ML-KEM exchange, XChaCha20-Poly1305, Ed25519+ML-DSA signatures | ✅ tested |
| `packages/sphinx` | Sphinx onion packet: fixed size, per-hop key blinding, per-hop MAC, payload onion | ✅ tested |
| `packages/protocol` | end-to-end envelope, addressing, wire framing | ✅ tested |
| `packages/net` | layered mix router with Poisson mixing, provider mailboxes, cover-traffic loops | ✅ tested |
| `apps/server` | zero-knowledge gateway + local testnet + public key directory | ✅ working |
| `apps/web` | the chat UI + a live view of packets moving through the mix layers | ✅ working |

## Run it

```bash
npm install
npm start          # builds the web client and starts the gateway on :8790
```

Then open **http://localhost:8790** in two browser tabs (or two browsers):

1. In each tab, pick a handle (e.g. `kirito` and `asuna`). Keys are generated
   locally in that tab.
2. In one tab, add the other by their handle and start chatting.
3. Flip **cover: on** to emit indistinguishable dummy packets, and watch the
   MIX NETWORK panel light up as packets hop through the layers.

Run the tests / the headless end-to-end check:

```bash
npm test           # 12 unit + integration tests
npm run smoke      # two clients exchange messages through the live gateway
```

## How a message travels

```
you ──[hybrid PQ E2E encrypt]──► [ mailboxId | envelope ]
    ──[wrap in a fixed-size Sphinx onion for a random path]──►
      mix L1 ─(delay)─► mix L2 ─(delay)─► mix L3 ─(delay)─► provider
                                                              └─► recipient's mailbox ──► recipient decrypts
```

Each mix node peels exactly one layer, learns only the next hop, waits a random
(Poisson) delay and forwards. The gateway/provider only ever sees opaque, equal-
sized packets and a mailbox to drop ciphertext into — never who sent it or what
it says. Cover-traffic loops keep a steady stream flowing so *whether* you're
talking is hidden too.

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

## Clients & install

NobleChat runs in any modern browser at your deployment URL, and installs as an
app on all three platforms.

### Install as an app (no store needed)

- **Desktop (Chrome/Edge):** open the site, click the install icon in the
  address bar.
- **Android (Chrome):** menu → "Add to Home screen" / "Install app".
- **iPhone (Safari):** Share → "Add to Home Screen". Runs full-screen with its
  own icon; same client-side crypto as the browser.

This works because NobleChat is a PWA (web app manifest + service worker).

### Native builds

Tagged releases build native clients in CI and attach them to the GitHub
release:

- **Desktop** (`clients/desktop`, Electron): AppImage (Linux), `.dmg` (macOS),
  `.exe` installer (Windows). Point it at another deployment with the
  `NOBLECHAT_URL` env var.
- **Android** (`clients/mobile`, Capacitor): a sideloadable debug `.apk`.

To cut a release: `git tag v0.1.0 && git push origin v0.1.0` — the `release`
workflow does the rest.

> **iOS note:** Apple does not allow app distribution via GitHub. A native
> iPhone build needs an Apple Developer account, a Mac (or macOS CI), and App
> Store review. The Capacitor iOS project is ready in `clients/mobile`; until
> then, iPhone users install the PWA. See `docs/ENTERPRISE.md`.

### Is this ready to sell as "enterprise-secure"?

Not yet — and that claim specifically needs an independent security audit plus
backend hardening. `docs/ENTERPRISE.md` is an honest gap analysis and roadmap.
