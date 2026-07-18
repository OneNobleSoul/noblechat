# NobleChat

Private messaging over a real mix network with hybrid post-quantum encryption.

[![ci](https://github.com/OneNobleSoul/noblechat/actions/workflows/ci.yml/badge.svg)](https://github.com/OneNobleSoul/noblechat/actions/workflows/ci.yml)
[![codeql](https://github.com/OneNobleSoul/noblechat/actions/workflows/codeql.yml/badge.svg)](https://github.com/OneNobleSoul/noblechat/actions/workflows/codeql.yml)
[![license: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

NobleChat encrypts every message end to end in the browser and routes it through
a Sphinx style mix network, so the server never sees message content and cannot
tell a real message from cover traffic. Keys are generated on your device and
never leave it.

## Status

This is a working project, not a finished product. The individual cryptographic
primitives come from the audited `@noble` libraries, but the way they are
composed here (the Sphinx layer, the packet and mailbox format, the account and
multi device model) has not had an independent security audit. Do not rely on it
to protect real secrets until that review has happened. See
[SECURITY.md](SECURITY.md) and [docs/ENTERPRISE.md](docs/ENTERPRISE.md) for an
honest gap analysis.

## What is inside

- Hybrid post-quantum key exchange (X25519 + ML-KEM-768) and hybrid signatures
  (Ed25519 + ML-DSA-65).
- A real mix network: layered mix nodes and providers, Poisson mixing, constant
  size packets, and cover traffic. Each node runs as its own process and only
  ever learns its own hop.
- A zero-knowledge gateway: it only handles opaque onion packets, a mailbox id,
  public contact cards, a password hash, and an opaque (client encrypted)
  contacts blob.
- Accounts with password login, multi device fan out, and durable offline
  delivery backed by PostgreSQL.
- An admin panel for announcements, maintenance mode, and moderation.
- Installable clients: a PWA (desktop, Android, iOS home screen) plus native
  desktop and Android builds produced by CI.

## Architecture

```
browser client  --ws-->  gateway  --http-->  mix node L1 -> L2 -> L3 -> provider
   (crypto)              (accounts,            (each is a separate process,
                          mailboxes,            holds only its own key)
                          web, admin)                 |
                                                  delivers back to the gateway,
                                                  which pushes to the recipient
```

- `packages/crypto` hybrid PQ primitives, AEAD, KDF.
- `packages/sphinx` fixed size onion packet format.
- `packages/net` mix router, directory, wire serialization, client helpers.
- `packages/protocol` content and envelope framing.
- `apps/server` the gateway (HTTP, WebSocket, accounts, admin, PostgreSQL).
- `apps/node` a single mix node process.
- `apps/web` the browser client and PWA.
- `clients/desktop` Electron shell, `clients/mobile` Capacitor shell.

## Quick start (self host)

Requires Docker and Docker Compose.

```sh
cp .env.example .env
# edit .env and set strong values for every secret
docker compose up -d --build
```

The gateway listens on port 8790 inside the compose network. Put a reverse proxy
(for example Caddy or nginx) in front of it for TLS. The compose file also starts
the mix nodes, the providers, and a PostgreSQL database.

## Development

Requires Node.js 20 or newer.

```sh
npm install
npm test            # unit tests for crypto, sphinx, and the router
npm run build:web   # bundle the browser client
npm run smoke       # optional headless end to end check
```

## Clients

Open the deployment URL in any modern browser. To install as an app:

- Desktop (Chrome or Edge): use the install icon in the address bar.
- Android (Chrome): menu, then "Add to Home screen".
- iPhone (Safari): Share, then "Add to Home Screen".

Tagged releases also build native desktop installers (AppImage, dmg, exe) and an
Android apk and attach them to the GitHub release. See the clients section in the
repository and `docs/ENTERPRISE.md` for the iOS note.

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and the
[code of conduct](CODE_OF_CONDUCT.md).

## License

AGPL-3.0. See [LICENSE](LICENSE).
