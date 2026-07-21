# Changelog

All notable changes to this project are documented here. The format is based on
Keep a Changelog, and the project aims to follow semantic versioning once it
reaches a stable release.

## Unreleased

### Added
- Accounts with password login and sessions, so a handle is owned rather than
  claimed by anyone.
- Multi device support: each device registers its own keys, messages fan out to
  every device of the recipient, and sent messages mirror to your own devices.
- Encrypted contacts sync so a new device restores its contact list.
- Distributed mix network: each mix node and provider runs as its own process
  and only ever learns its own hop.
- Admin panel for announcements, maintenance mode, and moderation.
- PostgreSQL backed durable storage with offline message delivery.
- Installable PWA and native desktop and Android builds from CI.
- Sender authentication: every message envelope is signed with the sender's
  hybrid keypair (Ed25519 + ML-DSA-65) and verified by the recipient against the
  sender's published device cards. Encryption alone never proved who sent a
  message; now it does.

### Changed
- Attachment ciphertext is streamed to disk under `FILES_DIR` instead of being
  buffered in memory and stored as a Postgres blob, so large uploads no longer
  risk running the gateway out of memory.
- Password hashing runs off the event loop (async scrypt), so a login can no
  longer stall message routing.
- The client key that encrypts the contacts-sync blob and local chat history is
  now derived with 600k PBKDF2 iterations (was 100k), per current OWASP
  guidance. A fresh login also derives the old-iteration key once and uses it to
  transparently decrypt and re-encrypt any pre-existing blobs, so contacts and
  history migrate without loss; auto-login is unaffected (its cached key already
  matches its blobs).

### Breaking
- The end-to-end envelope format changed (a version byte plus the sender
  signature, and the fixed mix payload grew from 2048 to 8192 bytes). This is a
  wire break: a recipient running the new client cannot open an envelope built
  by the old one, and `openEnvelope` rejects the old format rather than
  guessing. Two consequences when deploying this:
  - Any messages still queued in a mailbox from before the upgrade are dropped
    on delivery (a one-time loss). Let mailboxes drain, or accept it.
  - All clients must update together; a lagging client stops receiving until it
    reloads the new bundle.
  There is no in-place migration because the server never holds the plaintext or
  keys needed to re-sign an old envelope.

### Removed
- `scripts/gen-compose.py`. `docker-compose.yml` is maintained by hand and is
  the source of truth; the generator had drifted behind the hand-added
  nym-client, coturn, and volume config and would have silently deleted them.

## 0.1.0

### Added
- Initial release: hybrid post-quantum key exchange, a Sphinx style mix network,
  cover traffic, a zero-knowledge gateway, and a browser client.
