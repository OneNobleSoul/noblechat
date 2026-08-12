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

### Security
Findings from an external penetration test of chat.noblesoul.tech, August 2026.

- The password is no longer sent to the server. It used to be, and the contacts
  blob key was derived from that same password salted with the handle, so the
  server held both halves and could decrypt the blob it stores: contact list,
  group membership, and the key pins that exist to detect a server swapping
  someone's keys. Sign-in now sends a value derived under a separate salt, which
  proves who you are without the blob key following from it. Old accounts
  upgrade silently on their next sign-in; nobody needs to reset a password.
- The login throttle worked on the leftmost `X-Forwarded-For` entry, which the
  caller supplies. A different fake value per request made every attempt look
  like a new visitor, so the limit never fired: 12 wrong passwords in a row drew
  12 plain 401s. The gateway now reads the entry its own proxy appended
  (`TRUSTED_PROXY_HOPS`, default 1), and a per-handle backoff was added on top.
- `/api/bundle` and `/api/file` require a session. The first was an open user
  directory: it distinguished existing handles from missing ones and returned
  the mailbox id, provider id and device count for each, enough to map the user
  base and link mailbox ids back to handles. The second served attachment
  ciphertext to anyone holding an id.
- Attachment media types are no longer stored or returned. They came from a
  client header and sat in the clear beside otherwise opaque ciphertext;
  nothing ever read them back, since the real type travels inside the encrypted
  message.
- `connect-src` no longer ends in a blanket `https:`, which was a ready-made
  exfiltration channel for any injected script. The wildcard is granted only
  when a nym sidecar is configured, and `NYM_CONNECT_SRC` narrows it further.
- `style-src` dropped `'unsafe-inline'`: the embedded `<style>` blocks and
  `style=""` attributes moved into stylesheets and classes.
- Fonts are served from this server instead of Google, so no visitor's IP
  address is handed to a font CDN before the page renders.
- The contacts blob key is derived non-extractable and kept in IndexedDB rather
  than exported into `localStorage` beside the session token, so script running
  on the page can use it but not read it out.
- Request fields are type-checked instead of coerced. `String(["kirito"])` is
  `"kirito"`, so a JSON array used to pass the handle check; and an oversized
  contacts blob was silently truncated and stored, leaving the account unable
  to decrypt its own contacts.
- Added `/.well-known/security.txt`.

Two findings needed no change. The device limit the report could not confirm
from outside does exist (`MAX_DEVICES_PER_ACCOUNT`, default 10). The
coming-soon gate on the landing page is client-side by design and its own text
says so; it limits who opens the page and is not an access control.

### Removed
- `scripts/gen-compose.py`. `docker-compose.yml` is maintained by hand and is
  the source of truth; the generator had drifted behind the hand-added
  nym-client, coturn, and volume config and would have silently deleted them.
- The `x-file-type` header on uploads and downloads (see Security above).

## 0.1.0

### Added
- Initial release: hybrid post-quantum key exchange, a Sphinx style mix network,
  cover traffic, a zero-knowledge gateway, and a browser client.
