# NobleChat - the honest road to an enterprise product

This document is deliberately blunt. NobleChat today is a strong, working
**prototype** of private messaging over a real mix network with hybrid
post-quantum key exchange. That is genuinely rare and valuable. But "a secure
enterprise communications product you can sell on its security" is a higher bar,
and a few of the remaining steps are things no amount of coding can shortcut.

## What is real today

- Hybrid post-quantum key exchange (X25519 + ML-KEM-768) and hybrid signatures
  (Ed25519 + ML-DSA-65), using the audited `@noble` primitives.
- A working Sphinx-style mix network (layered nodes + providers), Poisson
  mixing, constant-size packets, and cover traffic - so the server cannot tell a
  real message from cover, nor a sender from a receiver by packet shape.
- End-to-end encryption performed entirely in the client; the gateway only ever
  sees opaque, fixed-size onion packets and a mailbox id.
- Installable clients on desktop, Android and iOS via PWA (home screen), plus a
  packaged desktop app and an Android APK produced by CI.
- A deterministic, restart-stable network topology and a test suite.

## What must happen before selling it as "enterprise-secure"

These are ordered by how much they gate a sale.

### 1. Independent security audit (hard gate - do not sell without it)
The protocol composition (our Sphinx layer, the packet/mailbox format, the
handshake, replay handling) is **custom and unaudited**. The individual crypto
primitives are solid; the way we glue them together is what needs expert review.
Selling unaudited custom crypto as "enterprise-secure" is both a real risk to
customers and a legal/reputational risk to us. Budget for a reputable firm
(e.g. Trail of Bits, Cure53, NCC Group) to review the protocol and the client.

### 2. A written threat model and security whitepaper
Buyers' security teams will ask "what exactly do you protect against, and what
do you not?" We need an explicit model: global passive adversary, malicious
server, compromised endpoint, traffic-analysis bounds of the mixnet at our size,
metadata we do and do not reveal. Honesty here is a feature, not a weakness.

### 3. Backend hardening (currently prototype-grade)
- The key directory and mailboxes are **in-memory** and single-process - they do
  not survive a restart and do not scale. Needs durable storage, real mailbox
  queuing, and offline delivery so a message waits for a recipient who is away.
- The mix network runs **in one process**. A real deployment wants independent
  mix/provider nodes (ideally run by different operators) for the anonymity set
  to mean anything.
- No rate limiting, abuse controls, or DoS protection yet.

### 4. Identity, accounts and multi-device
Today an identity is a browser-local keypair with a chosen handle and no
verification. Enterprise needs: verified organisational identity (SSO/SCIM),
safety-number/key verification between users, multi-device support (your keys on
phone *and* laptop), and key backup/recovery that does not break the security
model.

### 5. Features enterprises expect
Group chats (MLS / RFC 9420 is the right target), file/attachment transfer,
message history sync, read state, search, and mobile **push notifications**
(which for iOS/Android means running notification infrastructure without leaking
metadata - non-trivial for a metadata-minimising system).

### 6. Compliance & operations
SOC 2 / ISO 27001 posture, data-processing agreements, an admin console,
audit logging, retention controls, and a documented incident-response process.
These are usually contractual requirements, not nice-to-haves.

## The iOS distribution reality

You asked for iPhone clients "directly on GitHub". Apple does not permit that:
iOS apps can only be distributed through the App Store (or TestFlight / an
enterprise MDM cert). Shipping a real iPhone app requires:

- an Apple Developer account (99 USD/year),
- a macOS machine (or a macOS CI runner) to build and sign the `.ipa`,
- App Store review.

Until that is in place, iPhone users install NobleChat as a PWA (Safari →
Share → "Add to Home Screen"). It runs full-screen with its own icon and uses
the same client-side crypto. The Capacitor iOS project in `clients/mobile` is
ready to open in Xcode once you have the account and a Mac.

## Suggested sequence

1. Ship the PWA + desktop + Android APK as an **open beta** (done / in CI).
2. Write the threat model + whitepaper.
3. Harden the backend (persistence, offline delivery, separate nodes).
4. Commission the security audit; fix findings.
5. Add accounts/multi-device, then groups and push.
6. Then, and only then, market it as enterprise-secure.
