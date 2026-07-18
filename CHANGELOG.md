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

## 0.1.0

### Added
- Initial release: hybrid post-quantum key exchange, a Sphinx style mix network,
  cover traffic, a zero-knowledge gateway, and a browser client.
