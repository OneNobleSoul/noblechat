# Security policy

## Important context

NobleChat is under active development and has not had an independent security
audit. The cryptographic primitives come from the audited `@noble` libraries,
but their composition here (the Sphinx layer, the packet and mailbox format, the
account and multi device model) has not been reviewed by a third party. Treat
this software as experimental and do not use it to protect real secrets yet.

## Reporting a vulnerability

Please do not open a public issue for security problems.

Report privately through GitHub Security Advisories:

1. Go to the "Security" tab of the repository.
2. Click "Report a vulnerability".
3. Describe the issue, the impact, and steps to reproduce.

If you cannot use the advisory flow, you can open a minimal public issue that
asks a maintainer to reach out, without any technical detail.

We aim to acknowledge a report within a few days and to keep you updated while we
work on a fix. We will credit you in the advisory unless you prefer to stay
anonymous.

## Scope

In scope:

- The gateway, mix node, and client code in this repository.
- The mix routing, onion packet handling, and account and session logic.
- Cryptographic misuse, key handling, and metadata leaks.

Out of scope:

- Denial of service that only affects a single self hosted deployment.
- Issues that require a already compromised device or a malicious browser
  extension.
- Findings in third party dependencies (please report those upstream, but let us
  know so we can pin or patch).

## Supported versions

The project has not reached a stable release yet. Security fixes land on `main`.
Once tagged releases stabilise, this table will list supported versions.

| Version | Supported |
| ------- | --------- |
| main    | yes       |

## Handling of secrets

Never commit secrets. All deployment secrets live in a local `.env` file that is
ignored by git. See `.env.example` for the variables a deployment needs.
