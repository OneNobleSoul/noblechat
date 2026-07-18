# Contributing to NobleChat

Thanks for taking the time to contribute. This document explains how to get set
up, how to propose changes, and what we look for in a pull request.

## Ways to help

- Report a bug or a security issue (see [SECURITY.md](SECURITY.md) for the
  private reporting flow).
- Suggest a feature or an improvement.
- Improve documentation.
- Send a pull request.

For anything larger than a small fix, please open an issue first so we can agree
on the approach before you spend time on it.

## Development setup

You need Node.js 20 or newer. Docker and Docker Compose are needed to run the
full stack locally.

```sh
git clone https://github.com/OneNobleSoul/noblechat.git
cd noblechat
npm install
npm test            # unit tests
npm run build:web   # bundle the browser client
```

To run the whole system locally:

```sh
cp .env.example .env
# set strong values for every secret in .env
docker compose up -d --build
```

## Project layout

- `packages/` the crypto, sphinx, protocol, and net libraries.
- `apps/server` the gateway. `apps/node` a single mix node. `apps/web` the client.
- `clients/` the desktop and mobile shells.
- `tests/` gateway and store tests. Library tests live next to their package.

## Pull requests

- Branch off `main` and keep each pull request focused on one change.
- Make sure `npm test` passes and `npm run build:web` succeeds.
- Add or update tests for behaviour you change.
- Keep the diff small and readable. Split unrelated changes into separate pull
  requests.
- Write clear commit messages in the imperative mood, for example
  "fix stale provider routing" rather than "fixed stuff".
- Do not commit secrets, build output, or `node_modules`.

By contributing you agree that your work is licensed under the project license
(AGPL-3.0).

## Code style

- Plain modern JavaScript (ES modules). No build step for the server or the
  libraries.
- Prefer small, pure functions and clear names over cleverness.
- Match the style of the surrounding code.

## Security

Never report a vulnerability in a public issue or pull request. Use the private
flow described in [SECURITY.md](SECURITY.md).
