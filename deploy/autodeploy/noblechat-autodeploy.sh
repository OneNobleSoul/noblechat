#!/bin/bash
# Poll GitHub for new commits on main and redeploy this stack when the deployed
# revision falls behind. Runs on the host via a systemd timer; it does not need
# any secret stored in GitHub. The GitHub token used only to read a private repo
# lives in a root-only file on the host (see TOKEN_FILE).
#
# Safe to run every couple of minutes: if the remote HEAD equals the deployed
# HEAD it is a no-op. A flock guards against overlapping runs during a slow
# rebuild.
set -euo pipefail

REPO_DIR="${REPO_DIR:-/root/noblechat}"
REPO_SLUG="${REPO_SLUG:-OneNobleSoul/noblechat}"
BRANCH="${BRANCH:-main}"
TOKEN_FILE="${TOKEN_FILE:-/root/.noblechat-deploy-token}"
LOG="${LOG:-/root/noblechat-autodeploy.log}"
LOCK="/run/noblechat-autodeploy.lock"

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" >>"$LOG"; }

exec 9>"$LOCK"
if ! flock -n 9; then
  # Another run (probably a rebuild) is in progress; skip this tick quietly.
  exit 0
fi

[ -f "$TOKEN_FILE" ] || { log "ERROR token file $TOKEN_FILE missing"; exit 1; }
TOKEN="$(tr -d '\r\n' <"$TOKEN_FILE")"
REMOTE_URL="https://${TOKEN}@github.com/${REPO_SLUG}.git"

remote_sha="$(git ls-remote "$REMOTE_URL" "refs/heads/${BRANCH}" | cut -f1)"
[ -n "$remote_sha" ] || { log "ERROR could not read remote sha"; exit 1; }
local_sha="$(git -C "$REPO_DIR" rev-parse HEAD 2>/dev/null || echo none)"

if [ "$remote_sha" = "$local_sha" ]; then
  exit 0
fi

log "update: $local_sha -> $remote_sha, deploying"
cd "$REPO_DIR"
git fetch -q "$REMOTE_URL" "$BRANCH"
git reset -q --hard FETCH_HEAD
gateway_ok() {
  docker inspect -f '{{.State.Running}}' noblechat 2>/dev/null | grep -q true \
    && docker exec noblechat node -e 'fetch("http://127.0.0.1:8790/healthz").then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))' >/dev/null 2>&1
}

# The previous blanket `docker compose up -d --build` recreated all 11 containers
# at once; the nym-client's long stop grace could stall that batch and leave the
# gateway "Created" (not running) -> 502. Deploy gateway-first instead:

# 1. Build the image up front - no containers are touched, so no downtime.
if ! docker compose build >>"$LOG" 2>&1; then
  log "ERROR build failed; see docker output above"; exit 1
fi

# 2. Recreate ONLY the gateway with the new image and confirm it serves, so the
#    site is back within seconds regardless of the slower node/sidecar churn.
for attempt in 1 2 3 4 5; do
  docker compose up -d --no-deps noblechat >>"$LOG" 2>&1 || true
  for _ in $(seq 1 6); do gateway_ok && break; sleep 5; done
  gateway_ok && break
  log "gateway not up yet after targeted start (attempt $attempt)"
done
if ! gateway_ok; then log "ERROR gateway did not come up; manual attention needed"; exit 1; fi

# 3. Reconcile the rest (mix nodes, nym-client) now that the site already serves.
#    The gateway already matches the desired state, so this won't recreate it; if
#    the nym-client stop grace stalls here it no longer causes an outage.
docker compose up -d >>"$LOG" 2>&1 || true
gateway_ok || { docker compose up -d --no-deps noblechat >>"$LOG" 2>&1 || true; }
log "deploy ok, now at $(git rev-parse HEAD)"
exit 0
