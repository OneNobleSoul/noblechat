#!/bin/sh
# First run: create the client identity (keys + gateway registration) under
# /root/.nym, which the compose file mounts as a volume so the mixnet address
# stays stable across restarts and upgrades. Later runs skip straight to run.
set -e

ID="${NYM_CLIENT_ID:-noblechat}"
STARTFILE="/root/.nym/.nym-client-last-start"
STREAKFILE="/root/.nym/.nym-client-crash-streak"
FAST_CRASH_SECONDS=90
CRASH_STREAK_LIMIT=3

if [ ! -d "/root/.nym/clients/$ID" ]; then
  echo "no client config for '$ID' yet, initialising..."
  nym-client init --id "$ID"
fi

# If the registered gateway goes away for good (decommissioned, long outage),
# the client can never authenticate again with that identity - every run
# fails within seconds ("the client is not registered") and restart:
# unless-stopped just crash-loops the container forever, leaving the app
# stuck on the internal transport fallback instead of the mixnet.
#
# Detect that by how FAST consecutive restarts happen (a healthy client runs
# for hours/days, a rejected one dies in seconds) instead of parsing
# nym-client's own log output, so the `exec` handoff below - needed for a
# graceful reply-store flush on shutdown, see docker-compose.yml - stays
# untouched for the normal case.
NOW=$(date +%s)
LAST=0
[ -f "$STARTFILE" ] && LAST=$(cat "$STARTFILE" 2>/dev/null || echo 0)
case "$LAST" in ''|*[!0-9]*) LAST=0 ;; esac
STREAK=0
[ -f "$STREAKFILE" ] && STREAK=$(cat "$STREAKFILE" 2>/dev/null || echo 0)
case "$STREAK" in ''|*[!0-9]*) STREAK=0 ;; esac

if [ "$LAST" -gt 0 ] && [ $((NOW - LAST)) -lt "$FAST_CRASH_SECONDS" ]; then
  STREAK=$((STREAK + 1))
else
  STREAK=0
fi
echo "$STREAK" > "$STREAKFILE"
echo "$NOW" > "$STARTFILE"

if [ "$STREAK" -ge "$CRASH_STREAK_LIMIT" ]; then
  echo "nym-client keeps crashing within ${FAST_CRASH_SECONDS}s of starting (${STREAK}x in a row), re-initialising with a fresh gateway..."
  rm -rf "/root/.nym/clients/$ID"
  nym-client init --id "$ID"
  rm -f "$STREAKFILE"
fi

# --host 0.0.0.0 so the gateway container can reach the websocket; the compose
# network is internal-only, nothing is published to the outside.
exec nym-client run --id "$ID" --host 0.0.0.0
