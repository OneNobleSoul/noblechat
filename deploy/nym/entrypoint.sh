#!/bin/sh
# First run: create the client identity (keys + gateway registration) under
# /root/.nym, which the compose file mounts as a volume so the mixnet address
# stays stable across restarts and upgrades. Later runs skip straight to run.
set -e

ID="${NYM_CLIENT_ID:-noblechat}"

if [ ! -d "/root/.nym/clients/$ID" ]; then
  echo "no client config for '$ID' yet, initialising..."
  nym-client init --id "$ID"
fi

# --host 0.0.0.0 so the gateway container can reach the websocket; the compose
# network is internal-only, nothing is published to the outside.
exec nym-client run --id "$ID" --host 0.0.0.0
