FROM ubuntu:24.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Pinned nym release; bump deliberately, the client identity survives upgrades
# via the mounted /root/.nym volume.
ARG NYM_RELEASE=nym-binaries-v2026.13-ziller
RUN curl -fsSL -o /usr/local/bin/nym-client \
      "https://github.com/nymtech/nym/releases/download/${NYM_RELEASE}/nym-client" \
    && chmod +x /usr/local/bin/nym-client

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
