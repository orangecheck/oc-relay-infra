# Dockerfile — relay.ochk.io
#
# Single-stage:
#   1. dockurr/strfry pinned image as base (it builds strfry reproducibly upstream).
#   2. Add Python for the write-policy plugin + the plugin file + our config.
#
# The write-policy plugin is Python (musl-native on this Alpine base). The
# previous build copied a glibc-linked Deno binary onto this musl base, so Deno
# could not run and strfry rejected every event ("internal error") — the relay
# stored nothing from 2026-05-08. Python's apk package is musl-native, so it
# runs without a glibc-compat layer.
#
# Fly handles TLS termination at the edge (see fly.toml [[services.ports]]),
# so this image only listens internally on :7777. No Caddy, no Let's Encrypt
# bookkeeping inside the container.

FROM dockurr/strfry:0.9.7

USER root

# `python3` runs the write-policy plugin (musl-native — no glibc mismatch).
RUN apk add --no-cache ca-certificates bash python3

# App layout. The plugin lives where strfry.conf points.
RUN mkdir -p /data/strfry/db /data/strfry/policy /data/strfry/logs

COPY strfry.conf /etc/strfry.conf
COPY policy/oc-dtag-filter.py /data/strfry/policy/oc-dtag-filter.py
COPY sync/backfill.sh /usr/local/bin/oc-relay-backfill
RUN chmod +x /data/strfry/policy/oc-dtag-filter.py /usr/local/bin/oc-relay-backfill

EXPOSE 7777

ENTRYPOINT ["/app/strfry", "--config=/etc/strfry.conf"]
CMD ["relay"]
