# Dockerfile — relay.ochk.io
#
# Single-stage:
#   1. dockurr/strfry pinned image as base (it builds strfry reproducibly upstream).
#   2. Add Deno for the write-policy plugin + the plugin file + our config.
#
# Fly handles TLS termination at the edge (see fly.toml [[services.ports]]),
# so this image only listens internally on :7777. No Caddy, no Let's Encrypt
# bookkeeping inside the container.

FROM dockurr/strfry:0.9.7

USER root

# Deno for the write-policy plugin. Slim install — we only need the binary,
# no toolchain or stdlib.
RUN apk add --no-cache curl unzip ca-certificates bash \
    && curl -fsSL https://github.com/denoland/deno/releases/download/v1.46.3/deno-x86_64-unknown-linux-gnu.zip -o /tmp/deno.zip \
    && unzip -q /tmp/deno.zip -d /usr/local/bin \
    && rm /tmp/deno.zip \
    && chmod +x /usr/local/bin/deno

# App layout. The plugin lives where strfry.conf points.
RUN mkdir -p /data/strfry/db /data/strfry/policy /data/strfry/logs

COPY strfry.conf /etc/strfry.conf
COPY policy/oc-dtag-filter.ts /data/strfry/policy/oc-dtag-filter.ts
COPY sync/backfill.sh /usr/local/bin/oc-relay-backfill
RUN chmod +x /data/strfry/policy/oc-dtag-filter.ts /usr/local/bin/oc-relay-backfill

# Cache the Deno script so cold starts don't fetch.
RUN deno cache /data/strfry/policy/oc-dtag-filter.ts

EXPOSE 7777

ENTRYPOINT ["/app/strfry", "--config=/etc/strfry.conf"]
CMD ["relay"]
