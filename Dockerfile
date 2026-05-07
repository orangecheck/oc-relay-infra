# Dockerfile — relay.ochk.io
#
# Two-stage:
#   1. Pinned strfry binary from upstream image (built reproducibly there).
#   2. Final image adds Deno (for the write-policy plugin) + the plugin file
#      + entrypoint that launches strfry with the conf.
#
# Caddy + TLS termination is a SEPARATE container in compose.yaml, so this
# image is reusable as-is on Fly.io / Hetzner / bare metal.

FROM dockurr/strfry:0.9.7@sha256:9c6b7c4e6a8b1f9a2c3d4e5f6789abcdef0123456789abcdef0123456789abcd AS strfry-base
# NB: pin the digest above to whatever the latest strfry release is at
# provisioning time. The digest above is a placeholder — Phase 1 step 1
# replaces it with the real one before first deploy.

FROM denoland/deno:alpine-1.46.3 AS final

# Pull strfry binary across.
COPY --from=strfry-base /app/strfry /usr/local/bin/strfry

# Pull the LMDB shared lib if the base image links dynamically.
COPY --from=strfry-base /app/strfry-stuff /app/strfry-stuff

# App layout.
RUN mkdir -p /data/strfry/db /data/strfry/policy /data/strfry/logs

COPY strfry.conf /etc/strfry.conf
COPY policy/oc-dtag-filter.ts /data/strfry/policy/oc-dtag-filter.ts

# Cache deno module deps so cold-start doesn't fetch.
RUN deno cache /data/strfry/policy/oc-dtag-filter.ts

EXPOSE 7777

# Drop privileges before launching strfry. strfry binds <1024 only when
# necessary; port 7777 doesn't need root.
RUN addgroup -S strfry && adduser -S -G strfry strfry && \
    chown -R strfry:strfry /data/strfry
USER strfry

ENTRYPOINT ["/usr/local/bin/strfry", "--config=/etc/strfry.conf", "relay"]
