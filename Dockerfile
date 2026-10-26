# Dockerfile — relay.ochk.io
#
# Three stages:
#   1. Build oc-relay-front (front/, Go standard library only) as a static binary.
#   2. node:22-alpine, pinned by digest: the kind-30114 directory gate and the Node runtime it runs on.
#   3. dockurr/strfry pinned image as base (it builds strfry reproducibly
#      upstream), plus Python for the write-policy plugin, our config, the
#      front, the boot script and the gate.
#
# The write-policy plugin is Python (musl-native on this Alpine base). The
# previous build copied a glibc-linked Deno binary onto this musl base, so Deno
# could not run and strfry rejected every event ("internal error") — the relay
# stored nothing from 2026-05-08. Python's apk package is musl-native, so it
# runs without a glibc-compat layer.
#
# Fly handles TLS termination at the edge (see fly.toml [[services.ports]]) and
# forwards to :7777, where oc-relay-front listens. strfry listens on
# 127.0.0.1:7778 only, behind the front.

FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS front
WORKDIR /src
COPY front/ .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/oc-relay-front .

# The kind-30114 directory gate (policy/dir-gate) needs Node 22, newer than this
# Alpine 3.18 base carries. It is installed on the official Node image and copied
# over with the musl loader and C++ runtime it was built against, so it runs
# beside the base's own libraries without touching them.
FROM node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 AS dir-gate
WORKDIR /gate
COPY policy/dir-gate/package.json policy/dir-gate/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
COPY policy/dir-gate/gate.mjs policy/dir-gate/rules.mjs policy/dir-gate/tally.mjs ./
RUN mkdir -p /opt/node/bin /opt/node/lib \
    && cp /usr/local/bin/node /opt/node/bin/ \
    && cp /lib/ld-musl-x86_64.so.1 /opt/node/lib/ \
    && ln -s ld-musl-x86_64.so.1 /opt/node/lib/libc.musl-x86_64.so.1 \
    && cp -L /usr/lib/libstdc++.so.6 /usr/lib/libgcc_s.so.1 /opt/node/lib/

FROM dockurr/strfry:0.9.7

USER root

# `python3` runs the write-policy plugin (musl-native — no glibc mismatch).
RUN apk add --no-cache ca-certificates bash python3

# App layout. The plugin lives where strfry.conf points.
RUN mkdir -p /data/strfry/db /data/strfry/policy /data/strfry/logs

COPY strfry.conf /etc/strfry.conf
COPY policy/oc-dtag-filter.py /data/strfry/policy/oc-dtag-filter.py
COPY --from=dir-gate /opt/node /opt/node
COPY --from=dir-gate /gate /data/strfry/policy/dir-gate
# The gate must load on this base, or every directory write would be refused.
RUN /opt/node/lib/ld-musl-x86_64.so.1 --library-path /opt/node/lib /opt/node/bin/node \
    -e "import('/data/strfry/policy/dir-gate/rules.mjs').then(() => console.log('dir-gate loads'))"
COPY sync/backfill.sh /usr/local/bin/oc-relay-backfill
COPY boot/oc-relay-boot.sh /usr/local/bin/oc-relay-boot
COPY --from=front /out/oc-relay-front /usr/local/bin/oc-relay-front
RUN chmod +x /data/strfry/policy/oc-dtag-filter.py /usr/local/bin/oc-relay-backfill /usr/local/bin/oc-relay-boot

EXPOSE 7777

# The boot script rewrites the store once per volume, then runs the front, which runs strfry.
ENTRYPOINT ["/usr/local/bin/oc-relay-boot"]
