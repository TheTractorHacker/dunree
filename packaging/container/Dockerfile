# syntax=docker/dockerfile:1
#
# Dunree container image, multi-architecture.
#
# Build from the repository root (the context must hold src/ and docker/entrypoint.py):
#
#   docker buildx build -f packaging/container/Dockerfile \
#       --platform linux/amd64,linux/arm64 -t dunree:local .
#
# The Go program is cross-compiled on the build machine (no emulation), so the extra
# architectures cost little. linux/arm/v7, linux/arm/v6, linux/386 and linux/riscv64 work the
# same way when the base image exists for them.
#
# Build arguments:
#   WITH_ZEROTIER=true|false  include zerotier-one (default true, as the image always had it;
#                             it is compiled from source under emulation for foreign
#                             architectures, which is slow: use false if you do not need it,
#                             ZEROTIER=true then fails at start with a clear message)
#   DUNREE_VERSION, DUNREE_REVISION, DUNREE_SOURCE_URL
#                             recorded in the image labels; the source address is also shown in About
#   GO_IMAGE, RUNTIME_IMAGE         base images (pin them by digest for a reproducible build)
#
# Compatible with the image this one replaces: same environment variables (docker/entrypoint.py),
# same ports, and the old paths /opt/zoraxy/config and /opt/zoraxy/plugin still work because
# /opt/zoraxy is a link to /opt/dunree. Volumes of an existing container can be mounted unchanged.

ARG GO_IMAGE=docker.io/library/golang:1.27-alpine
ARG RUNTIME_IMAGE=docker.io/library/alpine:3
ARG WITH_ZEROTIER=true

## Build Dunree (runs on the build machine's own architecture)
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build-dunree
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG DUNREE_SOURCE_URL=""
WORKDIR /src
COPY src/go.mod src/go.sum ./
RUN go mod download
COPY src/ ./
RUN set -eu; \
    module="$(go list -m)"; \
    goarm=""; \
    if [ "$TARGETARCH" = "arm" ]; then goarm="${TARGETVARIANT#v}"; goarm="${goarm:-7}"; fi; \
    ldflags="-s -w"; \
    if [ -n "$DUNREE_SOURCE_URL" ]; then ldflags="$ldflags -X $module/mod/brand.SourceURL=$DUNREE_SOURCE_URL"; fi; \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" GOARM="$goarm" \
      go build -trimpath -ldflags "$ldflags" -o /out/dunree .

## Build ZeroTier (optional, runs on the target architecture)
FROM docker.io/library/rust:1.79-alpine AS zerotier-true
RUN apk add --update --no-cache curl make gcc g++ linux-headers openssl-dev
WORKDIR /opt/zerotier/source/
# Version is pinned because newer versions do not work with this build recipe
RUN curl -Lo ZeroTierOne.tar.gz https://codeload.github.com/zerotier/ZeroTierOne/tar.gz/refs/tags/1.10.6 &&\
    tar -xzf ZeroTierOne.tar.gz &&\
    cd ZeroTierOne-*/zeroidc &&\
    cargo update -p getrandom &&\
    cd .. &&\
    make -f make-linux.mk &&\
    mkdir -p /out/usr/local/bin &&\
    mv ./zerotier-one /out/usr/local/bin/zerotier-one &&\
    chmod 755 /out/usr/local/bin/zerotier-one

FROM scratch AS zerotier-false
# Nothing: the image is built without zerotier-one.
COPY --from=build-dunree /src/go.mod /out/.without-zerotier

FROM zerotier-${WITH_ZEROTIER} AS zerotier

## Main
FROM ${RUNTIME_IMAGE}
# Not named VERSION: that is one of the environment variables of the entry script (see below).
ARG DUNREE_VERSION=dev
ARG DUNREE_REVISION=""
ARG DUNREE_SOURCE_URL=""
# The same packages as the image this one replaces.
RUN apk add --update --no-cache tzdata python3 netcat-openbsd libressl-dev ca-certificates libc6-compat libstdc++ &&\
    rm -rf /var/cache/apk/* /tmp/*

COPY --chmod=700 docker/entrypoint.py /opt/dunree/entrypoint.py
COPY --from=build-dunree /out/dunree /usr/local/bin/dunree
COPY --from=zerotier /out/ /
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /usr/share/doc/dunree/

# Old names keep working: the entry script and existing compose files use /opt/zoraxy/... and "zoraxy".
RUN mkdir -p /opt/dunree/config /opt/dunree/plugin &&\
    ln -s /opt/dunree /opt/zoraxy &&\
    ln -s dunree /usr/local/bin/zoraxy &&\
    rm -f /.without-zerotier &&\
    echo "tun" | tee -a /etc/modules

WORKDIR /opt/dunree/config/

ENV TZ="Etc/UTC"
ENV ZEROTIER="false"

ENV AUTORENEW="86400"
ENV CFGUPGRADE="true"
ENV DB="auto"
ENV DOCKER="true"
ENV EARLYRENEW="30"
ENV ENABLELOG="true"
ENV FASTGEOIP="false"
ENV MDNS="true"
ENV MDNSNAME="''"
ENV NOAUTH="false"
ENV PLUGIN="/opt/dunree/plugin/"
ENV PORT="8000"
ENV SSHLB="false"
ENV UPDATE_GEOIP="false"
ENV VERSION="false"
ENV WEBROOT="./www"

VOLUME [ "/opt/dunree/config/" ]

LABEL org.opencontainers.image.title="Dunree" \
      org.opencontainers.image.description="Reverse proxy and web gateway" \
      org.opencontainers.image.vendor="Foley IT" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.version="${DUNREE_VERSION}" \
      org.opencontainers.image.revision="${DUNREE_REVISION}" \
      org.opencontainers.image.source="${DUNREE_SOURCE_URL}" \
      ie.foleyit.dunree.container-identifier="Dunree" \
      ie.foleyit.dunree.based-on="Zoraxy v3.3.6 by tobychui and imuslab (AGPL-3.0); independent derivative, not endorsed by them"
# Kept so that tools which look for the old identifier still find the container.
LABEL com.imuslab.zoraxy.container-identifier="Zoraxy"

EXPOSE 80 443 443/udp 8000

ENTRYPOINT [ "python3", "-u", "/opt/dunree/entrypoint.py" ]

HEALTHCHECK --start-period=5s --interval=15s --timeout=5s --retries=3 CMD nc -vz 127.0.0.1 $PORT || exit 1
