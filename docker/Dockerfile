# Dunree container image, single architecture, built from this folder:
#
#   cp -r ../src ./src && docker build -t dunree:local . ; rm -rf ./src
#
# The multi-architecture image (linux/amd64, linux/arm64, ...; what a release would publish) is
# packaging/container/Dockerfile, built from the repository root. Both have the same layout,
# environment variables, ports, labels and health check. See README.md in this folder.

## Build Dunree
FROM docker.io/golang:alpine AS build-dunree
RUN mkdir -p /opt/dunree/source/ &&\
    mkdir -p /usr/local/bin/

# If you build it yourself, you will need to add the src directory into the docker directory.
COPY ./src/ /opt/dunree/source/

WORKDIR /opt/dunree/source/

RUN go mod tidy &&\
    go build -o /usr/local/bin/dunree &&\
    chmod 755 /usr/local/bin/dunree


## Build ZeroTier
FROM docker.io/rust:1.79-alpine AS build-zerotier
RUN apk add --update --no-cache curl make gcc g++ linux-headers openssl-dev nano

RUN mkdir -p /opt/zerotier/source/ &&\
    mkdir -p /usr/local/bin/

WORKDIR /opt/zerotier/source/

# Version is pinned because newer versions don't work for whatever reason
RUN curl -Lo ZeroTierOne.tar.gz https://codeload.github.com/zerotier/ZeroTierOne/tar.gz/refs/tags/1.10.6 &&\
    tar -xzvf ZeroTierOne.tar.gz &&\
    cd ZeroTierOne-*/zeroidc &&\
    cargo update -p getrandom &&\
    cd .. &&\
    make -f make-linux.mk &&\
    mv ./zerotier-one /usr/local/bin/zerotier-one &&\
    chmod 755 /usr/local/bin/zerotier-one


## Main
FROM docker.io/alpine:latest
RUN apk add --update --no-cache tzdata python3 netcat-openbsd libressl-dev ca-certificates libc6-compat libstdc++ &&\
    rm -rf /sbin/apk /var/cache/apk/* /tmp/* # Simple cleanup

COPY --chmod=700 ./entrypoint.py /opt/dunree/

COPY --from=build-zerotier /usr/local/bin/zerotier-one /usr/local/bin/zerotier-one
COPY --from=build-dunree /usr/local/bin/dunree /usr/local/bin/dunree
# Licence, attribution and the notices of bundled components (the same files the About page serves).
COPY --from=build-dunree /opt/dunree/source/web/legal/ /usr/share/doc/dunree/

# Old names keep working: compose files and volumes of existing containers use /opt/zoraxy/... and "zoraxy".
RUN mkdir -p /opt/dunree/config/ /opt/dunree/plugin/ &&\
    ln -s /opt/dunree /opt/zoraxy &&\
    ln -s dunree /usr/local/bin/zoraxy &&\
    echo "tun" | tee -a /etc/modules # For ZeroTier

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
      ie.foleyit.dunree.container-identifier="Dunree" \
      ie.foleyit.dunree.based-on="Zoraxy v3.3.6 by tobychui and imuslab (AGPL-3.0); independent derivative, not endorsed by them"
# Kept, with its value: the container picker of the admin interface (and of older builds that look
# at this container from outside) recognises the proxy's own container by this label.
LABEL com.imuslab.zoraxy.container-identifier="Zoraxy"

EXPOSE 80 443 443/udp 8000

ENTRYPOINT [ "python3", "-u", "/opt/dunree/entrypoint.py" ]

# Healthy = the admin port accepts a TCP connection. It is a TCP check on purpose: it works with and
# without -webui_tls and needs no credentials. It does not prove that the proxy ports are bound.
HEALTHCHECK --start-period=5s --interval=15s --timeout=5s --retries=3 CMD nc -vz 127.0.0.1 $PORT || exit 1

