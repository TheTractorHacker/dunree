# Dunree in a container

Dunree is a reverse proxy and web gateway, published by Foley IT under AGPL-3.0 and based on Zoraxy v3.3.6 by tobychui
and imuslab (see `NOTICE`).

**There is no published Dunree image.** No registry is set up, so every file here takes the image name from you:
`DUNREE_IMAGE` in the compose files, `<your-dunree-image>` in the commands below. Build the image first (see
[Building](#building)); this page calls the result `dunree:local`.
The image of the Zoraxy project on Docker Hub is a different product and is never a default here. <!-- rebrand:keep -->

| File | What it is |
|---|---|
| `Dockerfile` | the image for one architecture, built from this folder |
| `../packaging/container/Dockerfile` | the same image for several architectures (what a release would publish), built from the repository root |
| `docker-compose.yml` | Dunree alone; the image is `DUNREE_IMAGE` |
| `docker-compose.socket-proxy.yml` | optional addition: a read-only Docker socket proxy for the container picker |
| `docker-compose-test.yaml`, `flake.nix` | a test container (`test-dunree`) for people who work on the image |
| `entrypoint.py`, `test_entrypoint.py` | turns the environment variables into start parameters; its test |

Coming from a container of the Zoraxy image: stop it and mount the same two folders. The Dunree image also answers on <!-- rebrand:keep -->
the old paths `/opt/zoraxy/config/` and `/opt/zoraxy/plugin/` (they are links to `/opt/dunree`), so an existing
compose file only needs its `image:` line changed. The first Dunree start keeps a copy of the configuration before it <!-- rebrand:keep -->
writes anything; see [Migrating from Zoraxy](../docs/migrating-from-zoraxy.md#docker). <!-- rebrand:keep -->

## Usage

If you are attempting to access your service from outside your network, make sure to forward ports 80 and 443 to the Dunree host to allow web traffic. If you know how to do this, great! If not, find the manufacturer of your router and search on how to do that. There are too many to be listed here. Read more about it from [whatismyip](https://www.whatismyip.com/port-forwarding/).

In the examples below, make sure to update `/path/to/dunree/config/`. If a path is not provided, an anonymous Docker volume will be created instead to prevent data loss, but it is recommended to store the data at a defined host location or a named Docker volume.

Once set up, open the admin interface at `http://<host-ip>:8000` to configure Dunree. Change the port in the URL if you changed the management port. The examples publish port 8000 on every address of the host, as the image always did; `127.0.0.1:8000:8000` publishes it on the host only (`packaging/container/compose.yaml` does that).

### Docker Run

```
docker run -d \
  --name dunree \
  --restart unless-stopped \
  --stop-timeout 30 \
  --add-host=host.docker.internal:host-gateway \
  -p 80:80 \
  -p 443:443 \
  -p 443:443/udp \
  -p 8000:8000 \
  -v /path/to/dunree/config/:/opt/dunree/config/ \
  -v /path/to/dunree/plugin/:/opt/dunree/plugin/ \
  -e FASTGEOIP="true" \
  -e TZ="America/New_York" \
  <your-dunree-image>
```

### Docker Compose

```yml
services:
  dunree:
    image: ${DUNREE_IMAGE:?set DUNREE_IMAGE}
    container_name: dunree
    restart: unless-stopped
    stop_grace_period: 30s
    ports:
      - 80:80
      - 443:443
      - 443:443/udp
      - 8000:8000
    volumes:
      - /path/to/dunree/config/:/opt/dunree/config/
      - /path/to/dunree/plugin/:/opt/dunree/plugin/
    extra_hosts:
      - "host.docker.internal:host-gateway"
    environment:
      FASTGEOIP: "true"
      TZ: "America/New_York"
```

### Ports

| Port | Details |
|:-|:-|
| `80` | HTTP traffic. |
| `443` | HTTPS traffic. |
| `443/udp` | HTTP/3 (QUIC). Only needed if HTTP/3 is enabled in Global Settings. |
| `8000` | Management interface. Can be changed with the `PORT` env. |

### Volumes

| Volume | Details |
|:-|:-|
| `/opt/dunree/config/` | Everything Dunree keeps: `conf/`, `sys.db`, `sys.uuid`, logs, the static web root. Declared as a volume in the image. |
| `/opt/dunree/plugin/` | Installed plugins (add-ons). |

`/opt/zoraxy/config/` and `/opt/zoraxy/plugin/` are the same folders under their older names (links inside the image).

### Health check, stopping, labels

* **Health check.** The image reports healthy when the admin port (`PORT`) accepts a TCP connection: checked every
  15 s, unhealthy after three failures. It is a TCP check so that it works with and without `-webui_tls`. It does not
  prove that ports 80 and 443 are bound; for a load balancer or an outside monitor use `GET /.dunree/health` on a
  proxy port (the older path `/.zoraxy/health` answers the same way).
* **Stopping.** Dunree needs up to 28 s to stop cleanly (requests are drained, statistics saved). Docker waits 10 s
  by default and then kills the container: give it 30 s (`stop_grace_period: 30s`, `--stop-timeout 30`).
* **Labels.** The image carries `ie.foleyit.dunree.container-identifier="Dunree"` and, unchanged from the image it
  replaces, `com.imuslab.zoraxy.container-identifier="Zoraxy"`. The container picker of the admin interface
  recognises Dunree's own container by the second one, so do not remove or change it. The image also has the usual
  `org.opencontainers.image.*` labels (title, vendor, licence) and `ie.foleyit.dunree.based-on` (the attribution).
* **Licence files** are in the image under `/usr/share/doc/dunree/`.

### Docker socket

The Docker socket is **not** mounted by default. Dunree only uses the Docker API to list containers and networks for the "Docker containers" picker when adding a proxy rule; everything else works without it.

> [!WARNING]
> Mounting `/var/run/docker.sock` into the Dunree container gives anything running in that container (Dunree itself, any installed plugin, or anyone who takes over the management interface) full control of the Docker daemon, which is equivalent to root on the host. `:ro` on the mount does not change this, it only protects the socket file, not the API behind it.

Recommended (opt-in): run a read-only socket proxy next to Dunree with the shipped override file. It only forwards `GET` requests for containers and networks.

```
docker compose -f docker-compose.yml -f docker-compose.socket-proxy.yml up -d
```

Legacy (not recommended): to restore the previous behaviour, add the mount back yourself with `-v /var/run/docker.sock:/var/run/docker.sock` (Docker run) or `- /var/run/docker.sock:/var/run/docker.sock` under `volumes:` (Compose).

### Extra Hosts
| Host | Details |
|:-|:-|
| `host.docker.internal:host-gateway` | Resolves host.docker.internal to the host’s gateway IP on the Docker bridge network, allowing containers to access services running on the host machine. |

### Environment

`entrypoint.py` turns these variables into the start parameters of the same name (`dunree -h` lists every parameter; a parameter without a variable here cannot be set through the environment).

| Variable | Default | Details |
|:-|:-|:-|
| `AUTORENEW` | `86400` (Integer) | ACME auto TLS/SSL certificate renew check interval. |
| `CFGUPGRADE` | `true` (Boolean) | Enable auto config upgrade if breaking change is detected. |
| `DB` | `auto` (String) | Database backend to use (leveldb, boltdb, auto) Note that fsdb will be used on unsupported platforms like RISCV (default "auto"). |
| `DOCKER` | `true` (Boolean) | Run Dunree in docker compatibility mode. |
| `EARLYRENEW` | `30` (Integer) | Number of days to early renew a soon expiring certificate. |
| `ENABLELOG` | `true` (Boolean) | Enable system wide logging, set to false for writing log to STDOUT only. |
| `FASTGEOIP` | `false`  (Boolean) | Enable high speed geoip lookup, requires 1GB extra memory (Not recommend for low end devices). |
| `MDNS` | `true` (Boolean) | Enable mDNS scanner and transponder. |
| `MDNSNAME` | `''` (String) | mDNS name, leave empty to use the default (`dunree_{node-uuid}.local`; `zoraxy_{node-uuid}.local`, the name existing installs are known by, is announced as well while *Also send legacy Zoraxy names* is on). | <!-- rebrand:keep -->
| `NOAUTH` | `false` (Boolean) | Disable authentication for management interface. |
| `PLUGIN` | `/opt/dunree/plugin/` (String) | Set the path for Dunree plugins. Only change this if you know what you are doing. |
| `PORT` | `8000` (Integer) | Management web interface listening port |
| `SSHLB` | `false` (Boolean) | Allow loopback web ssh connection (DANGER). |
| `TZ` | `Etc/UTC` (String) | Define timezone using [standard tzdata values](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones). |
| `UPDATE_GEOIP` | `false` (Boolean) | Download the latest GeoIP data and exit. |
| `VERSION` | `false` (Boolean) | Show version of this server. |
| `WEBROOT` | `./www` (String) | Static web server root folder. Only allow change in start parameters. |
| `ZEROTIER` | `false` (Boolean) | Enable ZeroTier functionality for GAN. |

> [!IMPORTANT]
> Unlike the `-port` start parameter (`-port=:8000`), the `PORT` variable is the number only, without the colon: `-e PORT="8000"` for Docker run and `PORT: "8000"` for Docker Compose.

### ZeroTier

If you are running with ZeroTier, make sure to add the following flags to ensure ZeroTier functionality:
  
`--cap_add NET_ADMIN` and `--device /dev/net/tun:/dev/net/tun`
`--environment ZEROTIER="true"`

Or for Docker Compose:
```
  cap_add:
    - NET_ADMIN
  devices:
    - /dev/net/tun:/dev/net/tun
  environment:
    ZEROTIER: "true"
```

### Plugins and add-ons

Dunree ships **without an add-on store** and contacts none until an administrator adds a source under
*System > Add-ons* (`docs/plugins/addon-store.md`). Installed plugins live in the plugin volume
(`/path/to/dunree/plugin/:/opt/dunree/plugin/`); to use a plugin you built yourself, put its folder there.
A *Local folder* source is read inside the container, so it has to be mounted too. Plugins must be built for
Linux and for the architecture of the image.

The in-app updater is switched off in a container: update by building the image again and recreating the
container (`docs/guides/updating.md`, section C).

## Building

One architecture, from this folder:

```
cp -r ../src ./src
docker build -t dunree:local .
rm -rf ./src
```

Several architectures, from the repository root (the Go program is cross-compiled on the build machine, so the extra
architectures need no emulation; ZeroTier is compiled under emulation and is slow, `--build-arg WITH_ZEROTIER=false`
leaves it out):

```
docker buildx build -f packaging/container/Dockerfile --platform linux/amd64,linux/arm64 -t dunree:local .
```

A multi-architecture result cannot be loaded into the local image store of the classic Docker engine: build one
platform with `--load`, or push to a registry with `--push -t <registry>/dunree:<version>`. `linux/arm/v7`,
`linux/arm/v6`, `linux/386` and `linux/riscv64` build the same way where the base images exist for them. The
workflow `.github/workflows/docker.yml` builds this file and pushes only when the repository variable
`DOCKER_IMAGE` and registry credentials are set; none are, so nothing is published.

Then run it: `DUNREE_IMAGE=dunree:local docker compose up -d` (after putting your folders in `docker-compose.yml`).

## Tests

```
python3 docker/test_entrypoint.py     # both layouts of the image, old and new
python3 tools/docs/test_docs.py       # this folder: image name is a variable, labels, paths, health check, no socket mount
packaging/test.sh                     # the multi-architecture Dockerfile and its compose files
```

## Known limits

* No image was built or run for this page: the machine it was written on has no Docker. The files are checked as
  text and YAML only.
* No published image, no registry, no signed image, no vulnerability scan of a built image.
* The health check only looks at the admin port.
* ZeroTier is compiled from a pinned old version (1.10.6) because newer ones do not build with this recipe.
