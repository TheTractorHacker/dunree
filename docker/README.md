# Dunree Docker

The image name is a variable: Dunree has no default registry yet, and the image of the Zoraxy project is a different <!-- rebrand:keep -->
product. Build the image yourself (see **Building** below, or `packaging/container/Dockerfile` for the multi-architecture
image) and put its name in `DUNREE_IMAGE` (Compose) or in place of `<your-dunree-image>` (Docker run).

Coming from a container of the Zoraxy image: stop it and mount the same two folders. The Dunree image also answers on <!-- rebrand:keep -->
the old paths `/opt/zoraxy/config/` and `/opt/zoraxy/plugin/` (they are links to `/opt/dunree`), so an existing
compose file only needs its `image:` line changed. <!-- rebrand:keep -->

## Usage

If you are attempting to access your service from outside your network, make sure to forward ports 80 and 443 to the Dunree host to allow web traffic. If you know how to do this, great! If not, find the manufacturer of your router and search on how to do that. There are too many to be listed here. Read more about it from [whatismyip](https://www.whatismyip.com/port-forwarding/).

In the examples below, make sure to update `/path/to/dunree/config/`. If a path is not provided, an anonymous Docker volume will be created instead to prevent data loss, but it is recommended to store the data at a defined host location or a named Docker volume.

Once setup, access the webui at `http://<host-ip>:8000` to configure Dunree. Change the port in the URL if you changed the management port.

### Docker Run

```
docker run -d \
  --name dunree \
  --restart unless-stopped \
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
| `/opt/dunree/config/` | Dunree configuration. |
| `/opt/dunree/plugin/` | Dunree plugins. |

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

Variables are the same as the start parameters of the program (`dunree -h` lists them).

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
| `MDNSNAME` | `''` (String) | mDNS name, leave empty to use the default (`zoraxy_{node-uuid}.local`, the name existing installs are known by). |
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
> Contrary to the Dunree README, Docker usage of the port flag should NOT include the colon. Ex: `-e PORT="8000"` for Docker run and `PORT: "8000"` for Docker compose.

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

### Plugins

Dunree includes a (experimental) store to download and use official plugins right from inside Dunree, no preparation required.
For those looking to use custom plugins, build your plugins and place them inside the volume `/path/to/dunree/plugin/:/opt/dunree/plugin/` (Adjust to your actual install location).

### Building

To build the Docker image:
  - Check out the repository/branch.
  - Copy the Dunree `src/` directory into the `docker/` (here) directory.
  - Run the build command with `docker build -t dunree_build .`
  - You can now use the image `dunree_build`
    - If you wish to change the image tag name, then modify `dunree_build` in the previous step and then build again.

