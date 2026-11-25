# NetBird (self-hosted) behind the proxy: gRPC paths with h2c

Answers Zoraxy issue #1029 (issue #201 of the fork that became Dunree): "400/404 on some of the virtual directory endpoints". <!-- rebrand:keep -->

**Status.** The proxy side below is covered by automated tests with a fake gRPC-style backend (plain HTTP/2 only,
bidirectional stream, trailers) next to a plain HTTP backend on the same host. It has **not been run against a real
NetBird installation**; that check stays with the owner of the installation. The NetBird container names, ports and
paths are taken from NetBird's own reverse-proxy documentation and differ between NetBird versions: compare them
with your `docker-compose.yml` before you type them in.

## Why it failed

NetBird serves several things on one host name:

* a web dashboard and a REST API (ordinary HTTP),
* two **gRPC** services, Signal and Management, which the NetBird clients call under fixed paths,
* depending on the version, WebSocket endpoints (relay, WebSocket fallback of the two gRPC services).

The gRPC services in the containers listen **without TLS**, and gRPC needs HTTP/2. HTTP/2 without TLS is called
**h2c**. A proxy that forwards these paths as HTTP/1.1 gets `400`, `404` or a broken stream back. Dunree has an
h2c switch per upstream (for a host that is gRPC only) and, for a mixed host like NetBird, **per path route**
(virtual directory). Both are off by default.

## What to create

One proxy rule for the NetBird host name with TLS on the listener (the clients speak HTTP/2 to the proxy only over
TLS), then the path routes below under **Sites > Path routes > Add path route**. The h2c tick box is in
**Advanced settings** of the form: **HTTP/2 without TLS (h2c)**.

A path route replaces its prefix by the path of the target. A gRPC server needs the full method path
(`/management.ManagementService/Login`), so for the two gRPC rows **repeat the prefix in the target address**.
The same goes for `/api`.

| Path prefix | Target address | TLS to target | h2c | What it is |
|---|---|---|---|---|
| (the proxy rule itself) | `dashboard:80` | off | off | Web dashboard |
| `/signalexchange.SignalExchange/` | `signal:80/signalexchange.SignalExchange/` | off | **on** | Signal, gRPC |
| `/management.ManagementService/` | `management:80/management.ManagementService/` | off | **on** | Management, gRPC |
| `/api/` | `management:80/api/` | off | off | Management REST API |
| `/relay` | `relay:80/relay` | off | off | Relay, WebSocket (versions with the relay service) |
| `/ws-proxy/signal` | `signal:80/ws-proxy/signal` | off | off | Signal over WebSocket (newer versions) |
| `/ws-proxy/management` | `management:80/ws-proxy/management` | off | off | Management over WebSocket (newer versions) |

Notes on the table:

* `dashboard`, `signal`, `management`, `relay` and port `80` are placeholders for the container names and the
  ports **inside** your compose network. Older set-ups publish Signal on `10000` and Management on `33073` (or
  `443` inside the container); a version that ships one combined server container uses the same address in every
  row. If the proxy does not run in the same Docker network, use the host address and the published ports.
* If your identity provider (Zitadel, Keycloak, Authentik, ...) lives under the same host name, its paths need their
  own path routes, as plain HTTP (h2c off) unless its documentation says otherwise.
* STUN/TURN (coturn, UDP 3478 and its relay port range) is not HTTP and does not go through path routes. Publish
  those ports directly or use **Sites > Stream Proxy**.
* WebSocket paths need no switch, an `Upgrade: websocket` request is detected by itself. On an h2c path route an
  upgrade request is still sent as HTTP/1.1, because HTTP/2 has no upgrade.

The same through the API (one call per row, `h2c` is `false` when left out):

```
POST /api/proxy/vdir/add
type=host&endpoint=netbird.example.com&path=/management.ManagementService/&domain=management:80/management.ManagementService/&reqTLS=false&skipValid=false&h2c=true
```

## Settings of the host rule that matter

Path routes take their limits and protection from the host rule they belong to.

* **Request timeout** (site editor, limits): leave it at `0`. The gRPC streams of the NetBird clients stay open for
  hours; a timeout cuts them and the clients reconnect in a loop.
* **Largest request body**: leave it at `0` (a stream has no known length).
* Do not put a login in front of the whole host (SSO / forward auth, basic auth, CAPTCHA, bot check): the NetBird
  clients are not browsers and cannot answer it. NetBird authenticates its own API and gRPC calls.
* A WAF or rate limit on the host also sees the gRPC requests. If clients are refused, check the blocked list
  first and make an exception for the two gRPC prefixes.

## Check it

From a machine that reaches the proxy (replace the host name):

```
curl -sS --http2 -o /dev/null -D - -X POST \
  -H 'content-type: application/grpc' -H 'te: trailers' \
  https://netbird.example.com/management.ManagementService/GetServerKey
```

* `HTTP/2 200` with `content-type: application/grpc` (a `grpc-status` line may follow): the request reached the
  gRPC server as HTTP/2. The path route works.
* `404` with the error page of the proxy: the host name in the target address does not resolve. Check the
  container name (it differs between NetBird versions) and that the proxy is in the same Docker network. The
  proxy log has the lookup error as `Upstream ... failed for request to ...`.
* `521` with the error page of the proxy: the target is not reachable (wrong address or port, service down), or a
  gRPC-only target closed the connection on an HTTP/1.1 request because h2c is not ticked on that path route.
  The reason is in the proxy log as `Upstream ... failed for request to ...`.
* `400`, `505`, a `404` that is not the error page of the proxy, or a `200` with an HTML or text body: the request
  reached a server that is not speaking gRPC over HTTP/2 there. Usual causes: h2c not ticked on that path route,
  the prefix not repeated in the target address, or the row points at the dashboard instead of the Signal /
  Management container.

Then `netbird up --management-url https://netbird.example.com` on a client and `netbird status -d`: Management and
Signal must both show `Connected`.

## Known limits

* Not verified against a real NetBird server or client (see Status). The table is a starting point, the NetBird
  documentation for your version is the reference for names, ports and paths.
* h2c is "prior knowledge" HTTP/2: every request of that path route except upgrade requests goes out as HTTP/2.
  A target that only speaks HTTP/1.1 answers with an error, so tick it only for gRPC paths.
* h2c cannot be combined with TLS to the target; the form disables the box and the API refuses the combination.
  A target with TLS negotiates HTTP/2 by itself. A path route that was stored with h2c and is later switched to TLS
  ignores the flag.
* The host rule option "Force HTTP/1.1 for upstream connections" does not apply to an h2c path route.
* The uptime monitor probes with HTTP/1.1, which a gRPC target refuses. A path route with h2c is therefore left
  out of the uptime monitor (it would always show as down); the host itself and its other path routes are still
  monitored.
* A path route has one target: no load balancing, no health check and no PROXY protocol for it. For several gRPC
  backends use a host rule of its own with upstreams that have h2c ticked.
* The bulk action that adds or removes a forward-auth path route on many hosts never touches a path route that has
  h2c on (it is reported as a conflict).
* gRPC-Web from browsers is a different protocol (HTTP/1.1 or HTTP/2 with its own content type) and needs no h2c
  unless the backend only listens with plain HTTP/2.
