#!/usr/bin/env python3
"""Two-Zoraxy integration harness: client -> EXTERNAL -> INTERNAL -> backend app.

  client (127.0.0.55) --http--> EXTERNAL (role external, rule app.test -> INTERNAL, HTTPS to a private CA)
                      --https/mTLS--> INTERNAL (role internal, trusted proxy 127.0.0.1, peer gate on) --http--> app

Everything except the process flags is configured through the admin APIs the GUI uses. Run it through run.sh (it
builds the binary and caps CPU/memory). Each check prints "PASS name" or "FAIL name: reason"; exit status is
non-zero when any check failed or the topology could not be built.

  dual_proxy.py [--mode tls|mtls|both] [--keep]      (--keep leaves the temp dirs for inspection)
"""
import argparse
import contextlib
import json
import os
import shutil
import sys
import tempfile
import traceback
import urllib.error
import urllib.request
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
import lib  # noqa: E402
from lib import Zoraxy, Fail, make_ca, make_leaf, wait_for, http_req  # noqa: E402
from app import App  # noqa: E402

PUBLIC_HOST = "app.test"
CLIENT_IP = "127.0.0.55"   # the "visitor": a distinct loopback address so the chain's client address is recognisable
EXT_ADDR = "127.0.0.1"     # address the INTERNAL proxy sees the EXTERNAL one connect from


def read(p):
    with open(p) as f:
        return f.read()


def upload_cert(z, name, crt, key):
    """POST /api/cert/upload twice (pub, pri) like the certificate page does: multipart, name in 'domain'."""
    for kt, path in (("pub", crt), ("pri", key)):
        b = uuid.uuid4().hex
        body = ("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
                "Content-Type: application/octet-stream\r\n\r\n%s\r\n--%s--\r\n" % (b, os.path.basename(path), read(path), b)).encode()
        req = urllib.request.Request("http://127.0.0.1:%d/api/cert/upload?ktype=%s&domain=%s" % (z.admin, kt, name), data=body,
                                     method="POST", headers={"X-CSRF-Token": z.csrf, "Content-Type": "multipart/form-data; boundary=" + b})
        try:
            z.opener.open(req, timeout=20).read()
        except urllib.error.HTTPError as e:
            raise Fail("cert upload %s/%s: HTTP %d %s" % (name, kt, e.code, e.read()[:200]))


def set_trusted_proxies(z, ips):
    """Replace the trusted proxy list by exactly ips (the GUI's Network > Trusted Proxies)."""
    for p in z.get("/api/trustedproxy/list") or []:
        z.api("/api/trustedproxy/remove", ip=p["IP"])
    for ip in ips:
        z.api("/api/trustedproxy/add", ip=ip, desc="dual-proxy e2e")
    got = sorted(p["IP"] for p in z.get("/api/trustedproxy/list") or [])
    if got != sorted(ips):
        raise Fail("trusted proxy list is %s, wanted %s" % (got, ips))


class DualProxy:
    """The whole topology for one run. mode is 'tls' (CA-verified hop) or 'mtls' (plus client certificates)."""

    def __init__(self, mode):
        self.mode = mode
        self.pki = tempfile.mkdtemp(prefix="zx-dual-pki-")
        self.app = App("backend")
        self.internal = None
        self.external = None

    # ------------------------------------------------------------------ PKI (throwaway private CA)
    def make_pki(self):
        d = self.pki
        self.ca = make_ca(d, "Dual-Proxy E2E Private CA")
        # internal proxy server certificate: verified by the external one against the dialled address and the host name
        self.srv_cert = make_leaf(d, "internal.test", self.ca, san="DNS:internal.test,DNS:%s,IP:127.0.0.1" % PUBLIC_HOST, name="internal")
        # the external proxy's client certificate (mTLS run)
        self.cli_cert = make_leaf(d, "external-proxy", self.ca, san="DNS:external-proxy", name="external-client", client=True)
        # a certificate from a different CA: for later negative checks
        os.makedirs(os.path.join(d, "other"))
        oca = make_ca(os.path.join(d, "other"), "Unrelated CA")
        self.other_srv = make_leaf(os.path.join(d, "other"), "internal.test", oca, san="DNS:internal.test,IP:127.0.0.1", name="otherserver")
        self.other_cli = make_leaf(os.path.join(d, "other"), "intruder", oca, san="DNS:intruder", name="otherclient", client=True)
        self.ca_pem = read(self.ca[0])

    # ------------------------------------------------------------------ build
    def up(self):
        self.make_pki()
        self.app.start()
        self.configure_internal()
        self.configure_external()
        return self

    def configure_internal(self):
        z = self.internal = Zoraxy(tls=True, name="int")
        z.start()
        upload_cert(z, "internal", *self.srv_cert)
        # the access rule the sites use must trust forwarded headers from trusted proxies only (Trusted Proxy Gating)
        z.api("/api/whitelist/trustProxy", enable=True, id="default")
        set_trusted_proxies(z, [EXT_ADDR])
        z.api("/api/deployrole/set", config=json.dumps(dict(role="internal", hardenHeaders=True, peerGate=True, directCIDRs=[])))
        z.add_rule(PUBLIC_HOST, self.app.addr)
        if self.mode == "mtls":
            z.api("/api/proxy/networking/clientcert", ep=PUBLIC_HOST, config=json.dumps(
                dict(Mode="require_and_verify", CAPEM=self.ca_pem)))

    def configure_external(self):
        z = self.external = Zoraxy(tls=False, name="ext")
        z.start()
        set_trusted_proxies(z, [])   # visitors connect directly: no CDN, nothing trusted in front
        z.api("/api/deployrole/set", config=json.dumps(dict(role="external", hardenHeaders=True, peerGate=False, directCIDRs=[])))
        internal_ep = "127.0.0.1:%d" % self.internal.proxy
        z.add_rule(PUBLIC_HOST, internal_ep, tls=True)   # tls=True: the upstream requires HTTPS; tlsval stays False (= verify)
        payload = dict(TLSCABundlePEM=self.ca_pem)
        if self.mode == "mtls":
            upload_cert(z, "ext-client", *self.cli_cert)
            payload["ClientCertName"] = "ext-client"
        z.api("/api/proxy/upstream/update", ep=PUBLIC_HOST, origin=internal_ep, payload=json.dumps(payload), active=True)

    def down(self, keep=False):
        for z in (self.external, self.internal):
            if z:
                if keep:
                    with contextlib.suppress(Exception):
                        os.killpg(os.getpgid(z.proc.pid), 15)
                        z.proc.wait(8)
                    print("kept: %s" % z.dir)
                else:
                    with contextlib.suppress(Exception):
                        z.stop()
        self.app.stop()
        if not keep:
            shutil.rmtree(self.pki, ignore_errors=True)

    # ------------------------------------------------------------------ client
    def get(self, path="/", headers=None, src=CLIENT_IP, host=PUBLIC_HOST, method="GET", body=None):
        """A request from a visitor through the EXTERNAL proxy."""
        return self.external.req(host, path, method=method, headers=headers, body=body, src=src)


# ---------------------------------------------------------------------- checks
CHECKS = []


def check(fn):
    CHECKS.append(fn)
    return fn


@check
def smoke_request_flows_with_real_client_address(t):
    """client -> external -> internal -> backend answers, and the backend sees the visitor's real address in
    X-Forwarded-For / Forwarded as set by the chain (not the external proxy's 127.0.0.1)."""
    r = t.get("/hello?x=1")
    if r.status != 200:
        raise Fail("status %d via external: %s" % (r.status, r.body[:200]))
    j = r.json()
    if j.get("app") != "backend" or j.get("path") != "/hello?x=1":
        raise Fail("not answered by the backend app for this path: %s" % j)
    h = j["headers"]
    if h.get("host") != PUBLIC_HOST:
        raise Fail("backend saw Host %r, wanted %r" % (h.get("host"), PUBLIC_HOST))
    xff = [p.strip() for p in h.get("x-forwarded-for", "").split(",") if p.strip()]
    fwd = h.get("forwarded", "")
    seen = "XFF=%r Forwarded=%r X-Real-Ip=%r" % (h.get("x-forwarded-for"), fwd, h.get("x-real-ip"))
    if not xff or xff[0] != CLIENT_IP:
        raise Fail("visitor %s is not the first X-Forwarded-For entry; backend saw %s" % (CLIENT_IP, seen))
    if "for=%s" % CLIENT_IP not in fwd.replace('"', "") and fwd:
        raise Fail("Forwarded header does not name the visitor %s; backend saw %s" % (CLIENT_IP, seen))
    if h.get("x-real-ip") not in (None, CLIENT_IP):
        raise Fail("X-Real-Ip names %r, not the visitor; backend saw %s" % (h.get("x-real-ip"), seen))
    if any(p == EXT_ADDR for p in xff[:1]):
        raise Fail("the external proxy's own address leads X-Forwarded-For; backend saw %s" % seen)
    # the hop really is the verified (m)TLS one: the internal proxy only listens for HTTPS here
    if t.mode == "mtls":
        subj = h.get("x-client-cert-subject", "")
        if "external-proxy" not in subj:
            raise Fail("mTLS run but the backend got no client certificate identity from the internal proxy (%s)" % list(h))
    print("  info: backend saw %s%s" % (seen, " client-cert-subject=%r" % h.get("x-client-cert-subject") if t.mode == "mtls" else ""))


def run_mode(mode, keep):
    print("== mode: %s ==" % mode, flush=True)
    t = DualProxy(mode)
    failed = 0
    try:
        t.up()
        print("  topology: client(%s) -> external http :%d -> internal https :%d -> backend :%d" % (
            CLIENT_IP, t.external.proxy, t.internal.proxy, t.app.port))
        for fn in CHECKS:
            name = "%s/%s" % (mode, fn.__name__)
            try:
                fn(t)
                print("PASS " + name, flush=True)
            except Fail as e:
                failed += 1
                print("FAIL %s: %s" % (name, e), flush=True)
            except Exception as e:
                failed += 1
                print("FAIL %s: %s: %s" % (name, type(e).__name__, e), flush=True)
                traceback.print_exc()
    except Exception as e:
        failed += 1
        print("FAIL %s/setup: %s: %s" % (mode, type(e).__name__, e), flush=True)
        traceback.print_exc()
        for z, n in ((t.external, "external"), (t.internal, "internal")):
            if z:
                print("--- %s log tail ---\n%s" % (n, z.logtail(2500)))
    finally:
        t.down(keep)
    return failed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["tls", "mtls", "both"], default="both")
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()
    if not os.path.exists(lib.BIN):
        print("FAIL setup: zoraxy binary %s missing (use run.sh)" % lib.BIN)
        return 2
    failed = 0
    for m in (["tls", "mtls"] if a.mode == "both" else [a.mode]):
        failed += run_mode(m, a.keep)
    print("RESULT %s (%d failed)" % ("FAIL" if failed else "PASS", failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
