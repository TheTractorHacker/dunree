#!/usr/bin/env python3
"""Enterprise dual-proxy checks (docs/enterprise-dual-proxy-plan.md Phase 5) on top of the dual_proxy.py topology.

  client -> EXTERNAL (http) -> INTERNAL (https, private CA, peer gate) -> backend app

Run through run.sh:  run.sh enterprise [--only 3,7] [--keep]
Each check prints PASS / FAIL / NOT RUN with evidence lines ("  evidence: ..."). Exit status is non-zero when any check
failed. Groups: shared (one tls topology, state restored by every check), mtls (own topology), and one fresh topology
per destructive check (backend/internal restarts, drain, config import, history restore).
"""
import argparse
import contextlib
import io
import json
import os
import re
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
import lib  # noqa: E402
from lib import Fail, Skip, wait_for, http_req, free_port, openssl  # noqa: E402
import dual_proxy as dp  # noqa: E402
from dual_proxy import DualProxy, PUBLIC_HOST, CLIENT_IP, EXT_ADDR, upload_cert, set_trusted_proxies, read  # noqa: E402
from fakelapi import FakeLAPI  # noqa: E402
import ws  # noqa: E402

SPOOF = "6.6.6.6"
SPOOF_HEADERS = {
    "X-Forwarded-For": SPOOF, "Forwarded": "for=%s;proto=https" % SPOOF, "X-Real-IP": SPOOF, "CF-Connecting-IP": SPOOF,
    "True-Client-IP": SPOOF, "X-Client-Cert-Verified": "SUCCESS", "X-Client-Cert-Subject": "CN=admin-spoof",
}
EVIDENCE = []


def ev(msg):
    EVIDENCE.append(msg)


def need(cond, msg):
    if not cond:
        raise Fail(msg)


def safe(fn, *a, **kw):
    """Run a request, returning the Resp or an Exception instance (connection refused, reset, TLS failure, timeout)."""
    try:
        return fn(*a, **kw)
    except Exception as e:  # noqa: BLE001
        return e


def desc(r):
    return ("HTTP %d %r" % (r.status, r.body[:90])) if hasattr(r, "status") else "%s: %s" % (type(r).__name__, str(r)[:100])


def internal_ep(t):
    return "127.0.0.1:%d" % t.internal.proxy


def direct_internal(t, path="/", headers=None, src="127.0.0.1", method="GET", body=None, cert=None, timeout=15):
    """A request straight to the INTERNAL proxy's https port (bypassing the external one)."""
    return http_req("127.0.0.1", t.internal.proxy, PUBLIC_HOST, path, method, headers, body, timeout, tls=True, src=src, cert=cert)


def good_upstream(t):
    p = dict(TLSCABundlePEM=t.ca_pem, TLSPinsSHA256=[], SkipCertValidations=False, ClientCertName="")
    if t.mode == "mtls":
        p["ClientCertName"] = "ext-client"
    return p


def set_upstream(t, **payload):
    t.external.api("/api/proxy/upstream/update", ep=PUBLIC_HOST, origin=internal_ep(t), payload=json.dumps(payload), active=True)


def restore_upstream(t):
    set_upstream(t, **good_upstream(t))


def spki_pin(crt):
    pub = subprocess.run(["openssl", "x509", "-in", crt, "-pubkey", "-noout"], check=True, capture_output=True).stdout
    der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "der"], input=pub, check=True, capture_output=True).stdout
    out = subprocess.run(["openssl", "dgst", "-sha256", "-hex"], input=der, check=True, capture_output=True).stdout.decode()
    return out.strip().split()[-1]


def set_rule(z, host=PUBLIC_HOST, **kw):
    z.edit_rule(host, **kw)


def audit(z, limit=300):
    return (z.get("/api/security/audit/list", limit=limit) or {}).get("entries") or []


def started_count(z):
    return z.logtail(10 ** 7).count("Zoraxy started")


def restart_wait(z, started_before, timeout=45):
    """After a self re-exec (history restore) wait until the new process logged its start, then for the admin API and the proxy"""
    wait_for(lambda: started_count(z) > started_before, timeout, 0.3, "the re-executed process to start")
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            urllib.request.urlopen("http://127.0.0.1:%d/" % z.admin, timeout=1).read()
            z._session()
            wait_for(lambda: z.logtail(10 ** 7).count("Dynamic Reverse Proxy service started") >= 2, 20, 0.3, "proxy service")
            z.wait_proxy()
            return
        except Exception:
            time.sleep(0.4)
    raise Fail("zoraxy did not come back after restart:\n" + z.logtail())


# ====================================================================== 1 spoofing

def c1a_spoof_via_external(t):
    """1a: forged identity headers sent to the EXTERNAL do not change the client address the backend sees"""
    for label, hdrs in (("all forged headers", dict(SPOOF_HEADERS)),
                        ("XFF chain ending in the real client", {"X-Forwarded-For": "%s, %s" % (SPOOF, CLIENT_IP)}),
                        ("Forwarded only", {"Forwarded": "for=%s" % SPOOF})):
        n0 = len(t.app.log)
        r = t.get("/spoof-ext", headers=hdrs)
        need(r.status == 200, "%s: status %s" % (label, desc(r)))
        need(len(t.app.log) == n0 + 1, "%s: backend did not log exactly one request" % label)
        h = t.app.log[-1]["headers"]
        joined = " | ".join("%s=%s" % kv for kv in h.items())
        need(SPOOF not in joined, "%s: forged address %s reached the backend: %s" % (label, SPOOF, joined))
        need("admin-spoof" not in joined, "%s: forged client-cert subject reached the backend" % label)
        xff = [p.strip() for p in h.get("x-forwarded-for", "").split(",") if p.strip()]
        need(xff and xff[0] == CLIENT_IP, "%s: first X-Forwarded-For is %r, wanted the real client %s" % (label, xff[:1], CLIENT_IP))
        need("cf-connecting-ip" not in h and "true-client-ip" not in h, "%s: CDN header survived: %s" % (label, joined))
        need(h.get("x-client-cert-verified") != "SUCCESS", "%s: forged X-Client-Cert-Verified survived" % label)
        need(h.get("x-real-ip") in (None, CLIENT_IP), "%s: X-Real-Ip is %r" % (label, h.get("x-real-ip")))
        ev("%s: backend saw XFF=%r Forwarded=%r X-Real-Ip=%r (client %s)" % (label, h.get("x-forwarded-for"), h.get("forwarded"), h.get("x-real-ip"), CLIENT_IP))


def c1b_spoof_direct_internal(t):
    """1b: the same headers straight to the INTERNAL from a non-trusted address (127.0.0.2) are refused by the peer gate"""
    before = t.internal.get("/api/deployrole/get")
    n0 = len(t.app.log)
    r = direct_internal(t, "/spoof-int", headers=SPOOF_HEADERS, src="127.0.0.2")
    need(r.status == 403, "expected 403 from the peer gate, got %s" % desc(r))
    need(len(t.app.log) == n0, "the refused request reached the backend: %s" % t.app.log[-1])
    after = t.internal.get("/api/deployrole/get")
    need(after.get("gateRejected", 0) > before.get("gateRejected", 0), "peer gate counter did not move: %s -> %s" % (before.get("gateRejected"), after.get("gateRejected")))
    ev("127.0.0.2 -> internal with forged headers: HTTP 403, backend log unchanged (%d), gateRejected %s -> %s" % (n0, before.get("gateRejected"), after.get("gateRejected")))
    # control: the same address without any forged header is refused too (the gate looks at the peer, not at headers)
    r2 = direct_internal(t, "/plain", src="127.0.0.2")
    need(r2.status == 403, "plain request from 127.0.0.2 got %s" % desc(r2))
    # control: the trusted peer (the external proxy's address) is let in
    r3 = direct_internal(t, "/trusted-peer", src="127.0.0.1")
    need(r3.status == 200, "trusted peer 127.0.0.1 got %s" % desc(r3))
    ev("controls: 127.0.0.2 plain -> 403; trusted peer 127.0.0.1 -> 200")


# ====================================================================== 2 rate limit identity

def burst(t, src, n, path="/rl"):
    out = []
    for _ in range(n):
        out.append(t.get(path, src=src).status)
    return out


def counters(t):
    """Per client allowed/denied counters of the INTERNAL rule from the Status > Tune sampler"""
    j = t.internal.get("/api/stats/livetune")
    return j


def c2_rate_limit_identity(t):
    """2: the INTERNAL rule's rate limit counts per real client; dry-run first, then enforce"""
    try:
        time.sleep(1.2)
        set_rule(t.internal, rate=True, ratenum=1, rateburst=3, ratedry=True)
        # dry run: nobody is limited, even far beyond the budget
        # the Status > Tune sampler has no baseline for a client it sees for the first time, so the traffic goes on for 14 s (5 req/s)
        a = []
        t_end = time.time() + 14
        while time.time() < t_end:
            a.append(t.get("/rl", src="127.0.0.2").status)
            time.sleep(0.2)
        need(set(a) == {200}, "dry-run must never block: %s" % sorted(set(a)))
        ev("dry-run, client 127.0.0.2 %d requests at ~5/s over 14 s (limit 1/s burst 3): all HTTP 200" % len(a))
        def tuned():
            for r in counters(t).get("rules") or []:
                if r.get("domain") == PUBLIC_HOST and r.get("limiter", {}).get("denied", 0) > 0:
                    return r["limiter"]
        lim = wait_for(tuned, 20, 1, "the dry-run denials to appear in Status > Tune (5 s sampler)")
        need(lim.get("dryRun") is True, "tune limiter view: %s" % lim)
        ev("dry-run counted in Status > Tune: %s" % json.dumps(lim))
        d = t.internal.detail(PUBLIC_HOST)
        need(d.get("RateLimitDryRun") is True and d.get("RequireRateLimit") is True, "rule did not store dry-run: %r" % {k: d.get(k) for k in ("RequireRateLimit", "RateLimit", "RateLimitDryRun")})
        # enforce
        time.sleep(3.5)
        set_rule(t.internal, rate=True, ratenum=1, rateburst=3, ratedry=False)
        a = burst(t, "127.0.0.2", 10)
        need(a[:3] == [200, 200, 200] and 429 in a, "enforce: client .2 should get its 3 burst tokens then 429: %s" % a)
        ev("enforce, client 127.0.0.2 x10: %s" % a)
        b = burst(t, "127.0.0.1", 3)
        need(b == [200, 200, 200], "client 127.0.0.1 must have its own bucket and not be blocked by .2's excess: %s" % b)
        ev("immediately after, client 127.0.0.1 x3: %s (own bucket)" % b)
        c = burst(t, CLIENT_IP, 3)
        need(c == [200, 200, 200], "client %s must have its own bucket: %s" % (CLIENT_IP, c))
        ev("client %s x3: %s" % (CLIENT_IP, c))
        # the exceeding client is still limited while the others are not, and 127.0.0.1 can be exceeded independently
        a2 = burst(t, "127.0.0.2", 2)
        need(429 in a2, "client .2 is still over its limit: %s" % a2)
        b2 = burst(t, "127.0.0.1", 6)
        need(429 in b2, "client 127.0.0.1 exceeding its own budget must be limited: %s" % b2)
        time.sleep(1.2)
        c2 = burst(t, CLIENT_IP, 1)
        need(c2 == [200], "client %s was refused although it stayed inside its own budget: %s" % (CLIENT_IP, c2))
        ev("exceeding as .1 (%s) does not affect %s (%s) or the other way round" % (b2, CLIENT_IP, c2))
        # forged X-Forwarded-For rotation by a client of the external does not escape the limit
        time.sleep(3.5)
        rot = [t.get("/rl-rot", src="127.0.0.2", headers={"X-Forwarded-For": "10.9.%d.%d" % (i, i)}).status for i in range(8)]
        need(429 in rot, "rotating a forged X-Forwarded-For escaped the limit: %s" % rot)
        ev("rotating forged X-Forwarded-For from .2 x8: %s" % rot)
    finally:
        with contextlib.suppress(Exception):
            set_rule(t.internal, rate=False, ratedry=False)


# ====================================================================== 3 TLS trust between the proxies

def logged_since(z, mark, pattern):
    """lines appended to the instance's log after the byte offset mark that match the regex"""
    z.log.flush()
    with open(os.path.join(z.dir, "zoraxy.log"), "rb") as f:
        f.seek(mark)
        txt = f.read().decode("utf8", "replace")
    return [l for l in txt.splitlines() if re.search(pattern, l, re.I)]


def logmark(z):
    z.log.flush()
    return os.path.getsize(os.path.join(z.dir, "zoraxy.log"))


def expect_closed(t, label, why_pattern=r"x509|certificate|tls|unknown authority|pin|handshake|bad certificate", status=(502, 521)):
    """the request through the external must fail closed: error status, backend never reached, reason logged on the external"""
    n0 = len(t.app.log)
    m = logmark(t.external)
    r = t.get("/tls-" + label.split()[0])
    need(hasattr(r, "status") and r.status in status, "%s: wanted HTTP %s, got %s" % (label, status, desc(r)))
    need(len(t.app.log) == n0, "%s: the request reached the backend (silent success)" % label)
    time.sleep(0.4)
    lines = logged_since(t.external, m, why_pattern)
    note = ""
    if not lines:
        # the upstream failure log is limited to one line per upstream and reason every 30 s (docs/guides/error-pages-and-521.md)
        recent = [l for l in logged_since(t.external, 0, r"\[proxy\].*Upstream .* failed for request") if time.time() - time.mktime(time.strptime(l[1:20], "%Y-%m-%d %H:%M:%S")) < 32]
        lines = [l for l in recent if re.search(why_pattern, l, re.I)]
        note = " (same reason already logged <30 s ago: the documented once-per-30 s limit)"
    ev("%s: HTTP %d, backend not reached; external log%s: %s" % (label, r.status, note, (lines[-1][:230] if lines else "NO MATCHING LOG LINE")))
    need(lines, "%s: no logged reason matching /%s/ in the external's log:\n%s" % (label, why_pattern, t.external.logtail(800)))
    return r, lines


def c3a_tls_private_ca_ok(t):
    """3a: external->internal over the private CA succeeds (CA bundle verification, https upstream)"""
    restore_upstream(t)
    n0 = len(t.app.log)
    r = t.get("/tls-ok")
    need(r.status == 200 and len(t.app.log) == n0 + 1, "expected 200 through both hops: %s" % desc(r))
    d = t.external.detail(PUBLIC_HOST)
    up = d["ActiveOrigins"][0]
    need(up["RequireTLS"] and not up["SkipCertValidations"] and up["TLSCABundlePEM"], "upstream is not a verified https one: %r" % {k: up.get(k) for k in ("RequireTLS", "SkipCertValidations")})
    ev("HTTP 200 over https with CA-bundle verification (skip-verify off), backend answered")


def c3b_wrong_ca_fails_closed(t):
    """3b: wrong CA bundle -> 502 and a logged reason, nothing reaches the backend"""
    try:
        need(t.get("/warm").status == 200, "warm-up request failed")  # a pooled keep-alive connection must not survive a trust change
        other = read(os.path.join(t.pki, "other", "ca.crt"))
        set_upstream(t, TLSCABundlePEM=other)
        expect_closed(t, "3b wrong-CA-bundle", r"x509|unknown authority")
        set_upstream(t, TLSCABundlePEM=other, SkipCertValidations=True)
        expect_closed(t, "3b wrong-CA-bundle-plus-skip-verify (no fallback to skip)", r"x509|unknown authority")
    finally:
        restore_upstream(t)
    need(t.get("/after-wrongca").status == 200, "did not recover after restoring the CA")


def c3c_pin_mismatch_fails(t):
    """3c: a pin mismatch fails; the right pin works (positive control)"""
    try:
        t.get("/warm")
        good = spki_pin(t.srv_cert[0])
        set_upstream(t, TLSPinsSHA256=["00" * 32])
        expect_closed(t, "3c pin-mismatch", r"pinned")
        set_upstream(t, TLSPinsSHA256=[good])
        r = t.get("/pin-ok")
        need(r.status == 200, "the matching pin %s was refused: %s" % (good[:12], desc(r)))
        ev("control: matching SPKI pin %s... + CA bundle -> HTTP 200" % good[:12])
    finally:
        restore_upstream(t)


def c3d_no_ca_no_skip_fails(t):
    """3d: skip-verify off and no CA/pin (system roots only) fails; only an explicit skip-verify lets the private CA through"""
    try:
        t.get("/warm")
        set_upstream(t, TLSCABundlePEM="", TLSPinsSHA256=[], SkipCertValidations=False)
        expect_closed(t, "3d no-CA-no-skip", r"x509|unknown authority")
        set_upstream(t, TLSCABundlePEM="", TLSPinsSHA256=[], SkipCertValidations=True)
        r = t.get("/skip-explicit")
        need(r.status == 200, "explicit skip-verify (control) should connect: %s" % desc(r))
        ev("control: only with SkipCertValidations explicitly on does the unverified hop connect (HTTP 200)")
    finally:
        restore_upstream(t)
    need(t.get("/after-3d").status == 200, "did not recover after restoring trust settings")


# ====================================================================== 4 mutual TLS between the proxies

def c4a_mtls_with_cert_ok(t):
    """4a: with the external's client certificate the internal accepts and tells the backend who called"""
    restore_upstream(t)
    n0 = len(t.app.log)
    r = t.get("/mtls-ok")
    need(r.status == 200 and len(t.app.log) == n0 + 1, "expected 200: %s" % desc(r))
    subj = t.app.log[-1]["headers"].get("x-client-cert-subject", "")
    need("external-proxy" in subj, "backend got no client certificate identity (headers: %s)" % list(t.app.log[-1]["headers"]))
    ev("HTTP 200; internal verified the client certificate, backend saw x-client-cert-subject=%r" % subj)


def c4b_mtls_without_cert_rejected(t):
    """4b: external WITHOUT a client certificate: the internal rejects (via the external and when connecting directly)"""
    try:
        t.get("/warm")
        set_upstream(t, ClientCertName="")
        expect_closed(t, "4b external-without-client-cert", r"certificate|tls|handshake|remote error|reset by peer|EOF")
        il = logged_since(t.internal, 0, r"handshake error|client didn.t provide")
        ev("internal log: %s" % (il[-1][:200] if il else "(no handshake line)"))
    finally:
        restore_upstream(t)
    # direct to the internal (trusted peer address, so the peer gate is not what refuses): no certificate offered
    n0 = len(t.app.log)
    r = safe(direct_internal, t, "/direct-nocert", src="127.0.0.1")
    need(not hasattr(r, "status"), "direct request without a client certificate was answered: %s" % desc(r))
    need(len(t.app.log) == n0, "backend reached without a client certificate")
    ev("direct to internal without client certificate: %s" % desc(r))
    r = safe(direct_internal, t, "/direct-good", src="127.0.0.1", cert=(t.cli_cert[0], t.cli_cert[1]))
    need(hasattr(r, "status") and r.status == 200, "direct request with the right client certificate failed: %s" % desc(r))
    ev("direct to internal with the right client certificate: HTTP 200")


def c4c_mtls_other_ca_rejected(t):
    """4c: a client certificate issued by another CA is rejected (via the external and directly)"""
    upload_cert(t.external, "ext-other", *t.other_cli)
    try:
        t.get("/warm")
        set_upstream(t, ClientCertName="ext-other")
        expect_closed(t, "4c external-with-other-CA-client-cert", r"certificate|tls|handshake|remote error")
    finally:
        restore_upstream(t)
    n0 = len(t.app.log)
    r = safe(direct_internal, t, "/direct-othercert", src="127.0.0.1", cert=(t.other_cli[0], t.other_cli[1]))
    need(not hasattr(r, "status"), "a certificate from another CA was accepted by the internal proxy: %s" % desc(r))
    need(len(t.app.log) == n0, "backend reached with a foreign certificate")
    ev("direct to internal with a client certificate from another CA: %s" % desc(r))
    need(t.get("/after-4c").status == 200, "did not recover after restoring the right certificate")


# ====================================================================== 5 route limits and websockets

def clear_limits(t):
    for z in (t.external, t.internal):
        with contextlib.suppress(Exception):
            set_rule(z, maxRequestBodyBytes=0, requestTimeout=0)


def c5a_max_body_413(t):
    """5a: max request body returns 413 (Content-Length and chunked), the backend is not reached; set on the internal and on the external"""
    try:
        for where, z in (("internal rule (answer passes through the external)", t.internal), ("external rule", t.external)):
            clear_limits(t)
            set_rule(z, maxRequestBodyBytes=100)
            n0 = len(t.app.log)
            r = t.get("/up", method="POST", body=b"x" * 500, headers={"Content-Type": "application/octet-stream"})
            need(r.status == 413, "%s: 500 byte body wanted 413, got %s" % (where, desc(r)))
            need(len(t.app.log) == n0, "%s: oversized body reached the backend" % where)
            r2 = t.get("/up", method="POST", body=b"y" * 50, headers={"Content-Type": "application/octet-stream"})
            need(r2.status == 200 and t.app.log[-1]["body"] == b"y" * 50, "%s: 50 byte body wanted 200 with the body intact, got %s" % (where, desc(r2)))
            n1 = len(t.app.log)
            r3 = safe(lib.http_req, "127.0.0.1", t.external.proxy, PUBLIC_HOST, "/up-chunked", "POST", {"Content-Type": "application/octet-stream"}, b"z" * 500, 15, False, None, True, CLIENT_IP)
            ok3 = hasattr(r3, "status") and r3.status == 413
            ev("%s: 500 B Content-Length -> HTTP 413 (backend untouched); 50 B -> HTTP 200; 500 B chunked -> %s; backend requests logged for the chunked one: %d" % (where, desc(r3), len(t.app.log) - n1))
            need(ok3, "%s: oversized chunked body wanted 413, got %s" % (where, desc(r3)))
    finally:
        clear_limits(t)


def c5b_request_timeout(t):
    """5b: the per-route request timeout answers with the timeout status (504) instead of waiting for the backend"""
    try:
        for where, z in (("internal rule", t.internal), ("external rule", t.external)):
            clear_limits(t)
            set_rule(z, requestTimeout=2)
            t0 = time.time()
            r = t.get("/slow?ms=6000")
            dt = time.time() - t0
            need(r.status == 504, "%s: slow backend wanted 504, got %s after %.1f s" % (where, desc(r), dt))
            need(dt < 4.5, "%s: 504 came after %.1f s, the 2 s budget was not enforced" % (where, dt))
            r2 = t.get("/slow?ms=300")
            need(r2.status == 200, "%s: a fast request under the budget wanted 200, got %s" % (where, desc(r2)))
            ev("%s requestTimeout=2 s: /slow?ms=6000 -> HTTP 504 after %.1f s; /slow?ms=300 -> HTTP 200" % (where, dt))
    finally:
        clear_limits(t)


def host_overwrite(z, hostname):
    z.api("/api/proxy/header/handleHostOverwrite", domain=PUBLIC_HOST, hostname=hostname)


def c5d_websocket_ip_upstream_without_host_overwrite(t):
    """5d: a websocket through an IP-addressed https upstream with a CA bundle and NO host overwrite (as the HTTP path allows)"""
    restore_upstream(t)
    host_overwrite(t.external, "")
    try:
        r = t.get("/http-control")
        need(r.status == 200, "control: plain HTTP over the same upstream must work: %s" % desc(r))
        m = logmark(t.external)
        s, st, h = ws.ws_connect(t.external.proxy, PUBLIC_HOST, "/ws")
        s.close()
        lines = logged_since(t.external, m, r"websocket")
    finally:
        host_overwrite(t.external, PUBLIC_HOST)
    ev("HTTP over the upstream: 200; websocket upgrade: %s; external log: %s" % (st, lines[-1][:260] if lines else "-"))
    need(" 101 " in st, "KNOWN DEFECT (reported, not fixed): the websocket dial to an IP-addressed https upstream sends no SNI, the internal "
         "proxy then presents its default certificate and verification fails (HTTP over the same upstream works because dpcore derives the SNI "
         "from the request host). Got %s. Workaround: set the rule's host overwrite (Header rewrite) to the public name, or address the internal proxy by DNS name" % st)


def c5c_websocket_both_hops(t):
    """5c: a websocket works through both hops (wss to the internal over the private CA), also with route limits set"""
    try:
        set_rule(t.internal, maxRequestBodyBytes=100, requestTimeout=2)
        set_rule(t.external, maxRequestBodyBytes=100, requestTimeout=2)
        n0 = len(t.app.ws_requests)
        s, st, h = ws.ws_connect(t.external.proxy, PUBLIC_HOST, "/ws")
        try:
            need(" 101 " in st, "websocket upgrade through both hops failed: %s %s" % (st, h))
            ws.write_frame(s, 1, b"hello", mask=True)
            op, data = ws.read_message(s)
            need((op, data) == (1, b"echo:hello"), "echo mismatch: %r %r" % (op, data))
            time.sleep(3.2)  # longer than the 2 s request timeout: an upgraded tunnel must not be cut by it
            big = b"b" * 3000  # larger than the 100 byte body limit: frames are not a request body
            ws.write_frame(s, 1, big, mask=True)
            op, data = ws.read_message(s)
            need(op == 1 and data == b"echo:" + big, "echo after the timeout / big frame failed (%r, %d bytes)" % (op, len(data)))
            ws.write_frame(s, 8, b"", mask=True)
        finally:
            s.close()
        need(len(t.app.ws_requests) == n0 + 1, "backend did not see exactly one upgrade request")
        hh = t.app.ws_requests[-1]
        ev("upgrade 101 through external -> internal (https) -> backend; echo ok before and after 3.2 s (> 2 s request timeout) and with a 3000 B frame (> 100 B body limit); backend saw x-forwarded-for=%r" % hh.get("x-forwarded-for"))
        need((hh.get("x-forwarded-for") or "").split(",")[0].strip() in ("127.0.0.1", CLIENT_IP), "backend websocket request lacks the real client address: %r" % hh.get("x-forwarded-for"))
    finally:
        clear_limits(t)


# ====================================================================== 6 CrowdSec on the external proxy

CS_BANNED, CS_BANNED2, CS_CLEAN = "203.0.113.77", "203.0.113.78", "198.51.100.5"
CDN_ADDR = "127.0.0.99"   # stands in for a CDN / front proxy: a trusted peer on the external, so the visitor address can be sent in X-Forwarded-For


def cs_hit(t, ip):
    return t.get("/cs", src=CDN_ADDR, headers={"X-Forwarded-For": ip} if ip else None)


def cs_status(t):
    return t.external.get("/api/crowdsec/status")


def blocked_reasons(t, ip):
    items = t.external.get("/api/blocked/list", limit=100).get("items") or []
    return [i for i in items if i.get("ip") == ip]


def c6_crowdsec(t):
    """6: CrowdSec on the EXTERNAL: log only (counted, nothing blocked), enforce (403 + blocked log), decision deleted, LAPI killed (fail-open, then fail-closed)"""
    key = "lapi-key-" + uuid.uuid4().hex
    lapi = FakeLAPI(free_port(), key)
    z = t.external
    gate_before = None
    try:
        set_trusted_proxies(z, [CDN_ADDR])
        z.api("/api/whitelist/trustProxy", enable=True, id="default")
        lapi.ban(1, CS_BANNED)
        lapi.ban(2, CS_BANNED2)
        need(cs_hit(t, CS_BANNED).status == 200, "CrowdSec is off: a visitor must be served")
        need(not lapi.calls, "CrowdSec off must not contact the LAPI")

        def conf(mode, **kw):
            c = dict(enabled=True, lapiUrl=lapi.url, mode=mode, pollSeconds=5, graceSeconds=10)
            c.update(kw)
            return c
        z.api("/api/crowdsec/set", config=json.dumps(conf("log")), apikey=key)
        st = wait_for(lambda: (lambda x: x if x.get("state") == "ok" and x.get("cacheSize", 0) >= 2 else None)(cs_status(t)), 40, 0.5, "status ok with 2 decisions")
        ev("log only: status=%s cache=%d mode=%s keySet=%s" % (st["state"], st["cacheSize"], st["mode"], st["keySet"]))
        # log only: nothing is blocked, the match is counted
        before = cs_status(t)
        r = cs_hit(t, CS_BANNED)
        need(r.status == 200, "log only must never block, got %s" % desc(r))
        after = cs_status(t)
        need(after["logOnly"] == before["logOnly"] + 1 and after["enforced"] == before["enforced"], "match not counted as log only: %s -> %s" % ({k: before[k] for k in ("logOnly", "enforced")}, {k: after[k] for k in ("logOnly", "enforced")}))
        ev("log only: banned %s served (HTTP 200), logOnly %d -> %d, enforced still %d" % (CS_BANNED, before["logOnly"], after["logOnly"], after["enforced"]))
        # enforce
        z.api("/api/crowdsec/set", config=json.dumps(conf("enforce")))
        wait_for(lambda: z.get("/api/crowdsec/get").get("mode") == "enforce", 8, 0.3, "enforce stored")
        n0 = len(t.app.log)
        r = cs_hit(t, CS_BANNED)
        need(r.status == 403, "enforce: banned address wanted 403, got %s" % desc(r))
        need(len(t.app.log) == n0, "blocked request reached the backend")
        need(key not in r.text, "the 403 page contains the API key")
        need(cs_hit(t, CS_CLEAN).status == 200, "enforce: a clean address must be served")
        need(t.get("/cs-loop").status == 200, "enforce: a loopback peer without forwarded address must never be refused")
        need(cs_hit(t, "%s, %s" % (CS_CLEAN, CS_BANNED)).status == 403, "a banned address anywhere in X-Forwarded-For must be refused")
        br = wait_for(lambda: blocked_reasons(t, CS_BANNED), 10, 0.5, "the blocked-request log to list the ban")
        need(any("crowdsec" in (b.get("reason") or "").lower() for b in br), "blocked log reasons: %s" % [b.get("reason") for b in br])
        ev("enforce: banned %s -> HTTP 403 (backend untouched), clean %s -> 200, loopback peer -> 200; blocked log reason=%r, enforced=%d" % (CS_BANNED, CS_CLEAN, br[0].get("reason"), cs_status(t)["enforced"]))
        # decision deleted at the LAPI
        lapi.unban(1)
        wait_for(lambda: cs_hit(t, CS_BANNED).status == 200, 30, 1, "the deleted decision to unblock the address")
        need(cs_hit(t, CS_BANNED2).status == 403, "the other decision must still block")
        ev("decision 1 deleted at the LAPI: %s served again (HTTP 200) within one poll; %s still HTTP 403" % (CS_BANNED, CS_BANNED2))
        # LAPI dies: fail open
        lapi.stop()
        first = wait_for(lambda: cs_status(t).get("state") in ("degraded", "down") and cs_status(t)["state"], 45, 1, "status to leave ok after the LAPI was killed")
        need(cs_hit(t, CS_CLEAN).status == 200 and t.get("/cs-loop").status == 200, "fail-open: visitors without a decision must still be served")
        need(cs_hit(t, CS_BANNED2).status == 403, "cached decisions must keep applying while the LAPI is down")
        s = wait_for(lambda: (lambda x: x if x.get("state") == "down" else None)(cs_status(t)), 60, 1, "status down after the grace period")
        need(not s.get("failClosedActive"), "fail-closed is off but active")
        need(cs_hit(t, CS_CLEAN).status == 200, "fail-open after the grace period: still served")
        need(s.get("lastError") and key not in json.dumps(s), "status must show an error and never the key: %r" % s.get("lastError"))
        ev("LAPI killed: state ok -> %s -> down (lastError=%r), fail-open serves clean visitors (200), cached ban still 403, warnings=%s" % (first, s.get("lastError")[:80], s.get("warnings")))
        # fail-closed needs an explicit, confirmed switch
        code, body = z.api("/api/crowdsec/set", raw=True, config=json.dumps(conf("enforce", failClosed=True)))
        err = json.loads(body) if body[:1] in (b"{", b"[") else body
        need(isinstance(err, dict) and err.get("error"), "fail-closed was enabled without the confirmation: %s" % body[:120])
        ev("fail-closed without confirmation refused: %s" % err["error"][:120])
        z.api("/api/crowdsec/set", config=json.dumps(conf("enforce", failClosed=True)), confirmfailclosed=True)
        wait_for(lambda: cs_status(t).get("failClosedActive"), 30, 1, "fail-closed to become active (LAPI already down beyond the grace period)")
        r = cs_hit(t, CS_CLEAN)
        need(r.status == 403, "fail-closed after the grace period must block, got %s" % desc(r))
        r2 = t.get("/cs-loop")
        s2 = cs_status(t)
        ev("fail-closed confirmed: clean visitor %s -> HTTP %d, loopback peer -> HTTP %d, failClosedBlocks=%d" % (CS_CLEAN, r.status, r2.status, s2.get("failClosedBlocks", -1)))
        need(s2.get("failClosedBlocks", 0) >= 1, "block not counted: %s" % s2)
        # the LAPI comes back: recovers by itself
        lapi2 = FakeLAPI(lapi.port, key)
        lapi2.ban(2, CS_BANNED2)
        lapi.stop()
        lapi = lapi2
        wait_for(lambda: cs_hit(t, CS_CLEAN).status == 200, 150, 2, "recovery once the LAPI is back (backoff up to 2 min)")
        ev("LAPI back: clean visitor served again, state=%s" % cs_status(t).get("state"))
    finally:
        with contextlib.suppress(Exception):
            z.api("/api/crowdsec/set", config=json.dumps(dict(enabled=False, lapiUrl="", mode="log")), clearkey=True)
        with contextlib.suppress(Exception):
            z.api("/api/whitelist/trustProxy", enable=False, id="default")
        with contextlib.suppress(Exception):
            set_trusted_proxies(z, [])
        lapi.stop()


# ====================================================================== 9 admin exposure

def admin_get(z, path, src):
    return http_req("127.0.0.1", z.admin, "127.0.0.1:%d" % z.admin, path, "GET", None, None, 10, src=src)


def find_check(obj, cid):
    if isinstance(obj, dict):
        if obj.get("id") == cid and "status" in obj:
            return obj
        for v in obj.values():
            r = find_check(v, cid)
            if r:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = find_check(v, cid)
            if r:
                return r
    return None


def c9_admin_exposure(t):
    """9: admin allow-list (client inside the CIDR works, outside is refused); admin listener as a proxy target is refused and flagged; admin API unreachable through the public proxy port"""
    z = t.external
    try:
        r = admin_get(z, "/api/adminallow/get", CLIENT_IP)
        need(r.status == 200, "control: admin API before the allow-list from %s: %s" % (CLIENT_IP, desc(r)))
        # lock-out protection
        code, body = z.api("/api/adminallow/set", raw=True, config=json.dumps(dict(cidrs=["10.0.0.0/8"])))
        need(b"error" in body and b"10.0.0.0" not in b"", "a list without the caller's address must be refused: %s" % body[:120])
        ev("lock-out protection: allow-list 10.0.0.0/8 saved from 127.0.0.1 -> refused (%s)" % body.decode()[:120].strip())
        z.api("/api/adminallow/set", config=json.dumps(dict(cidrs=["127.0.0.0/30"])))
        g = z.get("/api/adminallow/get")
        need(g.get("active") and g.get("cidrs") == ["127.0.0.0/30"], "allow-list not active: %s" % g)
        r1 = admin_get(z, "/api/adminallow/get", "127.0.0.1")
        r2 = admin_get(z, "/api/adminallow/get", "127.0.0.2")
        need(r1.status == 200 and r2.status == 200, "clients inside 127.0.0.0/30 must reach the admin API: %s / %s" % (desc(r1), desc(r2)))
        d0 = z.get("/api/adminallow/get")["denied"]
        r3 = admin_get(z, "/api/adminallow/get", CLIENT_IP)
        need(r3.status in (401, 403, 404) and "cidrs" not in r3.text, "client %s outside the CIDR must be refused, got %s" % (CLIENT_IP, desc(r3)))
        d1 = z.get("/api/adminallow/get")["denied"]
        need(d1 > d0, "denied counter did not move (%s -> %s)" % (d0, d1))
        ev("allow-list 127.0.0.0/30: admin API from 127.0.0.1 and 127.0.0.2 -> HTTP 200; from %s -> HTTP %d (denied %d -> %d)" % (CLIENT_IP, r3.status, d0, d1))
        # the admin listener as a proxy rule target
        z.add_rule("admin.test", "127.0.0.1:%d" % z.admin)
        r = t.get("/api/adminallow/get", host="admin.test")
        need(not (r.status == 200 and '"cidrs"' in r.text), "the admin API was reachable through a proxy rule while the allow-list is on: %s" % desc(r))
        ev("rule admin.test -> 127.0.0.1:%d (admin listener), allow-list on: GET /api/adminallow/get through the proxy -> HTTP %d %r" % (z.admin, r.status, r.body[:70]))
        ll = logged_since(z, 0, r"admin|refus")
        ev("external log: %s" % (ll[-1][:240] if ll else "(no admin/refus line)"))
        post = find_check(z.get("/api/security/posture"), "admin.rule_target")
        need(post is not None, "posture has no admin.rule_target check")
        need(post.get("status") == "warn", "posture admin.rule_target status %r, wanted warn: %s" % (post.get("status"), json.dumps(post)[:300]))
        ev("posture admin.rule_target: %s" % json.dumps(post)[:260])
        # public proxy port never serves the admin API
        for host in ("127.0.0.1:%d" % z.proxy, "localhost", "127.0.0.1", "%s" % PUBLIC_HOST, "zoraxy.local"):
            r = http_req("127.0.0.1", z.proxy, host, "/api/adminallow/get", "GET", None, None, 10, src=CLIENT_IP)
            need('"cidrs"' not in r.text and '"yourAddr"' not in r.text, "admin JSON served through the public port with Host %s: %s" % (host, desc(r)))
            r = http_req("127.0.0.1", z.proxy, host, "/index.html", "GET", None, None, 10, src=CLIENT_IP)
            need("zoraxy.csrf.Token" not in r.text, "the admin UI was served through the public port with Host %s" % host)
        ev("public proxy port :%d with Host in (127.0.0.1:port, localhost, 127.0.0.1, %s, zoraxy.local): no admin API JSON and no admin UI page" % (z.proxy, PUBLIC_HOST))
    finally:
        with contextlib.suppress(Exception):
            z.del_rule("admin.test")
        with contextlib.suppress(Exception):
            z.api("/api/adminallow/set", config=json.dumps(dict(cidrs=[])))


# ====================================================================== 7 failure and recovery

def upstream_state(z, origin):
    return (z.get("/api/proxy/upstream/list", ep=PUBLIC_HOST).get("States") or {}).get(origin) or {}


def enable_health(z, interval=2):
    cfg = z.get("/api/proxy/upstream/lb/get", ep=PUBLIC_HOST)
    cfg.pop("Algorithms", None)
    cfg["ActiveHealthCheck"].update(Enabled=True, IntervalSeconds=interval, TimeoutSeconds=2, Rise=1, Fall=2)
    z.api("/api/proxy/upstream/lb/set", ep=PUBLIC_HOST, payload=json.dumps(cfg))


def poll_until_ok(fn, timeout, step=0.5):
    t0 = time.time()
    last = None
    while time.time() - t0 < timeout:
        last = safe(fn)
        if hasattr(last, "status") and last.status == 200:
            return time.time() - t0, last
        time.sleep(step)
    raise Fail("no recovery within %d s, last answer: %s" % (timeout, desc(last)))


def c7a_backend_down_and_back(t):
    """7a: backend stopped: internal answers an error and logs the upstream failure, health shows down; backend restarted: traffic recovers without restarting either proxy"""
    pids = (t.internal.proc.pid, t.external.proc.pid)
    need(t.get("/before").status == 200, "baseline request failed")
    backend = t.app.addr
    ev("health defaults (no active or passive check configured): %s" % json.dumps({k: upstream_state(t.internal, backend).get(k) for k in ("State", "ConsecutiveFailures", "ActiveHealthy")}))
    enable_health(t.internal)
    wait_for(lambda: upstream_state(t.internal, backend).get("LastCheck", 0) > 0, 15, 0.5, "the first active health probe")
    need(upstream_state(t.internal, backend).get("State") == "healthy", "backend should be healthy before the stop")
    m = logmark(t.internal)
    t.app.stop()
    t_stop = time.time()
    statuses = []
    for _ in range(3):
        statuses.append(t.get("/during").status)
    di = safe(direct_internal, t, "/during-direct")
    need(all(s != 200 for s in statuses) and hasattr(di, "status") and di.status != 200, "traffic must fail while the backend is down: ext %s internal %s" % (statuses, desc(di)))
    need(all(s in (502, 503, 504, 521) for s in statuses) and di.status in (502, 503, 504, 521), "unexpected error statuses: ext %s internal %s" % (statuses, di.status))
    time.sleep(0.5)
    lines = logged_since(t.internal, m, r"Upstream .* failed for request to .*refused")
    need(lines, "internal did not log the upstream failure:\n" + t.internal.logtail(600))
    ev("backend stopped: via external HTTP %s, direct on internal HTTP %d; internal log: %s" % (statuses, di.status, lines[-1][:220]))
    st = wait_for(lambda: (lambda x: x if x.get("State") not in ("healthy", None) else None)(upstream_state(t.internal, backend)), 20, 0.5, "the upstream state to leave healthy (active probe, Fall=2, 2 s)")
    ev("internal upstream health after %.1f s: %s" % (time.time() - t_stop, json.dumps({k: st.get(k) for k in ("State", "ActiveHealthy", "LastCheckError", "ConsecutiveFailures")})))
    need(st.get("ActiveHealthy") is False or "down" in str(st.get("State")).lower() or "unhealthy" in str(st.get("State")).lower(), "health does not show down: %s" % st)
    # restart
    t.app.start()
    t_up = time.time()
    dt, r = poll_until_ok(lambda: t.get("/recovered"), 45)
    ev("backend restarted: external answers HTTP 200 again %.1f s later, no proxy restarted (PIDs %s unchanged, alive)" % (dt, pids))
    need(t.internal.proc.poll() is None and t.external.proc.poll() is None and pids == (t.internal.proc.pid, t.external.proc.pid), "a proxy process died")
    need(t.app.log[-1]["path"] == "/recovered", "recovery answer did not come from the backend")
    h = wait_for(lambda: (lambda x: x if x.get("State") == "healthy" else None)(upstream_state(t.internal, backend)), 20, 0.5, "health back to healthy")
    ev("internal upstream health back to %s %.1f s after the backend came back" % (h.get("State"), time.time() - t_up))


def c7b_internal_down_and_back(t):
    """7b: INTERNAL stopped: the EXTERNAL answers an error page (status noted) and logs why, health down; INTERNAL restarted: recovers without restarting the external"""
    z, i = t.external, t.internal
    need(t.get("/before-int").status == 200, "baseline request failed")
    enable_health(z)
    ep = internal_ep(t)
    wait_for(lambda: upstream_state(z, ep).get("LastCheck", 0) > 0, 15, 0.5, "the first active probe of the external")
    need(upstream_state(z, ep).get("State") == "healthy", "internal should be healthy for the external before the stop: %s" % upstream_state(z, ep))
    ext_pid = z.proc.pid
    m = logmark(z)
    os.kill(i.proc.pid, signal.SIGTERM)
    t0 = time.time()
    try:
        i.proc.wait(20)
    except Exception:
        raise Fail("the internal did not exit on SIGTERM within 20 s")
    ev("internal stopped (SIGTERM, exit %s after %.1f s)" % (i.proc.returncode, time.time() - t0))
    statuses = [t.get("/int-down").status for _ in range(3)]
    need(all(s in (502, 503, 504, 521) for s in statuses), "external must answer an error status while the internal is down, got %s" % statuses)
    time.sleep(0.5)
    lines = logged_since(z, m, r"Upstream .* failed for request to .*(refused|reset|EOF)")
    need(lines, "external did not log the upstream failure:\n" + z.logtail(600))
    r = t.get("/int-down")
    ev("external answers HTTP %s with its error page (%d bytes, 'Web server is down' style); external log: %s" % (statuses, len(r.body), lines[-1][:220]))
    st = wait_for(lambda: (lambda x: x if x.get("State") not in ("healthy", None) else None)(upstream_state(z, ep)), 20, 0.5, "the external to mark the internal unhealthy")
    ev("external's health of the internal upstream: %s" % json.dumps({k: st.get(k) for k in ("State", "ActiveHealthy", "LastCheckError", "ConsecutiveFailures")}))
    need(st.get("ActiveHealthy") is False or "healthy" not in str(st.get("State")), "health does not show down: %s" % st)
    i.start()
    t1 = time.time()
    dt, r = poll_until_ok(lambda: t.get("/int-back"), 60)
    need(z.proc.pid == ext_pid and z.proc.poll() is None, "the external restarted or died")
    ev("internal restarted (restart itself %.1f s): external answers HTTP 200 %.1f s after the internal listener was up again; external PID %d unchanged" % (t1 - t0, dt, ext_pid))
    h = wait_for(lambda: (lambda x: x if x.get("State") == "healthy" else None)(upstream_state(z, ep)), 20, 0.5, "health back to healthy")
    ev("external's health: %s again" % h.get("State"))


def c7c_active_health_probe_ip_upstream_without_host_overwrite(t):
    """7c: the external's active health probe of an IP-addressed https internal proxy with a CA bundle and NO host overwrite"""
    z = t.external
    ep = internal_ep(t)
    host_overwrite(z, "")
    try:
        need(t.get("/hc-control").status == 200, "control: plain HTTP over the upstream must work")
        enable_health(z)
        wait_for(lambda: upstream_state(z, ep).get("LastCheck", 0) > 0, 15, 0.5, "the first active probe")
        time.sleep(7)
        st = upstream_state(z, ep)
        ev("after 7 s of probing every 2 s (Fall=2) while real requests succeed: %s" % json.dumps({k: st.get(k) for k in ("State", "ActiveHealthy", "LastCheckError")}))
        need(st.get("State") == "healthy", "KNOWN DEFECT (reported, not fixed): the active health probe sends no SNI to the IP-addressed https upstream, the internal proxy "
             "answers with its default certificate and the probe fails verification, so a healthy internal proxy is shown unhealthy (%s). Workaround: host overwrite "
             "on the rule, or address the internal proxy by DNS name" % st.get("LastCheckError"))
    finally:
        host_overwrite(z, PUBLIC_HOST)


# ====================================================================== 8 graceful drain

def slow_request_thread(t, ms, box, timeout):
    def run():
        t0 = time.time()
        box["r"] = safe(
            lib.http_req, "127.0.0.1", t.external.proxy, PUBLIC_HOST, "/slow?ms=%d" % ms, "GET", None, None, timeout, False, None, False, CLIENT_IP)
        box["dt"] = time.time() - t0
    th = threading.Thread(target=run, daemon=True)
    th.start()
    return th


def c8a_drain_completes_in_flight(t):
    """8a: SIGTERM to the EXTERNAL (exact PID) while a 5 s request is in flight: the response completes, the process exits within the drain bound"""
    z = t.external
    pid = z.proc.pid
    box = {}
    th = slow_request_thread(t, 5000, box, 25)
    wait_for(lambda: any(l["path"].startswith("/slow") for l in t.app.log), 10, 0.1, "the slow request to reach the backend")
    time.sleep(0.8)
    t_sig = time.time()
    os.kill(pid, signal.SIGTERM)
    time.sleep(0.5)
    refused = safe(lambda: socket.create_connection(("127.0.0.1", z.proxy), 1).close())
    try:
        z.proc.wait(30)
    except Exception:
        raise Fail("the external did not exit within 30 s of SIGTERM")
    t_exit = time.time() - t_sig
    th.join(10)
    r = box.get("r")
    need(hasattr(r, "status") and r.status == 200 and b'"/slow?ms=5000"' in r.body, "the in-flight response did not complete: %s" % desc(r))
    need(t_exit <= 16, "exit took %.1f s, longer than the drain (8 s default) + shutdown steps (8 s budget)" % t_exit)
    need(z.proc.returncode == 0, "exit status %s" % z.proc.returncode)
    lines = logged_since(z, 0, r"drain|shutdown|stopping|in-flight|finish")
    ev("SIGTERM pid %d with a 5 s request in flight: HTTP 200 delivered after %.1f s, process exited %.1f s after the signal (status %s); new connection while draining: %s" % (pid, box["dt"], t_exit, z.proc.returncode, "refused" if isinstance(refused, Exception) else "accepted"))
    ev("shutdown log lines: %s" % " | ".join(l[28:150] for l in lines[-4:]))


def c8b_second_sigterm_forces_exit(t):
    """8b: a second SIGTERM while draining a long request forces the exit"""
    z = t.external
    z.start()   # the external exited in 8a; same data dir and ports
    pid = z.proc.pid
    box = {}
    th = slow_request_thread(t, 40000, box, 50)
    wait_for(lambda: sum(l["path"].startswith("/slow?ms=40000") for l in t.app.log) >= 1, 10, 0.1, "the 40 s request to reach the backend")
    os.kill(pid, signal.SIGTERM)
    t1 = time.time()
    time.sleep(2.5)
    alive = z.proc.poll() is None
    need(alive, "the process did not drain: it exited %.1f s after the first SIGTERM while a request was in flight" % (time.time() - t1))
    t2 = time.time()
    os.kill(pid, signal.SIGTERM)
    try:
        z.proc.wait(10)
    except Exception:
        raise Fail("a second SIGTERM did not force the exit within 10 s")
    dt = time.time() - t2
    need(dt <= 5, "forced exit took %.1f s" % dt)
    th.join(5)
    ev("first SIGTERM: still draining after 2.5 s (alive); second SIGTERM: exited %.1f s later, status %s; the cut client saw: %s" % (dt, z.proc.returncode, desc(box.get("r")) if box.get("r") is not None else "(still waiting)"))


# ====================================================================== 10 config management and audit

def post_zip(z, path, data, **query):
    b = uuid.uuid4().hex
    body = ("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"cfg.zip\"\r\nContent-Type: application/zip\r\n\r\n" % b).encode() + data + ("\r\n--%s--\r\n" % b).encode()
    url = "http://127.0.0.1:%d%s%s" % (z.admin, path, ("?" + urllib.parse.urlencode(query)) if query else "")
    req = urllib.request.Request(url, data=body, method="POST", headers={"X-CSRF-Token": z.csrf, "Content-Type": "multipart/form-data; boundary=" + b})
    try:
        return 200, z.opener.open(req, timeout=60).read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def rezip(src, edit):
    """copy a zip, edit(name, data) -> data for each entry"""
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(src)) as zi, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zo:
        for n in zi.namelist():
            zo.writestr(n, edit(n, zi.read(n)))
    return out.getvalue()


def c10_config_management(t):
    """10: shareable export has no secrets, full export has them, a tampered archive is refused by the dry run, the good one imports, schema stamp present, audit log has the sensitive changes without secret values"""
    z = t.internal
    cskey = "cs-secret-" + uuid.uuid4().hex
    lapi = FakeLAPI(free_port(), cskey)
    try:
        # sensitive changes made during the run (the role and the trusted proxy were set while the topology was built)
        z.api("/api/crowdsec/set", config=json.dumps(dict(enabled=True, lapiUrl=lapi.url, mode="log", pollSeconds=5, graceSeconds=30)), apikey=cskey)
        z.api("/api/adminallow/set", config=json.dumps(dict(cidrs=["127.0.0.0/8"])))
        z.api("/api/destguard/set", config=json.dumps(dict(restrictTools=True, allowedBackends=["127.0.0.1"])))
        set_rule(z, rate=True, ratenum=50, rateburst=100, ratedry=True)
        keypem = read(t.srv_cert[1])
        keybody = [l for l in keypem.splitlines() if l and not l.startswith("-----")][1]   # a line from the middle of the private key
        secrets = {"private key PEM body line": keybody, "private key header": "PRIVATE KEY", "crowdsec API key": cskey}
        need(wait_for(lambda: z.get("/api/crowdsec/status").get("keySet"), 10, 0.5, "crowdsec key stored"), "crowdsec key not stored")
        # ---- shareable export
        code, shr = z.api("/api/conf/export", method="GET", raw=True, mode="shareable")
        need(code == 200 and shr[:2] == b"PK", "shareable export failed: %s" % shr[:100])
        zs = zipfile.ZipFile(io.BytesIO(shr))
        names = zs.namelist()
        man = json.loads(zs.read("manifest.json"))
        blob = b"".join(zs.read(n) for n in names)
        leaks = [k for k, v in secrets.items() if v.encode() in blob]
        need(not leaks, "the shareable export contains: %s (entries %s)" % (leaks, names))
        need(not any(n.endswith(".key") for n in names), "a .key file is in the shareable export: %s" % names)
        ev("shareable export: %d entries, mode=%s, schemaVersion=%s, zoraxyVersion=%s, %d checksummed; grep for [private key body, 'PRIVATE KEY', crowdsec key] -> none; excluded: %s" % (
            len(names), man.get("mode"), man.get("schemaVersion"), man.get("zoraxyVersion"), len(man.get("files", [])), [e.get("path") for e in man.get("excluded", [])][:5]))
        # ---- full export (contains secrets by design)
        code, full = z.api("/api/conf/export", method="GET", raw=True, mode="full", manifest="true")
        need(code == 200 and full[:2] == b"PK", "full export failed")
        zf = zipfile.ZipFile(io.BytesIO(full))
        fblob = b"".join(zf.read(n) for n in zf.namelist())
        has = {k: (v.encode() in fblob) for k, v in secrets.items()}
        need(has["private key PEM body line"], "the full export lacks the TLS private key (it is a full backup)")
        ev("full export: %d entries incl. conf/certs/internal.key; contains private key=%s, plaintext crowdsec key=%s (vault is encrypted at rest); manifest.json present=%s" % (len(zf.namelist()), has["private key PEM body line"], has["crowdsec API key"], "manifest.json" in zf.namelist()))
        # ---- tamper: file content changed, manifest untouched
        def edit_a(n, d):
            return d.replace(b"app.test", b"evil.test", 1) if n.endswith("app.test.config") else d
        bad_a = rezip(shr, edit_a)
        code, body = post_zip(z, "/api/conf/importcheck", bad_a)
        need(code == 400 and (b"checksum" in body.lower() or b"manifest" in body.lower() or b"mismatch" in body.lower()), "tampered file content was not refused by the dry run: HTTP %d %s" % (code, body[:200]))
        ev("dry run, entry content changed: HTTP %d %s" % (code, body.decode().strip()[:160]))
        # ---- tamper: the checksum in the manifest changed
        def edit_b(n, d):
            if n != "manifest.json":
                return d
            m = json.loads(d)
            m["files"][0]["sha256"] = "0" * 64
            return json.dumps(m, indent=2).encode()
        bad_b = rezip(shr, edit_b)
        code, body = post_zip(z, "/api/conf/importcheck", bad_b)
        need(code == 400, "a manifest with a wrong checksum was not refused by the dry run: HTTP %d %s" % (code, body[:200]))
        ev("dry run, manifest checksum changed: HTTP %d %s" % (code, body.decode().strip()[:160]))
        code, body = post_zip(z, "/api/conf/import", bad_b, format="json")
        need(code == 400, "the real import accepted a tampered archive: HTTP %d %s" % (code, body[:200]))
        ev("real import of the tampered archive: HTTP %d (nothing applied)" % code)
        # ---- the good archive: dry run, then import
        code, body = post_zip(z, "/api/conf/importcheck", shr)
        need(code == 200, "dry run of the good archive failed: HTTP %d %s" % (code, body[:200]))
        rep = json.loads(body)
        need(rep.get("verified", rep.get("Verified")) is True, "good archive not shown as verified: %s" % body[:300])
        ev("dry run of the good archive: verified=%s mode=%s" % (rep.get("verified", rep.get("Verified")), rep.get("mode", rep.get("Mode"))))
        code, body = post_zip(z, "/api/conf/import", shr, format="json")
        need(code == 200, "import of the good archive failed: HTTP %d %s" % (code, body[:300]))
        res = json.loads(body)
        ev("import: %s" % json.dumps({k: res.get(k) for k in res if k in ("mode", "verified", "added", "replaced", "removed", "kept", "secretsIgnored", "backupDir", "dbReplaced")} or res)[:300])
        need(any(n.startswith("conf.old_") for n in os.listdir(z.dir)), "no conf.old_<time> backup of the previous config was kept: %s" % os.listdir(z.dir))
        # ---- schema stamp
        stamp = json.load(open(os.path.join(z.dir, "conf", "config_schema.json")))
        need(isinstance(stamp.get("schema"), int) and stamp["schema"] >= 1 and stamp["schema"] == man.get("schemaVersion"), "schema stamp %s vs manifest schemaVersion %s" % (stamp, man.get("schemaVersion")))
        ev("conf/config_schema.json = %s (matches manifest schemaVersion %s)" % (json.dumps(stamp), man.get("schemaVersion")))
        # ---- the imported config loads: restart the internal, traffic and the stored crowdsec key survive
        z.restart()
        r = t.get("/after-import")
        need(r.status == 200, "after import + restart the chain does not work: %s" % desc(r))
        need(z.get("/api/crowdsec/get").get("keySet"), "the crowdsec key was lost by a shareable import (secrets must stay)")
        ev("internal restarted on the imported config: chain HTTP 200, crowdsec keySet=true (shareable import keeps local secrets)")
        # ---- audit log
        au = audit(z, 400)
        events = sorted({e.get("event") for e in au})
        want = ["deployrole", "trustedproxy", "adminallow", "destguard", "ratelimit.change", "crowdsec.set", "config.export", "config.import"]
        missing = [w for w in want if not any((ev_ or "").startswith(w) for ev_ in events)]
        need(not missing, "security audit log lacks events for %s; has %s" % (missing, events))
        ajs = json.dumps(au).encode()
        aleaks = [k for k, v in secrets.items() if v.encode() in ajs]
        need(not aleaks, "the audit log contains secret values: %s" % aleaks)
        ver = z.get("/api/security/audit/verify")
        ev("security audit log: %d entries, events %s; no secret values in it; chain verify: %s" % (len(au), events, json.dumps(ver)[:160]))
    finally:
        lapi.stop()


# ====================================================================== 11 history rollback

def hist_snapshot(z, note):
    r = z.api("/api/history/snapshot", note=note)
    return r["version"]["id"]


def c11_history_rollback(t):
    """11: roll a deliberately bad change back with the config history API (dry run first, then restore); no binary rollback is exercised"""
    z = t.internal
    need(t.get("/h-before").status == 200, "baseline request failed")
    good = hist_snapshot(z, "e2e known good")
    ev("snapshot of the known-good configuration: version %s" % good)
    # the deliberately bad change: the upstream of the internal rule points at a dead port
    z.api("/api/proxy/upstream/update", ep=PUBLIC_HOST, origin=t.app.addr, payload=json.dumps(dict(OriginIpOrDomain="127.0.0.1:1")), active=True)
    bad = hist_snapshot(z, "e2e bad change")
    r = t.get("/h-bad")
    need(r.status in (502, 503, 504, 521), "the bad change should break the chain, got %s" % desc(r))
    ev("bad change (upstream -> 127.0.0.1:1) is live: chain answers HTTP %d; recorded as version %s" % (r.status, bad))
    items = z.get("/api/history/list")["items"]
    ev("history list: %d versions, newest summaries: %s" % (len(items), [i.get("summary") for i in items[:3]]))
    df = z.get("/api/history/diff", **{"from": good, "to": bad})
    need(any("proxy" in f.get("path", "") for f in df.get("files", [])), "diff good->bad does not show the proxy rule: %s" % json.dumps(df)[:300])
    ev("diff version %s -> %s: files %s" % (good, bad, [f.get("path") for f in df["files"]]))
    # dry run: shows the plan, changes nothing
    code, body = z.api("/api/history/restore", raw=True, id=good, scope="proxy", dryrun=True)
    plan = json.loads(body)
    need(code == 200 and plan.get("dryRun", plan.get("DryRun")) and plan.get("items", plan.get("Items")), "dry run answered HTTP %d %s" % (code, body[:300]))
    need(t.get("/h-still-bad").status != 200, "the dry run changed the live configuration")
    ev("dry run (scope proxy): %s; chain still broken" % [i.get("path") for i in plan.get("items", plan.get("Items", []))])
    # the real restore: Zoraxy re-executes itself to load it
    pid = z.proc.pid
    n_started = started_count(z)
    code, body = z.api("/api/history/restore", raw=True, id=good, scope="proxy")
    res = json.loads(body)
    need(code == 200 and res.get("applied", res.get("Applied")), "restore answered HTTP %d %s" % (code, body[:300]))
    ev("restore applied: restarting=%s message=%r pre-restore snapshot=%s" % (res.get("restarting", res.get("Restarting")), res.get("message", res.get("Message")), z.get("/api/history/list").get("lastRestore", {}).get("pre")))
    restart_wait(z, n_started)
    need(z.proc.poll() is None and z.proc.pid == pid, "the internal died or changed PID")
    r = t.get("/h-after")
    need(r.status == 200 and t.app.log[-1]["path"] == "/h-after", "the chain does not work after the rollback: %s" % desc(r))
    ev("after the rollback (same PID %d, re-exec): chain HTTP 200, backend answered" % pid)
    d = z.detail(PUBLIC_HOST)
    need(d["ActiveOrigins"][0]["OriginIpOrDomain"] == t.app.addr, "upstream is %s after the rollback" % d["ActiveOrigins"][0]["OriginIpOrDomain"])
    hl = z.get("/api/history/list")
    ev("lastRestore=%s" % json.dumps(hl.get("lastRestore"))[:200])
    pend = wait_for(lambda: z.get("/api/history/list").get("restorePending") in (None, {}), 60, 2, "the restore to be confirmed healthy (about 20 s)")
    lr = z.get("/api/history/list").get("lastRestore") or {}
    need(lr.get("result") == "confirmed", "the restore was not confirmed: %s" % lr)
    ev("restore confirmed (no pending restore); lastRestore=%s" % json.dumps(lr)[:200])
    au = audit(z, 400)
    rest = [e for e in au if "history" in (e.get("event") or "") or "restore" in (e.get("event") or "")]
    need(rest, "no audit entry for the restore; events: %s" % sorted({e.get("event") for e in au}))
    ev("audit entries: %s" % sorted({e.get("event") for e in rest}))


CHECKS_SHARED = [
    ("1a", c1a_spoof_via_external), ("1b", c1b_spoof_direct_internal),
    ("2", c2_rate_limit_identity),
    ("6", c6_crowdsec), ("9", c9_admin_exposure),
    ("5a", c5a_max_body_413), ("5b", c5b_request_timeout), ("5c", c5c_websocket_both_hops), ("5d", c5d_websocket_ip_upstream_without_host_overwrite),
    ("3a", c3a_tls_private_ca_ok), ("3b", c3b_wrong_ca_fails_closed), ("3c", c3c_pin_mismatch_fails), ("3d", c3d_no_ca_no_skip_fails),
]


# ====================================================================== runner
RESULTS = []


def run_one(cid, fn, t):
    del EVIDENCE[:]
    name = "%s/%s" % (cid, fn.__name__)
    try:
        fn(t)
        status, why = "PASS", ""
    except Skip as e:
        status, why = "NOT RUN", str(e)
    except Fail as e:
        status, why = "FAIL", str(e)
    except Exception as e:  # noqa: BLE001
        status, why = "FAIL", "%s: %s" % (type(e).__name__, e)
        traceback.print_exc()
    RESULTS.append((name, status))
    print("%s %s%s" % (status, name, (" :: " + why) if why else ""), flush=True)
    for e in EVIDENCE:
        print("  evidence: " + e, flush=True)
    if status == "FAIL":
        for z, n in ((t.external, "ext"), (t.internal, "int")):
            if z:
                print("  --- %s log tail ---\n%s" % (n, "\n".join("    " + l for l in z.logtail(1500).splitlines()[-12:])), flush=True)


def run_group(title, mode, checks, keep):
    print("== %s (topology: %s) ==" % (title, mode), flush=True)
    t = DualProxy(mode)
    try:
        t.up()
        print("  client(%s) -> external :%d -> internal https :%d -> backend :%d" % (CLIENT_IP, t.external.proxy, t.internal.proxy, t.app.port), flush=True)
        for cid, fn in checks:
            run_one(cid, fn, t)
    except Exception as e:  # noqa: BLE001
        for cid, fn in checks:
            RESULTS.append(("%s/%s" % (cid, fn.__name__), "FAIL"))
        print("FAIL %s/setup: %s: %s" % (title, type(e).__name__, e), flush=True)
        traceback.print_exc()
    finally:
        t.down(keep)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="", help="comma separated check numbers or ids, e.g. 1,3a,7")
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()
    if not os.path.exists(lib.BIN):
        print("FAIL setup: zoraxy binary %s missing (use run.sh)" % lib.BIN)
        return 2
    only = [x.strip() for x in a.only.split(",") if x.strip()]

    def pick(checks):
        return [(i, f) for i, f in checks if not only or any(i == o or i.rstrip("abcdefgh") == o for o in only)]
    for title, mode, checks in GROUPS:
        sel = pick(checks)
        if sel:
            run_group(title, mode, sel, a.keep)
    bad = [n for n, s in RESULTS if s == "FAIL"]
    print("SUMMARY: %d PASS, %d FAIL, %d NOT RUN" % (sum(s == "PASS" for _, s in RESULTS), len(bad), sum(s == "NOT RUN" for _, s in RESULTS)))
    for n, s in RESULTS:
        print("  %-8s %s" % (s, n))
    return 1 if bad else 0


CHECKS_MTLS = [("4a", c4a_mtls_with_cert_ok), ("4b", c4b_mtls_without_cert_rejected), ("4c", c4c_mtls_other_ca_rejected)]

GROUPS = [("config management", "tls", [("10", c10_config_management)]), ("history rollback", "tls", [("11", c11_history_rollback)]), ("drain", "tls", [("8a", c8a_drain_completes_in_flight), ("8b", c8b_second_sigterm_forces_exit)]), ("shared", "tls", CHECKS_SHARED), ("mtls", "mtls", CHECKS_MTLS), ("failure and recovery", "tls", [("7a", c7a_backend_down_and_back), ("7b", c7b_internal_down_and_back), ("7c", c7c_active_health_probe_ip_upstream_without_host_overwrite)])]

if __name__ == "__main__":
    sys.exit(main())
