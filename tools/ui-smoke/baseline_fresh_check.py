#!/usr/bin/env python3
"""Script-level check of the enterprise baseline on FRESH starts (no browser, standard library only).

Starts throw-away Zoraxy instances (-noauth, own temp dir under $HOME, unique high ports) and verifies through the admin API:
  1. an empty directory: the baseline is applied automatically (state.decision fresh, state.source fresh, the forwarded-header
     clean-up and the new-site security headers are on, audit log has baseline.apply with source fresh);
  2. Undo puts both back (and writes baseline.undo); restarting the SAME directory does not apply it again (items stay off, still
     only one baseline.apply in the audit log, the Apply button stays available);
  3. a directory that already holds a file in conf/ is an existing installation: nothing is applied, decision existing, no audit entry;
  4. an existing-style start that restarts keeps doing nothing.
Usage: baseline_fresh_check.py --bin PATH_TO_ZORAXY --web PATH_TO_src/web [--port 28430] [--work DIR]   (uses PORT and PORT+1, +2, +3)
Exit status 0 and the line "OK, fresh-start checks passed" when everything holds."""

import argparse
import http.cookiejar
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("--bin", required=True, help="the Zoraxy binary to start")
ap.add_argument("--web", required=True, help="the src/web folder (linked into each throw-away directory)")
ap.add_argument("--port", type=int, default=28430, help="first of 4 free ports (admin A, proxy A, admin B, proxy B)")
ap.add_argument("--work", default=os.path.expanduser("~/bl-fresh-work"), help="parent folder for the throw-away instances (removed at the end)")
args = ap.parse_args()

failures = []


def fail(msg):
    failures.append(msg)
    print("FAIL:", msg)


def check(cond, msg):
    if not cond:
        fail(msg)


class Inst:
    def __init__(self, name, admin, proxy):
        self.dir = os.path.join(args.work, name)
        self.admin, self.proxy = admin, proxy
        self.proc = None
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def start(self):
        os.makedirs(self.dir, exist_ok=True)
        if not os.path.exists(os.path.join(self.dir, "web")):
            os.symlink(os.path.abspath(args.web), os.path.join(self.dir, "web"))
        log = open(os.path.join(self.dir, "zoraxy.log"), "ab")
        self.proc = subprocess.Popen([os.path.abspath(args.bin), "-noauth", "-dev", "-default_inbound_port", str(self.proxy), "-port", ":%d" % self.admin,
                                      "-conf", "./conf", "-dbpath", "./sys.db"], cwd=self.dir, stdout=log, stderr=log)
        end = time.time() + 60
        while time.time() < end:
            try:
                self.op.open("http://127.0.0.1:%d/api/baseline/get" % self.admin, timeout=3).read()
                return
            except Exception:
                time.sleep(0.5)
        fail("%s: the instance did not answer in 60 s" % self.dir)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)  # exactly the PID started here
            try:
                self.proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

    def get(self, path):
        return json.loads(self.op.open("http://127.0.0.1:%d%s" % (self.admin, path), timeout=10).read())

    def post(self, path):
        html = self.op.open("http://127.0.0.1:%d/" % self.admin, timeout=10).read().decode()
        tok = re.search(r'name="zoraxy.csrf.Token" content="([^"]+)"', html).group(1)
        req = urllib.request.Request("http://127.0.0.1:%d%s" % (self.admin, path), data=b"", method="POST", headers={"X-CSRF-Token": tok})
        return json.loads(self.op.open(req, timeout=10).read())

    def raw_post_no_csrf(self, path):
        req = urllib.request.Request("http://127.0.0.1:%d%s" % (self.admin, path), data=b"", method="POST")
        try:
            return self.op.open(req, timeout=10).status
        except urllib.error.HTTPError as e:
            return e.code

    def audit(self, prefix):
        return [e for e in self.get("/api/security/audit/list?limit=200").get("entries", []) if e["event"].startswith(prefix)]


def item(d, iid):
    return next(i for i in d["items"] if i["id"] == iid)


shutil.rmtree(args.work, ignore_errors=True)
os.makedirs(args.work)
a = Inst("fresh", args.port, args.port + 1)
b = Inst("existing", args.port + 2, args.port + 3)
try:
    # ---- 1. fresh start
    a.start()
    d = a.get("/api/baseline/get")
    check(d["available"], "fresh: baseline not available")
    check(d["state"].get("decision") == "fresh" and d["state"].get("source") == "fresh", "fresh: state is %s, want decision fresh + source fresh" % d["state"])
    check(item(d, "harden-headers")["status"] == "on" and item(d, "new-site-headers")["status"] == "on", "fresh: both settings must be on after the first start")
    check(d["pending"] == 0 and d["canUndo"], "fresh: nothing pending and Undo available expected, got pending=%s canUndo=%s" % (d["pending"], d["canUndo"]))
    applies = a.audit("baseline.apply")
    check(len(applies) == 1 and applies[0]["detail"].get("source") == "fresh" and applies[0]["outcome"] == "ok", "fresh: want one baseline.apply (source fresh, ok), got %s" % applies)
    check(a.get("/api/deployrole/get").get("hardenActive") is True, "fresh: deployment settings do not show the header clean-up as active")
    # a POST without the CSRF token must not change anything
    code = a.raw_post_no_csrf("/api/baseline/undo")
    check(code in (400, 401, 403), "undo without CSRF token answered %s, want a refusal" % code)
    check(a.get("/api/baseline/get")["canUndo"], "undo without CSRF token must not have undone anything")

    # ---- 2. undo, restart, still not applied
    r = a.post("/api/baseline/undo")
    check(not (isinstance(r, dict) and r.get("error")), "undo failed: %s" % r)
    d = a.get("/api/baseline/get")
    check(item(d, "harden-headers")["status"] == "off" and item(d, "new-site-headers")["status"] == "off", "undo: both settings must be off")
    check(len(a.audit("baseline.undo")) == 1, "undo: want one baseline.undo audit entry")
    a.stop()
    a.start()
    d = a.get("/api/baseline/get")
    check(item(d, "harden-headers")["status"] == "off" and item(d, "new-site-headers")["status"] == "off", "restart after undo: the baseline was applied again")
    check(d["state"].get("decision") == "fresh" and d["state"].get("undoneAt"), "restart after undo: state lost (%s)" % d["state"])
    check(len(a.audit("baseline.apply")) == 1, "restart after undo: a second baseline.apply was recorded")
    check(d["pending"] >= 1, "restart after undo: the Apply button should still be available (pending=%s)" % d["pending"])
    check(a.get("/api/deployrole/get").get("hardenActive") is False, "restart after undo: the header clean-up came back on its own")
    a.stop()
    a.start()  # a second restart: still stable
    check(item(a.get("/api/baseline/get"), "harden-headers")["status"] == "off", "second restart: baseline applied again")

    # ---- 3. an existing-style directory (a file already in conf/) is left alone
    os.makedirs(os.path.join(b.dir, "conf"), exist_ok=True)
    open(os.path.join(b.dir, "conf", "existing-install.txt"), "w").write("an earlier installation left this\n")
    b.start()
    d = b.get("/api/baseline/get")
    check(d["state"].get("decision") == "existing", "existing: state is %s, want decision existing" % d["state"])
    check(item(d, "harden-headers")["status"] == "off" and item(d, "new-site-headers")["status"] == "off", "existing: settings must stay off")
    check(not d["canUndo"] and d["pending"] >= 1 and not d["state"].get("source"), "existing: nothing applied, Apply offered (canUndo=%s pending=%s)" % (d["canUndo"], d["pending"]))
    check(len(b.audit("baseline.")) == 0, "existing: no baseline audit entry expected, got %s" % b.audit("baseline."))
    b.stop()
    b.start()
    d = b.get("/api/baseline/get")
    check(item(d, "harden-headers")["status"] == "off" and not d["canUndo"], "existing after restart: nothing may be applied")
    check(len(b.audit("baseline.")) == 0, "existing after restart: no baseline audit entry expected")
finally:
    a.stop()
    b.stop()
    shutil.rmtree(args.work, ignore_errors=True)

if failures:
    print("%d FAILURE(S)" % len(failures))
    sys.exit(1)
print("OK, fresh-start checks passed")
