"""In-app updater against a local fake GitHub Releases server and a THROWAWAY signing key.

The test binary is the product built with `go build -overlay`: only two things differ from the shipped build, the
embedded release public key (replaced by a throwaway one) and the updater source's API base / http permission (to reach
127.0.0.1). The real release key is never read.

Versions: the "new" build is the source tree as it is and reports its own Dunree version (PRODUCT_VERSION); the release
that carries it is tagged "v" + that version, which is what tools/build_release.sh insists on. The "old" build is the
same tree with the version in mod/brand lowered by the overlay (OLD_VERSION), so that the release is an update for it."""
import hashlib, json, os, re, shutil, subprocess, tempfile, threading, http.server
from runner import scenario, NotTestable
import lib
from .common import *

SRC = os.path.join(ROOT, "src")
_ctx = {}
OLD_VERSION = "0.9.0"  # what the "old" build is told it is; lower than every Dunree release


def versions():
    """(Dunree version, version of the base) of the source tree, from mod/brand"""
    src = open(os.path.join(SRC, "mod", "brand", "brand.go")).read()
    pv = re.search(r'^\s*Version\s*=\s*"([^"]+)"', src, re.M)
    cv = re.search(r'^\s*BasedOnVersion\s*=\s*"([^"]+)"', src, re.M)
    check(pv and cv, "cannot read Version / BasedOnVersion from mod/brand/brand.go")
    return pv.group(1), cv.group(1)


def run(*a, **k):
    return subprocess.run(list(a), check=True, capture_output=True, text=True, **k)


def setup():
    if _ctx:
        return _ctx
    # cached under .build (ignored by VCS): the throwaway key and the two overlay builds survive between runs
    d = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".build", "updater")
    os.makedirs(d, exist_ok=True)
    priv, pub = os.path.join(d, "priv.pem"), os.path.join(d, "pub.pem")
    api_port = lib.PORT_MAX  # baked into the test binary; reserved for the fake release server
    lib._ports_used.add(api_port)
    old, new = os.path.join(d, "dunree-old"), os.path.join(d, "dunree-new")
    pv, cv = versions()
    # the stamp names what the cached builds were made from; another version or scheme rebuilds them
    stamp, want = os.path.join(d, "stamp"), f"dunree-release-1 {pv} {cv} {OLD_VERSION} {api_port}"
    have = open(stamp).read() if os.path.exists(stamp) else ""
    if have == want and all(os.path.exists(x) for x in (priv, pub, old, new)):
        _ctx.update(dir=d, priv=priv, pub=pub, old=old, new=new, api_port=api_port, version=pv, compat=cv, tag="v" + pv)
        return _ctx
    for x in (priv, pub, old, new, stamp):
        if os.path.exists(x):
            os.remove(x)
    run("go", "run", os.path.join(ROOT, "tools", "sign_release.go"), "-genkey", priv, pub)
    # overlay: replacement pubkey + source.go with local API base and http allowed
    src = open(os.path.join(SRC, "mod", "updater", "source.go")).read()
    src2 = src.replace('const DefaultAPIBase = "https://api.github.com"', f'const DefaultAPIBase = "http://127.0.0.1:{api_port}"')
    src2 = src2.replace('u.Scheme != "https" && !(s.allowHTTP && u.Scheme == "http")', 'u.Scheme != "https" && u.Scheme != "http"')
    check(src2 != src, "overlay patterns did not match source.go")
    ov = {"Replace": {os.path.join(SRC, "mod", "updater", "release_pubkey.pem"): pub,
                      os.path.join(SRC, "mod", "updater", "source.go"): os.path.join(d, "source.go")}}
    open(os.path.join(d, "source.go"), "w").write(src2)
    open(os.path.join(d, "overlay.json"), "w").write(json.dumps(ov))
    # the "old" build: the same, and mod/brand says an earlier version
    brand = open(os.path.join(SRC, "mod", "brand", "brand.go")).read()
    brand2 = re.sub(r'(?m)^(\s*Version\s*=\s*")[^"]+(")', r'\g<1>' + OLD_VERSION + r'\g<2>', brand, count=1)
    check(brand2 != brand, "overlay pattern did not match mod/brand/brand.go")
    open(os.path.join(d, "brand.go"), "w").write(brand2)
    ov_old = {"Replace": dict(ov["Replace"], **{os.path.join(SRC, "mod", "brand", "brand.go"): os.path.join(d, "brand.go")})}
    open(os.path.join(d, "overlay-old.json"), "w").write(json.dumps(ov_old))
    env = dict(os.environ, GOTMPDIR=os.path.expanduser("~/.cache/go-tmp"), CGO_ENABLED="0")
    subprocess.run(["go", "build", "-overlay", os.path.join(d, "overlay-old.json"), "-o", old, "."], cwd=SRC, check=True, env=env, capture_output=True)
    subprocess.run(["go", "build", "-overlay", os.path.join(d, "overlay.json"), "-trimpath", "-ldflags", "-s -w", "-o", new, "."], cwd=SRC, check=True, env=env, capture_output=True)
    for exe, v in ((old, OLD_VERSION), (new, pv)):
        out = subprocess.run([exe, "-version"], capture_output=True, text=True, cwd=d).stdout.strip()
        check(out.startswith(f"Dunree - Version {v} "), f"{os.path.basename(exe)} -version prints {out!r}, expected version {v}")
    open(stamp, "w").write(want)
    _ctx.update(dir=d, priv=priv, pub=pub, old=old, new=new, api_port=api_port, version=pv, compat=cv, tag="v" + pv)
    return _ctx


ASSET = "dunree_linux_amd64"


def make_release(ctx, tag, build, binary, name, mutate=None, prerelease=False):
    dist = os.path.join(ctx["dir"], "dist-" + name)
    shutil.rmtree(dist, ignore_errors=True)  # a folder of an earlier run may hold files under other names
    os.makedirs(dist)
    shutil.copy(binary, os.path.join(dist, ASSET))
    os.chmod(os.path.join(dist, ASSET), 0o755)
    run("go", "run", os.path.join(ROOT, "tools", "sign_release.go"), "-dist", dist, "-key", ctx["priv"], "-pub", ctx["pub"], "-tag", tag, "-build", str(build), "-upstream", ctx["compat"])
    if mutate:
        mutate(dist)
    return dist


def resign(ctx, dist):
    """sign SHA256SUMS of dist again as it is now, with the throwaway key (openssl; ed25519 signs the raw bytes)"""
    out = subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", ctx["priv"], "-rawin", "-in", os.path.join(dist, "SHA256SUMS")], check=True, capture_output=True).stdout
    check(len(out) == 64, f"openssl did not produce an ed25519 signature ({len(out)} bytes)")
    open(os.path.join(dist, "SHA256SUMS.sig"), "wb").write(out)


class FakeGH:
    def __init__(self, port):
        self.releases = []   # list of dicts {tag, dist, published}
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path.startswith("/repos/") and "/releases" in self.path:
                    out = []
                    for r in outer.releases:
                        base = f"http://127.0.0.1:{port}/dl/{r['tag']}/"
                        out.append({"tag_name": r["tag"], "name": r["tag"], "body": "e2e", "html_url": "http://x", "draft": False, "prerelease": bool(r.get("prerelease")),
                                    "published_at": r["published"], "assets": [{"name": n, "size": os.path.getsize(os.path.join(r["dist"], n)), "browser_download_url": base + n}
                                                                              for n in os.listdir(r["dist"])]})
                    b = json.dumps(out).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(b)))
                    self.end_headers()
                    self.wfile.write(b)
                    return
                m = re.match(r"/dl/([^/]+)/(.+)", self.path)
                if m:
                    for r in outer.releases:
                        if r["tag"] == m.group(1) and os.path.exists(os.path.join(r["dist"], m.group(2))):
                            b = open(os.path.join(r["dist"], m.group(2)), "rb").read()
                            self.send_response(200)
                            self.send_header("Content-Length", str(len(b)))
                            self.end_headers()
                            self.wfile.write(b)
                            return
                self.send_response(404)
                self.end_headers()

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


def check_result(c):
    """the "result" object of a forced update check ({} when the check failed)"""
    st, js = c.get("/api/updater/check", force="true")
    check(st == 200 and isinstance(js, dict), f"update check failed: {st} {str(js)[:300]}")
    return js.get("result") or {}


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def status_wait(c, want, timeout=60):
    def f():
        s = c.get("/api/updater/status")[1]
        return s if isinstance(s, dict) and (s.get("state") in want or s.get("State") in want) else None
    return wait_until(f, timeout, 0.5)


def start_inst(ctx, name):
    # The instance is a plain child process here. When the suite itself runs inside a systemd unit or scope
    # (systemd-run, a CI runner service) INVOCATION_ID is inherited and the updater would take the restart method
    # "systemd" and wait for a supervisor that does not exist.
    os.environ.pop("INVOCATION_ID", None)
    d = tempfile.mkdtemp(prefix=f"e2e-{name}-")
    exe = os.path.join(d, "dunree")
    shutil.copy(ctx["old"], exe)
    os.chmod(exe, 0o755)
    inst = Instance(name, workdir=d, binary=exe, flags=["-update_repo", "e2e/dunree"])
    inst.start()
    return inst, exe


def wait_restart(inst, old_pid_alive=True, timeout=60):
    """in-place exec keeps the PID; wait until the admin API answers again"""
    time.sleep(2)
    return wait_until(lambda: inst.client.get("/api/updater/info")[0] == 200, timeout, 0.5)


@scenario("updater-full-flow", ["110"])
def updater_flow():
    ctx = setup()
    gh = FakeGH(ctx["api_port"])
    inst = None
    try:
        # releases: good (build 100), plus a tampered-binary variant and a downgrade (build 50) published later
        tag = ctx["tag"]
        pre = "-" in tag  # a tag with a pre-release part is only offered on the beta channel
        good = make_release(ctx, tag, 100, ctx["new"], "good")
        # a release of the fork Dunree comes from: higher version number, its own file name and header.  # legacy-compat
        # It is published later and must never be offered or installed.
        fork = os.path.join(ctx["dir"], "dist-fork")
        shutil.rmtree(fork, ignore_errors=True)
        os.makedirs(fork)
        shutil.copy(ctx["new"], os.path.join(fork, "zoraxy_linux_amd64"))  # legacy-compat
        forksums = "# zoraxy-release tag=v3.3.7 build=5000 upstream=3.3.7\n" + sha(os.path.join(fork, "zoraxy_linux_amd64")) + "  zoraxy_linux_amd64\n"  # legacy-compat
        open(os.path.join(fork, "SHA256SUMS"), "w").write(forksums)
        open(os.path.join(fork, "SHA256SUMS.sig"), "wb").write(b"\0" * 64)
        forkrel = {"tag": "v3.3.7", "dist": fork, "published": "2099-06-01T00:00:00Z"}
        gh.releases = [forkrel]
        inst, exe = start_inst(ctx, "upd")
        c = inst.client
        before = sha(exe)
        info = c.get("/api/updater/info")[1]
        check(info.get("preflight") is not None, f"info {str(info)[:200]}")
        check((info.get("current") or {}).get("version") == OLD_VERSION, f"running version: {info.get('current')}")
        if pre:
            st, js = c.post("/api/updater/setChannel", channel="beta")
            check(st == 200, f"cannot select the beta channel: {st} {js}")
        chk = check_result(c)
        check(isinstance(chk, dict) and chk.get("update_available") is False and not chk.get("latest") and "no Dunree release" in (chk.get("reason") or ""),
              f"a source with only a fork release must offer nothing: {str(chk)[:300]}")
        gh.releases = [forkrel, {"tag": tag, "dist": good, "published": "2099-01-01T00:00:00Z", "prerelease": pre}]
        chk = check_result(c)
        check(isinstance(chk, dict) and chk.get("update_available") is True and (chk.get("latest") or {}).get("tag") == tag and chk.get("asset_name") == ASSET,
              f"check: {str(chk)[:300]}")
        pid = inst.proc.pid
        st, js = c.post("/api/updater/start", action="app", backup="true", confirm="true")
        check(st in (200, 202) and not (isinstance(js, dict) and js.get("error")), f"start: {st} {js}")
        ok = wait_until(lambda: sha(exe) == sha(ctx["new"]), 60)
        check(ok, f"binary was not swapped; log: {inst.tail(600)}")
        check(os.path.exists(exe + ".prev") and sha(exe + ".prev") == before, "dunree.prev is not the previous binary")
        # restart in place, health confirmation clears the marker, history records success
        check(wait_restart(inst), "admin API did not come back after the restart")
        check(inst.proc.poll() is None, "process died")
        gone = wait_until(lambda: not os.path.exists(os.path.join(inst.dir, "conf", "updater", "pending.json")), 30)
        check(gone, "pending marker not cleared (health not confirmed)")
        hist = c.get("/api/updater/history")[1]
        check("success" in json.dumps(hist) and tag in json.dumps(hist), f"history: {json.dumps(hist)[:300]}")
        backups = [f for f in os.listdir(os.path.join(inst.dir, "backups")) if "pre-update" in f] if os.path.isdir(os.path.join(inst.dir, "backups")) else []
        check(backups, "no pre-update backup zip")
        installed = json.load(open(os.path.join(inst.dir, "conf", "updater", "installed.json")))
        check(installed.get("tag") == tag and installed.get("product") == "dunree" and installed.get("build") == 100, f"installed.json: {installed}")
        info = c.get("/api/updater/info")[1]
        check((info.get("current") or {}).get("version") == ctx["version"] and (info.get("current") or {}).get("tag") == tag, f"after the update: {info.get('current')}")
        # same release again: nothing to offer (forward only); the fork release is still not offered
        chk = check_result(c)
        check(chk.get("update_available") is False and (chk.get("latest") or {}).get("tag") == tag, f"re-offered the installed release, or offered another: {chk}")
        # downgrade: a higher version signed with build 50 (below the installed 100) must be refused at the header
        down = make_release(ctx, "v99.0.0", 50, ctx["new"], "down")
        gh.releases.append({"tag": "v99.0.0", "dist": down, "published": "2099-02-01T00:00:00Z"})
        c.get("/api/updater/check", force="true")
        st, js = c.post("/api/updater/start", action="app", backup="false", confirm="true")
        s = status_wait(c, ("failed", "error", "idle", "done"), 40)
        txt = json.dumps([js, c.get("/api/updater/status")[1], c.get("/api/updater/history")[1]]).lower()
        check(sha(exe) == sha(ctx["new"]) and ("build" in txt or "downgrade" in txt or "replay" in txt or "older" in txt), f"downgrade not refused: {txt[:500]}")
        # explicit rollback to the saved previous binary
        st, js = c.post("/api/updater/rollback", confirm="true")
        check(st in (200, 202) and not (isinstance(js, dict) and js.get("error")), f"rollback: {js}")
        check(wait_until(lambda: sha(exe) == before, 30), "rollback did not restore the previous binary")
        check(wait_restart(inst), "admin API did not come back after rollback")
        return ("local fake GitHub + throwaway ed25519 key (go build -overlay swaps only the embedded pubkey and API base; the old build is told an earlier version): "
                f"a release of the earlier fork with a higher version number is never offered, check offers the signed Dunree release {tag}, update takes a pre-update backup, "
                "downloads, verifies signature + header + sha256, swaps (dunree.prev kept), restarts via in-place exec (same PID), health confirmation clears the pending marker, history/installed.json updated, "
                "the installed release is not re-offered, a lower-build (downgrade) release is refused, explicit rollback restores the previous binary and restarts")
    finally:
        gh.stop()
        if inst:
            inst.cleanup()
            subprocess.run(["pkill", "-f", inst.dir], check=False)


@scenario("updater-tampered-and-unsigned-refused", ["110"])
def updater_tamper():
    ctx = setup()
    gh = FakeGH(ctx["api_port"])
    inst = None
    try:
        def tamper_bin(dist):
            with open(os.path.join(dist, ASSET), "ab") as f:
                f.write(b"\0tampered")

        def tamper_sums(dist):
            p = os.path.join(dist, "SHA256SUMS")
            open(p, "a").write("# extra\n")

        def wrong_sig(dist):
            b = bytearray(open(os.path.join(dist, "SHA256SUMS.sig"), "rb").read())
            b[0] ^= 0xFF
            open(os.path.join(dist, "SHA256SUMS.sig"), "wb").write(bytes(b))
        def fork_header(dist):
            # a correct signature over a file that starts with the header of the earlier fork (same key)  # legacy-compat
            p = os.path.join(dist, "SHA256SUMS")
            lines = open(p).read().split("\n", 1)
            open(p, "w").write("# zoraxy-release tag=" + ctx["tag"] + " build=303 upstream=" + ctx["compat"] + "\n" + lines[1])  # legacy-compat
            resign(ctx, dist)

        def no_product(dist):
            p = os.path.join(dist, "SHA256SUMS")
            t = open(p).read()
            check(" product=dunree" in t, "the sign tool no longer writes product=dunree")
            open(p, "w").write(t.replace(" product=dunree", "", 1))
            resign(ctx, dist)
        tag = ctx["tag"]
        cases = (("tampered binary", make_release(ctx, tag, 300, ctx["new"], "t-bin", tamper_bin)),
                 ("tampered SHA256SUMS", make_release(ctx, tag, 301, ctx["new"], "t-sums", tamper_sums)),
                 ("corrupted signature", make_release(ctx, tag, 302, ctx["new"], "t-sig", wrong_sig)),
                 ("header of the earlier fork", make_release(ctx, tag, 303, ctx["new"], "t-forkhdr", fork_header)),
                 ("header without the product", make_release(ctx, tag, 304, ctx["new"], "t-noprod", no_product)))
        inst, exe = start_inst(ctx, "updt")
        c = inst.client
        before = sha(exe)
        if "-" in tag:
            c.post("/api/updater/setChannel", channel="beta")
        for name, dist in cases:
            gh.releases = [{"tag": tag, "dist": dist, "published": "2099-01-01T00:00:00Z", "prerelease": "-" in tag}]
            chk = check_result(c)
            check(isinstance(chk, dict) and chk.get("update_available") is True, f"{name}: the release was not even offered, so nothing was tested: {str(chk)[:200]}")
            st, js = c.post("/api/updater/start", action="app", backup="false", confirm="true")
            time.sleep(4)
            wait_until(lambda: (c.get("/api/updater/status")[1] or {}).get("state") not in ("running", "downloading"), 30)
            check(sha(exe) == before, f"{name}: binary changed although the release must be refused")
            check(not os.path.exists(os.path.join(inst.dir, "conf", "updater", "pending.json")), f"{name}: pending marker left")
            stt = c.get("/api/updater/status")[1] or {}
            err = (stt.get("error") or "").lower()
            check(stt.get("state") == "failed" and err, f"{name}: no failure recorded: {json.dumps(stt)[:300]}")
            want = {"tampered binary": "checksum mismatch", "tampered SHA256SUMS": "signature", "corrupted signature": "signature",
                    "header of the earlier fork": "not a dunree release", "header without the product": "not a dunree release"}[name]
            check(want in err, f"{name}: refused for another reason than expected ({want}): {err[:300]}")
        return ("tampered binary (sha mismatch), tampered SHA256SUMS, corrupted signature, and two correctly signed files that are not Dunree releases "
                "(header of the earlier fork, header without product=dunree) each refused for its own reason; running binary untouched, no pending marker, failure recorded")
    finally:
        gh.stop()
        if inst:
            inst.cleanup()


@scenario("updater-bad-release-auto-rollback", ["110"])
def updater_autorollback():
    ctx = setup()
    gh = FakeGH(ctx["api_port"])
    inst = None
    try:
        bad = os.path.join(ctx["dir"], "dunree-bad")
        # passes the `-version` smoke test and the upstream version check, then exits immediately
        open(bad, "w").write('#!/bin/sh\nif [ "$1" = "-version" ]; then echo "Dunree - Version %s"; exit 0; fi\nexit 1\n' % ctx["version"])
        os.chmod(bad, 0o755)
        tag = ctx["tag"]
        rel = make_release(ctx, tag, 900, bad, "bad")
        gh.releases = [{"tag": tag, "dist": rel, "published": "2099-03-01T00:00:00Z", "prerelease": "-" in tag}]
        inst, exe = start_inst(ctx, "updb")
        c = inst.client
        before = sha(exe)
        if "-" in tag:
            c.post("/api/updater/setChannel", channel="beta")
        c.get("/api/updater/check", force="true")
        st, js = c.post("/api/updater/start", action="app", backup="false", confirm="true")
        check(st in (200, 202) and not (isinstance(js, dict) and js.get("error")), f"start {js}")
        check(wait_until(lambda: sha(exe) == sha(bad), 60), "bad release was not installed")
        # the process is now a script that exits; the watchdog (old binary) rolls back after deadline + grace
        restored = wait_until(lambda: sha(exe) == before, 200, 2)
        check(restored, f"no automatic rollback within 200s; watchdog log: {open(os.path.join(inst.dir, 'conf', 'updater', 'watchdog.log')).read()[-300:] if os.path.exists(os.path.join(inst.dir, 'conf', 'updater', 'watchdog.log')) else 'none'}")
        up = wait_until(lambda: c.get("/api/updater/info")[0] == 200, 60, 1)
        check(up, "restored binary was not started again")
        hist = json.dumps(c.get("/api/updater/history")[1])
        check("auto_rollback" in hist, f"history lacks auto_rollback: {hist[:300]}")
        return "release whose binary passes -version but exits at start: installed, then the out-of-process watchdog restored the previous binary after the 90s deadline + grace, restarted it, history records auto_rollback"
    finally:
        gh.stop()
        if inst:
            inst.cleanup()
            subprocess.run(["pkill", "-f", inst.dir], check=False)
