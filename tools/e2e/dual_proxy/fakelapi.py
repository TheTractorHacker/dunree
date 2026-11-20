"""Fake CrowdSec Local API for the dual-proxy harness.

Same documented endpoints as FakeLAPI in tools/ui-smoke/crowdsec_smoke.py (X-Api-Key, /v1/decisions/stream with startup=true
then deltas, /v1/decisions?ip=), copied here because that file is exec()'d by the UI smoke runner and cannot be imported.
"""
import contextlib
import http.server
import json
import socketserver
import threading


class FakeLAPI:
    def __init__(self, port, key):
        self.port, self.key = port, key
        self.lock = threading.Lock()
        self.decisions = {}
        self.pend_new, self.pend_del = [], []
        self.calls = []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                path, _, qs = self.path.partition("?")
                if self.headers.get("X-Api-Key") != outer.key:
                    self.send_response(403)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                with outer.lock:
                    outer.calls.append(self.path)
                    if path == "/v1/decisions/stream":
                        if "startup=true" in qs:
                            body = {"new": list(outer.decisions.values()) or None, "deleted": None}
                            outer.pend_new, outer.pend_del = [], []
                        else:
                            body = {"new": outer.pend_new or None, "deleted": outer.pend_del or None}
                            outer.pend_new, outer.pend_del = [], []
                    elif path == "/v1/decisions":
                        ip = qs.split("ip=")[-1] if "ip=" in qs else ""
                        body = [d for d in outer.decisions.values() if d["value"] == ip] or None
                    else:
                        self.send_response(404)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                raw = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True
            allow_reuse_address = True

        self.srv = S(("127.0.0.1", port), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    @property
    def url(self):
        return "http://127.0.0.1:%d" % self.port

    def ban(self, ident, ip, typ="ban"):
        d = {"id": ident, "origin": "cscli", "type": typ, "scope": "Ip", "value": ip, "duration": "1h", "scenario": "e2e/manual ban"}
        with self.lock:
            self.decisions[ident] = d
            self.pend_new.append(d)

    def unban(self, ident):
        with self.lock:
            d = self.decisions.pop(ident, None)
            if d:
                self.pend_del.append(d)

    def stop(self):
        with contextlib.suppress(Exception):
            self.srv.shutdown()
            self.srv.server_close()
