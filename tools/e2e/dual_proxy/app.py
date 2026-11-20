"""Backend application for the dual-proxy harness: plain HTTP, stoppable and restartable on the same port.

  /            JSON echo of the request as the app saw it (method, path, headers, peer address)
  /slow?ms=N   answers after N milliseconds (default 2000)
  /ws          WebSocket echo (text frames come back prefixed with "echo:"), handshake headers in .ws_requests

Every request is recorded in .log. stop() closes the listener and every open connection; start() binds the same
port again, so a test can take the backend down and bring it back while the proxies keep running.
"""
import contextlib
import http.server
import json
import os
import socket
import socketserver
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from lib import free_port  # noqa: E402
from ws import accept_key, read_message, write_frame  # noqa: E402


class App:
    def __init__(self, name="app", bind="127.0.0.1"):
        self.name = name
        self.bind = bind
        self.port = free_port()
        self.log = []
        self.ws_requests = []
        self.srv = None
        self.conns = set()
        self.lock = threading.Lock()

    @property
    def addr(self):
        return "%s:%d" % (self.bind, self.port)

    @property
    def running(self):
        return self.srv is not None

    def start(self):
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def setup(self):
                super().setup()
                with outer.lock:
                    outer.conns.add(self.connection)

            def finish(self):
                with outer.lock:
                    outer.conns.discard(self.connection)
                with contextlib.suppress(Exception):
                    super().finish()

            def _do(self):
                if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
                    body = b""
                    try:
                        while True:
                            ln = int(self.rfile.readline().strip() or b"0", 16)
                            if ln == 0:
                                self.rfile.readline()
                                break
                            body += self.rfile.read(ln)
                            self.rfile.readline()
                    except Exception:
                        pass
                else:
                    n = int(self.headers.get("Content-Length") or 0)
                    body = self.rfile.read(n) if n else b""
                hdrs = {k.lower(): v for k, v in self.headers.items()}
                outer.log.append(dict(method=self.command, path=self.path, headers=hdrs, body=body, peer=self.client_address[0]))
                u = urllib.parse.urlparse(self.path)
                if u.path == "/ws" and "websocket" in hdrs.get("upgrade", "").lower():
                    return self._ws(hdrs)
                if u.path == "/slow":
                    ms = int((urllib.parse.parse_qs(u.query).get("ms") or ["2000"])[0])
                    time.sleep(ms / 1000.0)
                out = json.dumps(dict(app=outer.name, method=self.command, path=self.path, headers=hdrs,
                                      peer=self.client_address[0], body=body.decode("latin1"))).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(out)

            do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_OPTIONS = do_PATCH = _do

            def _ws(self, hdrs):
                outer.ws_requests.append(hdrs)
                c = self.connection
                c.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                           "Sec-WebSocket-Accept: %s\r\n\r\n" % accept_key(hdrs["sec-websocket-key"])).encode())
                self.close_connection = True
                try:
                    while True:
                        op, data = read_message(c)
                        if op == 8:
                            write_frame(c, 8, data)
                            return
                        if op == 1:
                            write_frame(c, 1, b"echo:" + data)
                        elif op == 2:
                            write_frame(c, 2, data)
                except Exception:
                    pass

        class Srv(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True
            allow_reuse_address = True
            request_queue_size = 128

            def handle_error(self, request, client_address):
                pass  # clients that give up (timeouts, drain tests) are expected here

        with self.lock:
            if self.srv:
                return
            self.srv = Srv((self.bind, self.port), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        with self.lock:
            srv, self.srv = self.srv, None
            conns = list(self.conns)
        if srv:
            with contextlib.suppress(Exception):
                srv.shutdown()
                srv.server_close()
        for c in conns:
            with contextlib.suppress(Exception):
                c.shutdown(socket.SHUT_RDWR)
                c.close()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *a):
        self.stop()
