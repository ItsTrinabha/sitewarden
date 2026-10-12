"""A small local website (HTTPS + HTTP redirect) built on the standard library, for end-to-end scans."""

from __future__ import annotations

import http.server
import pathlib
import socket
import ssl
import threading

GOOD_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; "
                               "frame-ancestors 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Set-Cookie": "__Host-sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax",
}
GOOD_PAGE = b"<!doctype html><html><head><title>ok</title><script src='/app.js'></script></head><body>hi</body></html>"
BAD_PAGE = (b"<!doctype html><html><head><script src='https://code.jquery.com/jquery-1.12.4.min.js'></script>"
            b"<script src='https://cdn.polyfill.io/v3/polyfill.min.js'></script></head>"
            b"<body><form action='http://example.com/login' method='post'><input type=password></form></body></html>")


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Site:
    def __init__(self, cert: pathlib.Path, key: pathlib.Path, host: str, hardened: bool = True):
        self.host, self.hardened = host, hardened
        self.https_port, self.http_port = _free_port(), _free_port()
        site = self

        class Handler(http.server.BaseHTTPRequestHandler):
            server_version = "nginx" if hardened else "Apache/2.2.15"
            sys_version = ""

            def log_message(self, *a):
                pass

            def do_GET(self):  # noqa: N802
                tls = isinstance(self.connection, ssl.SSLSocket)
                if not tls and site.hardened:
                    self.send_response(301)
                    self.send_header("Location", f"https://{site.host}:{site.https_port}{self.path}")
                    self.end_headers()
                    return
                body = (b"console.log(1)" if self.path == "/app.js" else
                        (GOOD_PAGE if site.hardened else BAD_PAGE))
                if self.path.startswith("/.well-known/"):
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript" if self.path == "/app.js" else "text/html")
                self.send_header("Content-Length", str(len(body)))
                if site.hardened:
                    for k, v in GOOD_HEADERS.items():
                        self.send_header(k, v)
                else:
                    self.send_header("X-Powered-By", "PHP/5.6.40")
                    self.send_header("Set-Cookie", "PHPSESSID=abc; path=/")
                self.end_headers()
                self.wfile.write(body)

            do_HEAD = do_GET

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert, key)
        self.https = http.server.ThreadingHTTPServer(("127.0.0.1", self.https_port), Handler)
        self.https.socket = ctx.wrap_socket(self.https.socket, server_side=True)
        self.http = http.server.ThreadingHTTPServer(("127.0.0.1", self.http_port), Handler)
        for srv in (self.https, self.http):
            srv.daemon_threads = True
            threading.Thread(target=srv.serve_forever, daemon=True).start()

    def close(self):
        for srv in (self.https, self.http):
            srv.shutdown()
            srv.server_close()
