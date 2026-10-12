"""A small HTTP/1.1 client that connects only to vetted, pinned addresses."""

from __future__ import annotations

import http.client
import socket
import ssl
import time
import warnings
import zlib
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from ..net import BlockedAddress, Network, ResolutionError

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0 Safari/537.36 Sitewarden/1.0 (+passive security check)"
)
DEFAULT_MAX_BODY = 3 * 1024 * 1024


@dataclass
class Response:
    url: str
    status: int = 0
    reason: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    error: str | None = None
    ip: str | None = None
    elapsed_ms: int = 0
    tls_version: str | None = None
    tls_cipher: str | None = None
    alpn: str | None = None
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None and self.status > 0

    def header(self, name: str) -> str | None:
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return None

    def header_all(self, name: str) -> list[str]:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]

    @property
    def location(self) -> str | None:
        loc = self.header("location")
        return urljoin(self.url, loc.strip()) if loc else None

    @property
    def is_redirect(self) -> bool:
        return self.status in (301, 302, 303, 307, 308) and bool(self.location)

    def text(self, limit: int | None = None) -> str:
        ctype = (self.header("content-type") or "").lower()
        charset = "utf-8"
        if "charset=" in ctype:
            charset = ctype.split("charset=")[-1].split(";")[0].strip().strip('"') or "utf-8"
        body = self.body if limit is None else self.body[:limit]
        try:
            return body.decode(charset, "replace")
        except LookupError:
            return body.decode("utf-8", "replace")


def _verified_context() -> ssl.SSLContext:
    import certifi

    return ssl.create_default_context(cafile=certifi.where())


def _insecure_context(alpn: list[str] | None = None) -> ssl.SSLContext:
    # Certificate trust is evaluated separately (tls/certificate.py), so this client
    # still reads headers from sites with broken certificates, the way a scanner must.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():  # legacy sites still need TLS 1.0 to be readable
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    if alpn:
        ctx.set_alpn_protocols(alpn)
    return ctx


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port, ip, net: Network, timeout):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip
        self._net = net

    def connect(self):
        self.sock = self._net.connect(self._ip, self.port, self.timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, ip, net: Network, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._ip = ip
        self._net = net

    def connect(self):
        raw = self._net.connect(self._ip, self.port, self.timeout)
        server_hostname = self.host if not _is_ip(self.host) else None
        self.sock = self._context.wrap_socket(raw, server_hostname=server_hostname)


def _is_ip(host: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _decode_body(raw: bytes, encoding: str | None, limit: int) -> tuple[bytes, bool]:
    enc = (encoding or "").lower().strip()
    if enc in ("gzip", "x-gzip", "deflate"):
        wbits = 16 + zlib.MAX_WBITS if "gzip" in enc else zlib.MAX_WBITS
        try:
            d = zlib.decompressobj(wbits)
            out = d.decompress(raw, limit)
            return out, bool(d.unconsumed_tail)
        except zlib.error:
            try:
                d = zlib.decompressobj(-zlib.MAX_WBITS)
                out = d.decompress(raw, limit)
                return out, bool(d.unconsumed_tail)
            except zlib.error:
                return raw, False
    return raw[:limit], len(raw) > limit


def fetch(net: Network, url: str, *, method: str = "GET", headers: dict[str, str] | None = None,
          body: bytes | None = None, max_body: int = DEFAULT_MAX_BODY, timeout: float = 12.0,
          alpn: list[str] | None = None, verify: bool = False) -> Response:
    """One request, no redirect following. verify=True enforces certificate validation."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    resp = Response(url=url)
    if scheme not in ("http", "https"):
        resp.error = f"unsupported scheme {scheme!r}"
        return resp
    host = (parts.hostname or "").lower()
    port = parts.port or (443 if scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    hdrs = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
    }
    hdrs.update(headers or {})
    start = time.monotonic()
    conn = None
    try:
        if net.proxy:
            p = urlsplit(net.proxy)
            if scheme == "https":
                conn = http.client.HTTPSConnection(p.hostname, p.port or 8080, timeout=timeout,
                                                   context=_verified_context() if verify else _insecure_context(alpn))
            else:
                conn = http.client.HTTPConnection(p.hostname, p.port or 8080, timeout=timeout)
            conn.set_tunnel(host, port)
        else:
            ip = net.resolve(host)
            resp.ip = ip
            if scheme == "https":
                ctx = _verified_context() if verify else _insecure_context(alpn)
                conn = _PinnedHTTPSConnection(host, port, ip, net, timeout, ctx)
            else:
                conn = _PinnedHTTPConnection(host, port, ip, net, timeout)
        conn.request(method, path, body=body, headers=hdrs)
        r = conn.getresponse()
        resp.status = r.status
        resp.reason = r.reason
        resp.headers = [(k, v) for k, v in r.getheaders()]
        if isinstance(conn.sock, ssl.SSLSocket):
            resp.tls_version = conn.sock.version()
            c = conn.sock.cipher()
            resp.tls_cipher = c[0] if c else None
            resp.alpn = conn.sock.selected_alpn_protocol()
        if method != "HEAD":
            raw = r.read(max_body + 1)
            resp.body, resp.truncated = _decode_body(raw[:max_body], r.getheader("content-encoding"), max_body)
            resp.truncated = resp.truncated or len(raw) > max_body
    except BlockedAddress as exc:
        resp.error = str(exc)
    except ResolutionError as exc:
        resp.error = str(exc)
    except ssl.SSLCertVerificationError as exc:
        resp.error = f"certificate verification failed: {exc.verify_message or exc}"
    except ssl.SSLError as exc:
        resp.error = f"TLS error: {exc.reason or exc}"
    except TimeoutError:
        resp.error = "timed out"
    except ConnectionRefusedError:
        resp.error = "connection refused"
    except (OSError, http.client.HTTPException) as exc:
        resp.error = f"{exc.__class__.__name__}: {exc}"
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass
    resp.elapsed_ms = int((time.monotonic() - start) * 1000)
    return resp


def fetch_chain(net: Network, url: str, *, max_hops: int = 10, **kw) -> list[Response]:
    """Follow redirects, returning every hop (the last one is the final response)."""
    hops: list[Response] = []
    seen = set()
    current = url
    for _ in range(max_hops):
        r = fetch(net, current, **kw)
        hops.append(r)
        if not r.ok or not r.is_redirect:
            break
        nxt = r.location
        if nxt in seen:
            r.error = "redirect loop"
            break
        seen.add(current)
        current = nxt
    return hops
