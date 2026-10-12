"""Hand-built TLS ClientHello messages and a parser for the server's first flight.

Building the handshake ourselves (rather than going through the local OpenSSL)
lets Sitewarden test protocol versions and cipher suites that modern client
libraries refuse to speak, such as SSL 3.0, TLS 1.0, export and RC4 suites.
Only the unencrypted part of the handshake is ever read; no key material is
derived and no application data is sent.
"""

from __future__ import annotations

import hashlib
import os
import socket
import struct
import time
from dataclasses import dataclass, field

from .ciphers import SSL2, SSL3, TLS12, TLS13

# --- extension and group registries -------------------------------------------------

EXT_SERVER_NAME = 0x0000
EXT_STATUS_REQUEST = 0x0005
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_HEARTBEAT = 0x000F
EXT_ALPN = 0x0010
EXT_SCT = 0x0012
EXT_PADDING = 0x0015
EXT_ENCRYPT_THEN_MAC = 0x0016
EXT_EXTENDED_MASTER_SECRET = 0x0017
EXT_SESSION_TICKET = 0x0023
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_PSK_MODES = 0x002D
EXT_KEY_SHARE = 0x0033
EXT_RENEGOTIATION_INFO = 0xFF01

GROUPS = {
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001D: "x25519",
    0x001E: "x448",
    0x001A: "brainpoolP256r1",
    0x001B: "brainpoolP384r1",
    0x001C: "brainpoolP512r1",
    0x001F: "brainpoolP256r1tls13",
    0x0020: "brainpoolP384r1tls13",
    0x0021: "brainpoolP512r1tls13",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x0102: "ffdhe4096",
    0x0103: "ffdhe6144",
    0x0104: "ffdhe8192",
    0x11EB: "SecP256r1MLKEM768",
    0x11EC: "X25519MLKEM768",
    0x11ED: "SecP384r1MLKEM1024",
    0x6399: "X25519Kyber768Draft00",
    # legacy binary / small prime curves, offered only to find them
    0x0013: "secp192r1",
    0x0015: "secp224r1",
    0x0016: "secp256k1",
}
PQ_GROUPS = {0x11EB, 0x11EC, 0x11ED, 0x6399}
TLS12_EC_GROUPS = [0x001D, 0x0017, 0x0018, 0x0019, 0x001E, 0x001A, 0x001B, 0x001C, 0x0016, 0x0015, 0x0013]
DEFAULT_GROUPS = [0x001D, 0x0017, 0x0018, 0x0019, 0x001E, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104,
                  0x001A, 0x001B, 0x001C, 0x0016, 0x0015, 0x0013]

SIG_ALGS = [
    0x0403, 0x0503, 0x0603,  # ecdsa_secp{256,384,521}r1_sha{256,384,512}
    0x0807, 0x0808,  # ed25519, ed448
    0x0804, 0x0805, 0x0806,  # rsa_pss_rsae
    0x0809, 0x080A, 0x080B,  # rsa_pss_pss
    0x0401, 0x0501, 0x0601,  # rsa_pkcs1
    0x0303, 0x0301, 0x0302,  # sha224 variants (legacy)
    0x0203, 0x0201, 0x0202,  # sha1 (legacy)
    0x0402, 0x0502, 0x0602,  # dsa
]

ALERTS = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 21: "decryption_failed",
    22: "record_overflow", 30: "decompression_failure", 40: "handshake_failure",
    41: "no_certificate", 42: "bad_certificate", 43: "unsupported_certificate",
    44: "certificate_revoked", 45: "certificate_expired", 46: "certificate_unknown",
    47: "illegal_parameter", 48: "unknown_ca", 49: "access_denied", 50: "decode_error",
    51: "decrypt_error", 60: "export_restriction", 70: "protocol_version",
    71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback",
    90: "user_canceled", 100: "no_renegotiation", 109: "missing_extension",
    110: "unsupported_extension", 112: "unrecognized_name",
    113: "bad_certificate_status_response", 115: "unknown_psk_identity",
    116: "certificate_required", 120: "no_application_protocol",
}

HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
assert HRR_RANDOM == hashlib.sha256(b"HelloRetryRequest").digest()

# TLS 1.3 downgrade sentinels in ServerHello.random (RFC 8446 4.1.3)
DOWNGRADE_TLS12 = b"DOWNGRD\x01"
DOWNGRADE_TLS11 = b"DOWNGRD\x00"


# --- building -----------------------------------------------------------------------


def _u8(n: int) -> bytes:
    return struct.pack("!B", n)


def _u16(n: int) -> bytes:
    return struct.pack("!H", n)


def _u24(n: int) -> bytes:
    return struct.pack("!I", n)[1:]


def _vec8(b: bytes) -> bytes:
    return _u8(len(b)) + b


def _vec16(b: bytes) -> bytes:
    return _u16(len(b)) + b


def _ext(ext_type: int, data: bytes) -> bytes:
    return _u16(ext_type) + _vec16(data)


def _key_share_entry(group: int) -> bytes:
    """A syntactically valid public key for the group. The private half is discarded."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, x448, x25519

    if group == 0x001D:
        pub = x25519.X25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    elif group == 0x001E:
        pub = x448.X448PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    elif group in (0x0017, 0x0018, 0x0019):
        curve = {0x0017: ec.SECP256R1(), 0x0018: ec.SECP384R1(), 0x0019: ec.SECP521R1()}[group]
        pub = ec.generate_private_key(curve).public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    else:
        raise ValueError(f"no key share generator for group 0x{group:04X}")
    return _u16(group) + _vec16(pub)


@dataclass
class HelloOptions:
    version: int = TLS12  # legacy_version / highest version offered
    ciphers: list[int] = field(default_factory=list)
    server_name: str | None = None
    tls13_versions: list[int] | None = None  # supported_versions extension contents
    groups: list[int] | None = None
    key_shares: list[int] | None = None  # groups for which a key_share is sent
    compression: list[int] = field(default_factory=lambda: [0])
    status_request: bool = True
    sct: bool = True
    alpn: list[str] | None = None
    renegotiation_info: bool = True
    extended_master_secret: bool = True
    encrypt_then_mac: bool = True
    session_ticket: bool = True
    heartbeat: bool = False
    fallback_scsv: bool = False
    extensions: bool = True
    record_version: int | None = None


def build_client_hello(o: HelloOptions) -> bytes:
    if o.version == SSL2:
        return build_sslv2_client_hello()
    legacy_version = min(o.version, TLS12)
    suites = list(o.ciphers)
    if o.fallback_scsv:
        suites.append(0x5600)
    if not o.renegotiation_info or not o.extensions:
        suites.append(0x00FF)
    body = _u16(legacy_version) + os.urandom(32)
    body += _vec8(os.urandom(32))  # session id (middlebox compat for TLS 1.3)
    body += _vec16(b"".join(_u16(c) for c in suites))
    body += _vec8(bytes(o.compression))

    exts = b""
    if o.extensions:
        if o.server_name and not _is_ip(o.server_name):
            name = o.server_name.encode("idna")
            sni = _u8(0) + _vec16(name)
            exts += _ext(EXT_SERVER_NAME, _vec16(sni))
        groups = o.groups if o.groups is not None else DEFAULT_GROUPS
        if groups:
            exts += _ext(EXT_SUPPORTED_GROUPS, _vec16(b"".join(_u16(g) for g in groups)))
            exts += _ext(EXT_EC_POINT_FORMATS, _vec8(b"\x00"))
        if o.version >= TLS12:
            exts += _ext(EXT_SIGNATURE_ALGORITHMS, _vec16(b"".join(_u16(s) for s in SIG_ALGS)))
        if o.status_request:
            exts += _ext(EXT_STATUS_REQUEST, b"\x01" + _u16(0) + _u16(0))
        if o.sct:
            exts += _ext(EXT_SCT, b"")
        if o.alpn:
            protos = b"".join(_vec8(p.encode()) for p in o.alpn)
            exts += _ext(EXT_ALPN, _vec16(protos))
        if o.renegotiation_info:
            exts += _ext(EXT_RENEGOTIATION_INFO, b"\x00")
        if o.extended_master_secret:
            exts += _ext(EXT_EXTENDED_MASTER_SECRET, b"")
        if o.encrypt_then_mac:
            exts += _ext(EXT_ENCRYPT_THEN_MAC, b"")
        if o.session_ticket:
            exts += _ext(EXT_SESSION_TICKET, b"")
        if o.heartbeat:
            exts += _ext(EXT_HEARTBEAT, b"\x01")
        if o.tls13_versions:
            vers = b"".join(_u16(v) for v in o.tls13_versions)
            exts += _ext(EXT_SUPPORTED_VERSIONS, _vec8(vers))
            exts += _ext(EXT_PSK_MODES, _vec8(b"\x01"))
            shares = o.key_shares if o.key_shares is not None else [0x001D]
            entries = b"".join(_key_share_entry(g) for g in shares)
            exts += _ext(EXT_KEY_SHARE, _vec16(entries))
        # Work around the F5 / IronPort bug with hellos of 256..511 bytes (RFC 7685).
        unpadded = 4 + len(body) + 2 + len(exts)
        if 256 <= unpadded < 512:
            pad = 512 - unpadded - 4
            exts += _ext(EXT_PADDING, b"\x00" * max(pad, 1))
        body += _vec16(exts)

    handshake = _u8(1) + _u24(len(body)) + body
    record_version = o.record_version or (SSL3 if o.version == SSL3 else 0x0301)
    return _u8(22) + _u16(record_version) + _vec16(handshake)


SSL2_CIPHER_SPECS = {
    0x010080: "SSL_CK_RC4_128_WITH_MD5",
    0x020080: "SSL_CK_RC4_128_EXPORT40_WITH_MD5",
    0x030080: "SSL_CK_RC2_128_CBC_WITH_MD5",
    0x040080: "SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5",
    0x050080: "SSL_CK_IDEA_128_CBC_WITH_MD5",
    0x060040: "SSL_CK_DES_64_CBC_WITH_MD5",
    0x0700C0: "SSL_CK_DES_192_EDE3_CBC_WITH_MD5",
}


def build_sslv2_client_hello() -> bytes:
    specs = b"".join(struct.pack("!I", s)[1:] for s in SSL2_CIPHER_SPECS)
    challenge = os.urandom(16)
    msg = b"\x01" + _u16(SSL2) + _u16(len(specs)) + _u16(0) + _u16(len(challenge)) + specs + challenge
    return _u16(0x8000 | len(msg)) + msg


def _is_ip(name: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        return False


# --- parsing ------------------------------------------------------------------------


@dataclass
class ServerHello:
    version: int  # negotiated version (after supported_versions)
    legacy_version: int
    random: bytes
    session_id: bytes
    cipher: int
    compression: int
    extensions: dict[int, bytes]
    hello_retry: bool = False

    @property
    def selected_group(self) -> int | None:
        data = self.extensions.get(EXT_KEY_SHARE)
        if data and len(data) >= 2:
            return struct.unpack("!H", data[:2])[0]
        return None

    @property
    def alpn(self) -> str | None:
        data = self.extensions.get(EXT_ALPN)
        if data and len(data) > 3:
            return data[3:3 + data[2]].decode("ascii", "replace")
        return None

    @property
    def downgrade_sentinel(self) -> bytes | None:
        tail = self.random[-8:]
        if tail in (DOWNGRADE_TLS12, DOWNGRADE_TLS11):
            return tail
        return None


@dataclass
class ServerResponse:
    """Everything observed from one ClientHello."""

    ok: bool = False
    hello: ServerHello | None = None
    alert: int | None = None
    error: str | None = None
    certificates: list[bytes] = field(default_factory=list)
    ocsp_response: bytes | None = None
    kx_group: int | None = None  # named curve from ServerKeyExchange (TLS <= 1.2)
    dh_bits: int | None = None  # finite-field DH prime size from ServerKeyExchange
    dh_prime: bytes | None = None
    sslv2_ciphers: list[int] = field(default_factory=list)
    sslv2: bool = False
    elapsed_ms: int = 0

    @property
    def alert_name(self) -> str | None:
        if self.alert is None:
            return None
        return ALERTS.get(self.alert, f"alert_{self.alert}")


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError("truncated")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("!H", self.take(2))[0]

    def u24(self) -> int:
        return struct.unpack("!I", b"\x00" + self.take(3))[0]

    def remaining(self) -> int:
        return len(self.data) - self.pos


def parse_server_hello(body: bytes) -> ServerHello:
    r = _Reader(body)
    legacy_version = r.u16()
    random = r.take(32)
    session_id = r.take(r.u8())
    cipher = r.u16()
    compression = r.u8()
    exts: dict[int, bytes] = {}
    if r.remaining() >= 2:
        total = r.u16()
        er = _Reader(r.take(total))
        while er.remaining() >= 4:
            et = er.u16()
            exts[et] = er.take(er.u16())
    version = legacy_version
    sv = exts.get(EXT_SUPPORTED_VERSIONS)
    if sv and len(sv) == 2:
        version = struct.unpack("!H", sv)[0]
    return ServerHello(version, legacy_version, random, session_id, cipher, compression, exts,
                       hello_retry=random == HRR_RANDOM)


def parse_certificate_list(body: bytes) -> list[bytes]:
    r = _Reader(body)
    total = r.u24()
    cr = _Reader(r.take(total))
    certs = []
    while cr.remaining() >= 3:
        certs.append(cr.take(cr.u24()))
    return certs


def _recv_exact(sock: socket.socket, n: int, deadline: float) -> bytes:
    buf = b""
    while len(buf) < n:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("read timed out")
        sock.settimeout(remaining)
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def read_server_flight(sock: socket.socket, timeout: float, offered_version: int) -> ServerResponse:
    """Read records until ServerHelloDone, a TLS 1.3 ServerHello, an alert or EOF."""
    resp = ServerResponse()
    deadline = time.monotonic() + timeout
    hs_buf = b""
    first = True
    try:
        while True:
            header = _recv_exact(sock, 5 if not first else 1, deadline)
            if first:
                first = False
                if header[0] & 0x80 and offered_version == SSL2:
                    return _read_sslv2(sock, header, deadline, resp)
                header += _recv_exact(sock, 4, deadline)
            ctype, _rver, length = header[0], struct.unpack("!H", header[1:3])[0], struct.unpack("!H", header[3:5])[0]
            if length > 18432:
                resp.error = "oversized record"
                return resp
            payload = _recv_exact(sock, length, deadline)
            if ctype == 21:  # alert
                if len(payload) >= 2:
                    resp.alert = payload[1]
                return resp
            if ctype == 20:  # change_cipher_spec (TLS 1.3 middlebox compat)
                continue
            if ctype == 23:  # encrypted data: we are past the plaintext flight
                return resp
            if ctype != 22:
                resp.error = f"unexpected record type {ctype}"
                return resp
            hs_buf += payload
            while len(hs_buf) >= 4:
                mtype = hs_buf[0]
                mlen = struct.unpack("!I", b"\x00" + hs_buf[1:4])[0]
                if len(hs_buf) < 4 + mlen:
                    break
                body = hs_buf[4:4 + mlen]
                hs_buf = hs_buf[4 + mlen:]
                if mtype == 2:
                    resp.hello = parse_server_hello(body)
                    resp.ok = True
                    if resp.hello.hello_retry or resp.hello.version == TLS13:
                        return resp
                elif mtype == 11:
                    resp.certificates = parse_certificate_list(body)
                elif mtype == 22:
                    if body and body[0] == 1:
                        resp.ocsp_response = body[4:4 + struct.unpack("!I", b"\x00" + body[1:4])[0]]
                elif mtype == 12 and resp.hello is not None:
                    _parse_server_key_exchange(body, resp)
                elif mtype == 14:  # ServerHelloDone
                    return resp
    except TimeoutError:
        if not resp.ok:
            resp.error = "timeout"
    except (ConnectionError, OSError) as exc:
        if not resp.ok:
            resp.error = f"connection closed ({exc.__class__.__name__})"
    except ValueError as exc:
        resp.error = f"malformed response: {exc}"
    return resp


def _parse_server_key_exchange(body: bytes, resp: ServerResponse) -> None:
    from .ciphers import get

    assert resp.hello is not None
    cs = get(resp.hello.cipher)
    try:
        r = _Reader(body)
        if cs.kx in ("ECDHE",) or (cs.kx == "ECDH" and cs.auth == "anon"):
            if r.u8() == 3:
                resp.kx_group = r.u16()
        elif cs.kx in ("DHE",) or (cs.kx == "DH" and cs.auth == "anon"):
            p = r.take(r.u16())
            resp.dh_prime = p.lstrip(b"\x00")
            resp.dh_bits = len(resp.dh_prime) * 8
            if resp.dh_prime:
                resp.dh_bits = (len(resp.dh_prime) - 1) * 8 + resp.dh_prime[0].bit_length()
    except ValueError:
        pass


def _read_sslv2(sock, first_byte: bytes, deadline: float, resp: ServerResponse) -> ServerResponse:
    rest = _recv_exact(sock, 1, deadline)
    length = ((first_byte[0] & 0x7F) << 8) | rest[0]
    body = _recv_exact(sock, length, deadline)
    if body and body[0] == 4:  # SERVER-HELLO
        r = _Reader(body[1:])
        r.u8()  # session id hit
        r.u8()  # certificate type
        r.u16()  # version
        cert_len = r.u16()
        specs_len = r.u16()
        r.u16()  # connection id length
        cert = r.take(cert_len)
        specs = r.take(specs_len)
        resp.sslv2 = True
        resp.ok = True
        resp.certificates = [cert] if cert else []
        resp.sslv2_ciphers = [struct.unpack("!I", b"\x00" + specs[i:i + 3])[0] for i in range(0, len(specs) - 2, 3)]
    return resp


# --- one round trip -------------------------------------------------------------------


def handshake(ip: str, port: int, options: HelloOptions, timeout: float = 6.0,
              connect=None) -> ServerResponse:
    """Open a TCP connection, send one ClientHello and parse the reply."""
    start = time.monotonic()
    data = build_client_hello(options)
    try:
        sock = connect(ip, port, timeout) if connect else socket.create_connection((ip, port), timeout=timeout)
    except OSError as exc:
        return ServerResponse(error=f"connect failed: {exc.strerror or exc}")
    try:
        sock.sendall(data)
        resp = read_server_flight(sock, timeout, options.version)
    except OSError as exc:
        resp = ServerResponse(error=f"send failed: {exc}")
    finally:
        try:
            sock.close()
        except OSError:
            pass
    resp.elapsed_ms = int((time.monotonic() - start) * 1000)
    return resp
