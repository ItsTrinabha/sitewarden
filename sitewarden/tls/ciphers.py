"""Cipher suite registry with security properties derived from IANA names."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from .cipher_table import CIPHERS

SSL2 = 0x0002
SSL3 = 0x0300
TLS10 = 0x0301
TLS11 = 0x0302
TLS12 = 0x0303
TLS13 = 0x0304

PROTOCOL_NAMES = {
    SSL2: "SSL 2.0",
    SSL3: "SSL 3.0",
    TLS10: "TLS 1.0",
    TLS11: "TLS 1.1",
    TLS12: "TLS 1.2",
    TLS13: "TLS 1.3",
}

SCSV_RENEGOTIATION = 0x00FF
SCSV_FALLBACK = 0x5600


@dataclass(frozen=True)
class CipherSuite:
    code: int
    name: str
    openssl: str
    kx: str  # RSA, DHE, ECDHE, DH, ECDH, PSK, SRP, ANY (TLS 1.3)
    auth: str  # RSA, ECDSA, DSS, anon, PSK, ANY
    cipher: str  # AES_128_GCM, CHACHA20_POLY1305, 3DES_EDE_CBC, RC4_128, NULL, ...
    bits: int
    mac: str  # SHA, SHA256, SHA384, MD5, AEAD
    export: bool
    tls13: bool

    @property
    def hex(self) -> str:
        return f"0x{self.code:04X}"

    @property
    def aead(self) -> bool:
        return any(x in self.cipher for x in ("GCM", "CCM", "CHACHA20", "POLY1305"))

    @property
    def cbc(self) -> bool:
        return "CBC" in self.cipher

    @property
    def forward_secret(self) -> bool:
        return self.tls13 or self.kx in ("DHE", "ECDHE")

    @property
    def anonymous(self) -> bool:
        return self.auth == "anon"

    @property
    def null_cipher(self) -> bool:
        return self.cipher == "NULL"

    @property
    def rc4(self) -> bool:
        return self.cipher.startswith("RC4")

    @property
    def block_64bit(self) -> bool:
        return any(x in self.cipher for x in ("3DES", "DES", "IDEA", "RC2"))

    @property
    def min_version(self) -> int:
        if self.tls13:
            return TLS13
        if self.aead or self.mac in ("SHA256", "SHA384"):
            return TLS12
        return SSL3

    @property
    def strength(self) -> str:
        """insecure / weak / acceptable / strong, in the spirit of ciphersuite.info."""
        if self.null_cipher or self.anonymous or self.export or self.rc4 or self.bits < 112:
            return "insecure"
        if self.cipher.startswith("DES") or "RC2" in self.cipher:
            return "insecure"
        if self.block_64bit or self.mac == "MD5":
            return "weak"
        if not self.forward_secret:
            return "weak"
        if self.cbc:
            return "acceptable"
        return "strong"

    def to_dict(self) -> dict:
        return {
            "code": self.hex,
            "name": self.name,
            "openssl": self.openssl,
            "kx": self.kx,
            "auth": self.auth,
            "cipher": self.cipher,
            "bits": self.bits,
            "mac": self.mac,
            "forward_secret": self.forward_secret,
            "aead": self.aead,
            "strength": self.strength,
        }


_TLS13_PARAMS = {
    "TLS_AES_128_GCM_SHA256": ("AES_128_GCM", 128),
    "TLS_AES_256_GCM_SHA384": ("AES_256_GCM", 256),
    "TLS_CHACHA20_POLY1305_SHA256": ("CHACHA20_POLY1305", 256),
    "TLS_AES_128_CCM_SHA256": ("AES_128_CCM", 128),
    "TLS_AES_128_CCM_8_SHA256": ("AES_128_CCM_8", 128),
}


def _bits_for(cipher: str) -> int:
    if cipher == "NULL":
        return 0
    if "EXPORT" in cipher:
        return 40
    if cipher.startswith("3DES"):
        return 112  # effective strength against meet-in-the-middle
    if cipher.startswith("DES40"):
        return 40
    if cipher.startswith("DES"):
        return 56
    if cipher.startswith("CHACHA20"):
        return 256
    for token in cipher.split("_"):
        if token.isdigit():
            return int(token)
    if cipher.startswith(("IDEA", "SEED")):
        return 128
    return 128


def parse_iana(code: int, name: str, openssl: str = "") -> CipherSuite:
    if name in _TLS13_PARAMS:
        cipher, bits = _TLS13_PARAMS[name]
        return CipherSuite(code, name, openssl, "ANY", "ANY", cipher, bits, "AEAD", False, True)
    body = name[len("TLS_"):] if name.startswith("TLS_") else name
    export = "_EXPORT" in body
    left, _, right = body.partition("_WITH_")
    left = left.replace("_EXPORT1024", "").replace("_EXPORT", "")
    parts = left.split("_")
    kx = parts[0]
    auth = parts[1] if len(parts) > 1 else parts[0]
    if kx == "RSA" and len(parts) == 1:
        auth = "RSA"
    if auth == "anon":
        pass
    elif kx in ("PSK", "SRP") and len(parts) == 1:
        auth = kx
    elif kx in ("DHE", "ECDHE", "DH", "ECDH") and len(parts) > 1 and parts[1] == "PSK":
        auth = "PSK"
    tokens = right.split("_")
    mac = tokens[-1]
    if mac in ("SHA", "SHA256", "SHA384", "MD5"):
        cipher_tokens = tokens[:-1]
    else:
        cipher_tokens = tokens
        mac = "AEAD"
    cipher = "_".join(cipher_tokens) or "NULL"
    if any(x in cipher for x in ("GCM", "CCM", "POLY1305")):
        mac = "AEAD" if mac in ("SHA256", "SHA384") and "CBC" not in cipher else mac
    if cipher == "DES40_CBC":
        bits = 40
    elif "RC4_40" in cipher or "RC2_CBC_40" in cipher:
        bits = 40
    elif cipher == "RC4_56" or (cipher == "DES_CBC" and "EXPORT1024" in name):
        bits = 56
    else:
        bits = _bits_for(cipher)
    if export:
        bits = min(bits, 56)
    return CipherSuite(code, name, openssl, kx, auth, cipher, bits, mac, export, False)


@lru_cache(maxsize=1)
def registry() -> dict[int, CipherSuite]:
    return {code: parse_iana(code, iana, ossl) for code, (iana, ossl) in CIPHERS.items()}


def get(code: int) -> CipherSuite:
    reg = registry()
    if code in reg:
        return reg[code]
    return CipherSuite(code, f"UNKNOWN_0x{code:04X}", "", "?", "?", "?", 0, "?", False, False)


def probe_suites(version: int) -> list[int]:
    """Suites worth offering for a given protocol version (no PSK/SRP/KRB)."""
    out = []
    for code, cs in registry().items():
        if cs.kx in ("PSK", "SRP", "RSA_PSK", "KRB5") or cs.auth in ("PSK", "SRP"):
            continue
        if "PSK" in cs.name or "SRP" in cs.name or "KRB5" in cs.name:
            continue
        if version == TLS13:
            if cs.tls13:
                out.append(code)
            continue
        if cs.tls13:
            continue
        if cs.min_version > version:
            continue
        if version == SSL3 and (cs.kx.startswith("EC")):
            continue  # SSLv3 predates elliptic-curve suites
        out.append(code)
    return out


def preference_sort_key(code: int) -> tuple:
    """A sensible client-side ordering: strongest first (used for our hellos)."""
    cs = get(code)
    rank = {"strong": 0, "acceptable": 1, "weak": 2, "insecure": 3}[cs.strength]
    return (rank, not cs.forward_secret, not cs.aead, -cs.bits, code)
