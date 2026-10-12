"""TLS configuration probing: protocols, cipher suites, key exchange groups and features."""

from __future__ import annotations

import concurrent.futures as cf
import threading
from collections.abc import Callable
from dataclasses import dataclass, field

from . import ciphers as C
from .wire import (
    EXT_EXTENDED_MASTER_SECRET,
    EXT_HEARTBEAT,
    EXT_RENEGOTIATION_INFO,
    EXT_SCT,
    EXT_SESSION_TICKET,
    EXT_STATUS_REQUEST,
    GROUPS,
    TLS12_EC_GROUPS,
    HelloOptions,
    ServerResponse,
    handshake,
)

LEGACY_PROTOCOLS = [C.TLS12, C.TLS11, C.TLS10, C.SSL3]
TLS13_GROUP_CANDIDATES = [0x11EC, 0x11EB, 0x11ED, 0x6399, 0x001D, 0x0017, 0x0018, 0x0019, 0x001E,
                          0x0100, 0x0101, 0x0102, 0x0103, 0x0104, 0x001F, 0x0020, 0x0021]
MAX_SUITES_PER_HELLO = 120
MAX_ROUNDS = 80


@dataclass
class TLSScan:
    host: str
    ip: str
    port: int
    reachable: bool = False
    error: str | None = None
    protocols: dict[int, bool] = field(default_factory=dict)
    protocol_errors: dict[int, str] = field(default_factory=dict)
    ciphers: dict[int, list[int]] = field(default_factory=dict)
    server_preference: dict[int, bool | None] = field(default_factory=dict)
    groups: list[int] = field(default_factory=list)
    groups_tls12: list[int] = field(default_factory=list)
    dh_bits: dict[int, int] = field(default_factory=dict)  # cipher code -> DH prime size
    chains: dict[str, list[bytes]] = field(default_factory=dict)  # "RSA"/"ECDSA"/... -> DER chain
    ocsp_stapled: bool | None = None
    ocsp_response: bytes | None = None
    secure_renegotiation: bool | None = None
    extended_master_secret: bool | None = None
    session_tickets: bool | None = None
    compression: bool | None = None
    heartbeat: bool | None = None
    fallback_scsv: bool | None = None
    sct_in_tls: bool | None = None
    alpn: list[str] = field(default_factory=list)
    sslv2_ciphers: list[int] = field(default_factory=list)
    downgrade_sentinel: bool | None = None
    sni_required: bool | None = None
    handshakes: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def max_protocol(self) -> int | None:
        supported = [p for p, ok in self.protocols.items() if ok]
        return max(supported) if supported else None

    def supported(self, proto: int) -> bool:
        return bool(self.protocols.get(proto))

    def all_ciphers(self) -> set[int]:
        return {c for lst in self.ciphers.values() for c in lst}

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "ip": self.ip,
            "port": self.port,
            "reachable": self.reachable,
            "error": self.error,
            "protocols": {C.PROTOCOL_NAMES[p]: ok for p, ok in sorted(self.protocols.items(), reverse=True)},
            "ciphers": {
                C.PROTOCOL_NAMES[p]: [C.get(c).to_dict() | ({"dh_bits": self.dh_bits[c]} if c in self.dh_bits else {}) for c in lst]
                for p, lst in sorted(self.ciphers.items(), reverse=True)
            },
            "server_preference": {C.PROTOCOL_NAMES[p]: v for p, v in self.server_preference.items()},
            "groups": [GROUPS.get(g, f"0x{g:04X}") for g in self.groups],
            "groups_tls12": [GROUPS.get(g, f"0x{g:04X}") for g in self.groups_tls12],
            "post_quantum": [GROUPS[g] for g in self.groups if g in (0x11EB, 0x11EC, 0x11ED, 0x6399)],
            "features": {
                "ocsp_stapling": self.ocsp_stapled,
                "secure_renegotiation": self.secure_renegotiation,
                "extended_master_secret": self.extended_master_secret,
                "session_tickets": self.session_tickets,
                "tls_compression": self.compression,
                "heartbeat_extension": self.heartbeat,
                "fallback_scsv": self.fallback_scsv,
                "sct_tls_extension": self.sct_in_tls,
                "alpn": self.alpn,
                "tls13_downgrade_protection": self.downgrade_sentinel,
                "sni_required": self.sni_required,
            },
            "sslv2_ciphers": self.sslv2_ciphers,
            "handshakes": self.handshakes,
            "notes": self.notes,
        }


class TLSScanner:
    def __init__(self, host: str, ip: str, port: int = 443, *, timeout: float = 6.0, workers: int = 4,
                 progress: Callable[[str], None] | None = None, connect=None):
        self.host = host
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.workers = workers
        self.progress = progress or (lambda _msg: None)
        self.connect = connect
        self._lock = threading.Lock()
        self.result = TLSScan(host, ip, port)

    # -- plumbing --

    def _hello(self, **kw) -> ServerResponse:
        kw.setdefault("server_name", self.host)
        opts = HelloOptions(**kw)
        resp = handshake(self.ip, self.port, opts, self.timeout, connect=self.connect)
        if resp.error == "timeout" or (resp.error or "").startswith("connection closed"):
            # one retry: busy servers and middleboxes occasionally drop a hello
            resp2 = handshake(self.ip, self.port, opts, self.timeout, connect=self.connect)
            with self._lock:
                self.result.handshakes += 1
            if resp2.ok or resp2.alert is not None:
                resp = resp2
        with self._lock:
            self.result.handshakes += 1
        return resp

    @staticmethod
    def _accepted(resp: ServerResponse, proto: int) -> bool:
        return resp.ok and resp.hello is not None and resp.hello.version == proto and not resp.sslv2

    # -- phases --

    def run(self) -> TLSScan:
        r = self.result
        self.progress("Testing protocol versions")
        first = self._hello(version=C.TLS13, ciphers=self._ordered(C.probe_suites(C.TLS13)) + self._ordered(C.probe_suites(C.TLS12)),
                            tls13_versions=[C.TLS13, C.TLS12, C.TLS11, C.TLS10])
        if not first.ok and first.alert is None:
            # maybe a legacy-only server that chokes on TLS 1.3 hellos
            first = self._hello(version=C.TLS12, ciphers=self._ordered(C.probe_suites(C.TLS12)))
            if not first.ok and first.alert is None:
                r.error = first.error or "no TLS response"
                r.reachable = False
                # SSLv2-only servers are vanishingly rare but let us still look
                self._probe_sslv2()
                if r.sslv2_ciphers:
                    r.reachable = True
                return r
        r.reachable = True
        self._probe_protocols()
        if not any(r.protocols.values()) and not r.sslv2_ciphers:
            r.error = "the server did not complete a handshake with any protocol version"
            return r
        self.progress("Enumerating cipher suites")
        self._enumerate_all_ciphers()
        self.progress("Testing key exchange groups")
        self._enumerate_groups()
        self.progress("Testing TLS features")
        self._probe_features()
        self.progress("Collecting certificates")
        self._collect_chains()
        return r

    def _ordered(self, codes: list[int]) -> list[int]:
        return sorted(codes, key=C.preference_sort_key)

    def _probe_sslv2(self) -> None:
        resp = self._hello(version=C.SSL2)
        self.result.protocols[C.SSL2] = bool(resp.sslv2)
        if resp.sslv2:
            self.result.sslv2_ciphers = resp.sslv2_ciphers

    def _probe_protocol(self, proto: int) -> tuple[int, bool, str | None]:
        if proto == C.SSL2:
            resp = self._hello(version=C.SSL2)
            if resp.sslv2:
                self.result.sslv2_ciphers = resp.sslv2_ciphers
            return proto, bool(resp.sslv2), resp.error
        if proto == C.TLS13:
            resp = self._hello(version=C.TLS13, ciphers=self._ordered(C.probe_suites(C.TLS13)),
                               tls13_versions=[C.TLS13])
            if resp.ok and resp.hello and resp.hello.hello_retry:
                return proto, True, None
            return proto, self._accepted(resp, C.TLS13), resp.alert_name or resp.error
        kw = {}
        if proto == C.SSL3:
            kw = {"extensions": False}
        resp = self._hello(version=proto, ciphers=self._ordered(C.probe_suites(proto))[:MAX_SUITES_PER_HELLO], **kw)
        if not resp.ok and proto != C.SSL3 and resp.alert in (40, 47, 50, 80):
            # some stacks reject long hellos for old versions; retry with a compact one
            resp = self._hello(version=proto, ciphers=self._ordered(C.probe_suites(proto))[:40])
        return proto, self._accepted(resp, proto), resp.alert_name or resp.error

    def _probe_protocols(self) -> None:
        protos = [C.TLS13, C.TLS12, C.TLS11, C.TLS10, C.SSL3, C.SSL2]
        with cf.ThreadPoolExecutor(self.workers) as pool:
            for proto, ok, err in pool.map(self._probe_protocol, protos):
                self.result.protocols[proto] = ok
                if err and not ok:
                    self.result.protocol_errors[proto] = err

    def _enumerate(self, proto: int) -> list[int]:
        """Repeatedly offer the remaining suites and strike out whatever the server picks."""
        candidates = self._ordered(C.probe_suites(proto))
        accepted: list[int] = []
        tls13 = proto == C.TLS13
        kw: dict = {"tls13_versions": [C.TLS13]} if tls13 else {}
        if proto == C.SSL3:
            kw["extensions"] = False
        chunks = [candidates] if tls13 else [candidates[i:i + MAX_SUITES_PER_HELLO]
                                             for i in range(0, len(candidates), MAX_SUITES_PER_HELLO)]
        for chunk in chunks:
            remaining = list(chunk)
            for _ in range(MAX_ROUNDS):
                if not remaining:
                    break
                resp = self._hello(version=proto, ciphers=remaining, **kw)
                if not (resp.ok and resp.hello and (resp.hello.version == proto or resp.hello.hello_retry)):
                    break
                chosen = resp.hello.cipher
                if chosen not in remaining:
                    self.result.notes.append(
                        f"{C.PROTOCOL_NAMES[proto]}: server selected suite 0x{chosen:04X} that was not offered")
                    break
                accepted.append(chosen)
                remaining.remove(chosen)
                if resp.dh_bits:
                    self.result.dh_bits[chosen] = resp.dh_bits
        return accepted

    def _server_preference(self, proto: int, accepted: list[int]) -> bool | None:
        if len(accepted) < 2:
            return None
        kw: dict = {"tls13_versions": [C.TLS13]} if proto == C.TLS13 else {}
        if proto == C.SSL3:
            kw["extensions"] = False
        fwd = self._hello(version=proto, ciphers=accepted, **kw)
        rev = self._hello(version=proto, ciphers=list(reversed(accepted)), **kw)
        if not (fwd.ok and rev.ok and fwd.hello and rev.hello):
            return None
        return fwd.hello.cipher == rev.hello.cipher

    def _enumerate_all_ciphers(self) -> None:
        protos = [p for p in (C.TLS13, C.TLS12, C.TLS11, C.TLS10, C.SSL3) if self.result.protocols.get(p)]

        def work(proto: int):
            acc = self._enumerate(proto)
            pref = self._server_preference(proto, acc)
            return proto, acc, pref

        with cf.ThreadPoolExecutor(self.workers) as pool:
            for proto, acc, pref in pool.map(work, protos):
                if acc:
                    self.result.ciphers[proto] = acc
                self.result.server_preference[proto] = pref
        # DH prime sizes for DHE suites the server picked only implicitly
        dhe = [c for c in self.result.all_ciphers() if C.get(c).kx == "DHE" and c not in self.result.dh_bits]
        best = max((p for p in self.result.ciphers if p != C.TLS13), default=None)
        for code in dhe[:4]:
            if best is None:
                break
            resp = self._hello(version=best, ciphers=[code])
            if resp.dh_bits:
                self.result.dh_bits[code] = resp.dh_bits

    def _enumerate_groups(self) -> None:
        r = self.result
        if r.supported(C.TLS13):
            remaining = list(TLS13_GROUP_CANDIDATES)
            for _ in range(len(TLS13_GROUP_CANDIDATES)):
                resp = self._hello(version=C.TLS13, ciphers=C.probe_suites(C.TLS13), tls13_versions=[C.TLS13],
                                   groups=remaining, key_shares=[])
                if not (resp.ok and resp.hello and resp.hello.hello_retry):
                    break
                g = resp.hello.selected_group
                if g is None or g not in remaining:
                    break
                r.groups.append(g)
                remaining.remove(g)
        legacy = [p for p in (C.TLS12, C.TLS11, C.TLS10) if r.supported(p)]
        ecdhe = [c for p in legacy for c in r.ciphers.get(p, []) if C.get(c).kx == "ECDHE"]
        if legacy and ecdhe:
            proto = legacy[0]
            remaining = list(TLS12_EC_GROUPS)
            suites = list(dict.fromkeys(ecdhe))
            for _ in range(len(TLS12_EC_GROUPS)):
                resp = self._hello(version=proto, ciphers=suites, groups=remaining)
                if not (resp.ok and resp.kx_group in remaining):
                    break
                r.groups_tls12.append(resp.kx_group)
                remaining.remove(resp.kx_group)
            if not r.groups:
                r.groups = list(r.groups_tls12)

    def _probe_features(self) -> None:
        r = self.result
        legacy = [p for p in (C.TLS12, C.TLS11, C.TLS10, C.SSL3) if r.supported(p)]
        jobs: dict[str, Callable[[], None]] = {}

        if legacy:
            best = legacy[0]
            suites = r.ciphers.get(best) or self._ordered(C.probe_suites(best))

            def base():
                resp = self._hello(version=best, ciphers=suites, heartbeat=True, alpn=["h2", "http/1.1"])
                if resp.ok and resp.hello:
                    ext = resp.hello.extensions
                    r.secure_renegotiation = EXT_RENEGOTIATION_INFO in ext
                    r.extended_master_secret = EXT_EXTENDED_MASTER_SECRET in ext
                    r.session_tickets = EXT_SESSION_TICKET in ext
                    r.heartbeat = EXT_HEARTBEAT in ext
                    r.sct_in_tls = EXT_SCT in ext
                    r.ocsp_stapled = EXT_STATUS_REQUEST in ext and resp.ocsp_response is not None
                    r.ocsp_response = resp.ocsp_response
                    if not r.supported(C.TLS13) and resp.hello.alpn:
                        r.alpn = [resp.hello.alpn]

            def compression():
                resp = self._hello(version=best, ciphers=suites, compression=[1, 0])
                if resp.ok and resp.hello:
                    r.compression = resp.hello.compression != 0

            jobs["base"] = base
            jobs["compression"] = compression

        # TLS_FALLBACK_SCSV (RFC 7507): a downgraded retry must be refused
        versions = sorted([p for p in (C.TLS13, C.TLS12, C.TLS11, C.TLS10, C.SSL3) if r.supported(p)], reverse=True)
        if len(versions) >= 2:
            lower = versions[1]

            def fallback():
                kw = {"extensions": False} if lower == C.SSL3 else {}
                resp = self._hello(version=lower, ciphers=r.ciphers.get(lower) or self._ordered(C.probe_suites(lower)),
                                   fallback_scsv=True, **kw)
                if resp.alert == 86:
                    r.fallback_scsv = True
                elif resp.ok:
                    r.fallback_scsv = False
            jobs["fallback"] = fallback

            if versions[0] == C.TLS13:
                def sentinel():
                    resp = self._hello(version=C.TLS12, ciphers=r.ciphers.get(C.TLS12) or self._ordered(C.probe_suites(C.TLS12)))
                    if resp.ok and resp.hello:
                        r.downgrade_sentinel = resp.hello.downgrade_sentinel is not None
                if r.supported(C.TLS12):
                    jobs["sentinel"] = sentinel

        def sni():
            best_proto = r.max_protocol
            if best_proto is None or best_proto == C.SSL2:
                return
            kw = {"tls13_versions": [C.TLS13]} if best_proto == C.TLS13 else {}
            suites = r.ciphers.get(best_proto) or self._ordered(C.probe_suites(best_proto))
            resp = self._hello(version=best_proto, ciphers=suites, server_name=None, **kw)
            r.sni_required = not resp.ok
        jobs["sni"] = sni

        with cf.ThreadPoolExecutor(self.workers) as pool:
            list(pool.map(lambda f: f(), jobs.values()))

    def _collect_chains(self) -> None:
        """Ask for RSA- and ECDSA-authenticated suites separately to find dual-certificate setups."""
        r = self.result
        legacy = [p for p in (C.TLS12, C.TLS11, C.TLS10, C.SSL3) if r.supported(p)]
        if not legacy:
            return
        best = legacy[0]
        accepted = [C.get(c) for c in r.ciphers.get(best, [])]
        by_auth: dict[str, list[int]] = {}
        for cs in accepted:
            by_auth.setdefault(cs.auth, []).append(cs.code)
        for auth, suites in by_auth.items():
            if auth == "anon":
                continue
            resp = self._hello(version=best, ciphers=suites)
            if resp.ok and resp.certificates:
                r.chains[auth] = resp.certificates
