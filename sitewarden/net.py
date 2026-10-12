"""Name resolution, outbound connection policy and SSRF protection.

Every socket Sitewarden opens goes through :class:`Network`, which resolves the
name once, refuses non-public addresses (unless explicitly allowed) and then
connects to the vetted IP. Pinning the address closes the DNS-rebinding gap
between "check" and "connect", which matters when the scanner runs as a public
web service.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import threading
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver


class BlockedAddress(Exception):
    """Raised when a name resolves only to addresses the policy forbids."""


class ResolutionError(Exception):
    pass


def is_public_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if isinstance(addr, ipaddress.IPv6Address) and addr in ipaddress.ip_network("64:ff9b::/96"):
        addr = ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    return addr.is_global and not addr.is_multicast


@dataclass
class DNSAnswer:
    rrset: list[str]
    rcode: str = "NOERROR"
    authenticated: bool = False  # AD flag from a validating resolver
    ttl: int | None = None
    error: str | None = None
    signatures: int = 0

    @property
    def nxdomain(self) -> bool:
        return self.rcode == "NXDOMAIN"


@dataclass
class Network:
    allow_private: bool = False
    nameservers: list[str] | None = None
    dns_port: int = 53
    extra_roots: list[bytes] = field(default_factory=list)  # PEM trust anchors (private CAs, tests)
    dns_timeout: float = 4.0
    connect_timeout: float = 6.0
    overrides: dict[str, str] = field(default_factory=dict)  # host -> ip (like curl --resolve)
    proxy: str | None = None  # http://host:port, CONNECT tunnelling for HTTP(S) fetches only
    _cache: dict = field(default_factory=dict, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # ---- DNS ----

    def resolver(self) -> dns.resolver.Resolver:
        if self.nameservers:
            res = dns.resolver.Resolver(configure=False)
            res.nameservers = list(self.nameservers)
            res.port = self.dns_port
        else:
            try:
                res = dns.resolver.Resolver()
            except dns.resolver.NoResolverConfiguration:
                res = dns.resolver.Resolver(configure=False)
                res.nameservers = ["1.1.1.1", "8.8.8.8"]
        res.lifetime = self.dns_timeout
        res.timeout = min(2.0, self.dns_timeout)
        res.use_edns(0, dns.flags.DO, 1232)
        res.flags = dns.flags.RD | dns.flags.AD
        return res

    def query(self, name: str, rdtype: str) -> DNSAnswer:
        key = (name.lower().rstrip("."), rdtype)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        ans = self._query(name, rdtype)
        with self._lock:
            self._cache[key] = ans
        return ans

    def _query(self, name: str, rdtype: str) -> DNSAnswer:
        try:
            result = self.resolver().resolve(name, rdtype, raise_on_no_answer=False, search=False)
        except dns.resolver.NXDOMAIN:
            return DNSAnswer([], "NXDOMAIN")
        except dns.resolver.NoNameservers as exc:
            return DNSAnswer([], "SERVFAIL", error=str(exc).split(";")[0])
        except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
            return DNSAnswer([], "TIMEOUT", error="DNS query timed out")
        except dns.exception.DNSException as exc:
            return DNSAnswer([], "ERROR", error=str(exc))
        resp = result.response
        rrs = []
        sigs = 0
        ttl = None
        for rrset in resp.answer:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                sigs += len(rrset)
                continue
            if rrset.rdtype == dns.rdatatype.from_text(rdtype):
                ttl = rrset.ttl
                for rd in rrset:
                    rrs.append(_rdata_text(rd))
        return DNSAnswer(rrs, "NOERROR", bool(resp.flags & dns.flags.AD), ttl, signatures=sigs)

    def raw_query(self, name: str, rdtype: str, want_dnssec: bool = True,
                  nameserver: str | None = None) -> dns.message.Message | None:
        """A single query returning the whole message (used for DNSSEC validation)."""
        q = dns.message.make_query(name, rdtype, want_dnssec=want_dnssec, use_edns=0, payload=1232)
        q.flags |= dns.flags.CD  # we validate ourselves, so ask for bogus data too
        servers = [nameserver] if nameserver else (self.resolver().nameservers or [])
        for ns in servers:
            try:
                port = self.dns_port if self.nameservers else 53
                resp = dns.query.udp(q, str(ns), timeout=self.dns_timeout, port=port)
                if resp.flags & dns.flags.TC:
                    resp = dns.query.tcp(q, str(ns), timeout=self.dns_timeout, port=port)
                return resp
            except (dns.exception.DNSException, OSError):
                continue
        return None

    def addresses(self, host: str) -> list[str]:
        host = host.rstrip(".").lower()
        if host in self.overrides:
            return [self.overrides[host]]
        try:
            ipaddress.ip_address(host)
            return [host]
        except ValueError:
            pass
        ips: list[str] = []
        errors = []
        for rdtype in ("A", "AAAA"):
            ans = self.query(host, rdtype)
            ips.extend(ans.rrset)
            if ans.error:
                errors.append(ans.error)
        if not ips and errors and not self.nameservers:
            # fall back to the OS resolver (e.g. split-horizon corporate DNS)
            try:
                infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
                ips = list(dict.fromkeys(i[4][0] for i in infos))
            except OSError:
                pass
        return ips

    def resolve(self, host: str) -> str:
        """Pick one vetted address for the host (IPv4 first)."""
        ips = self.addresses(host)
        if not ips:
            raise ResolutionError(f"{host} does not resolve to any address")
        allowed = [ip for ip in ips if self.allow_private or is_public_ip(ip)]
        if not allowed:
            raise BlockedAddress(f"{host} resolves only to non-public addresses ({', '.join(ips[:3])})")
        allowed.sort(key=lambda ip: ":" in ip)
        return allowed[0]

    # ---- sockets ----

    def check_ip(self, ip: str) -> None:
        if not self.allow_private and not is_public_ip(ip):
            raise BlockedAddress(f"refusing to connect to non-public address {ip}")

    def connect(self, ip: str, port: int, timeout: float | None = None) -> socket.socket:
        self.check_ip(ip)
        return socket.create_connection((ip, port), timeout=timeout or self.connect_timeout)

    @classmethod
    def from_env(cls, **kw) -> Network:
        net = cls(**kw)
        if os.environ.get("SITEWARDEN_PROXY"):
            net.proxy = os.environ["SITEWARDEN_PROXY"]
        if os.environ.get("SITEWARDEN_DNS"):
            net.nameservers = [s.strip() for s in os.environ["SITEWARDEN_DNS"].split(",") if s.strip()]
        return net


def _rdata_text(rd) -> str:
    if rd.rdtype == dns.rdatatype.TXT:
        return b"".join(rd.strings).decode("utf-8", "replace")
    if rd.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
        return rd.address
    return rd.to_text()


def split_host(target: str) -> tuple[str, int | None]:
    """Accept 'example.com', 'https://example.com/path', 'example.com:8443'."""
    t = target.strip()
    if "://" not in t:
        t = "https://" + t
    parts = urlsplit(t)
    host = (parts.hostname or "").rstrip(".").lower()
    return host, parts.port
