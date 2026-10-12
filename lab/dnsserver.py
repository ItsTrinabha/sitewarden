"""A tiny DNS server for tests and the lab range, with optional DNSSEC signing.

It answers as if it were a recursive resolver that already knows every zone, which is
all Sitewarden needs: DNSSEC validation is done by Sitewarden itself from the trust anchor.
"""

from __future__ import annotations

import datetime as dt
import socket
import socketserver
import struct
import threading
from dataclasses import dataclass, field

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
from cryptography.hazmat.primitives.asymmetric import ec


@dataclass
class Zone:
    origin: dns.name.Name
    records: dict[tuple[dns.name.Name, int], dns.rrset.RRset] = field(default_factory=dict)
    ksk: object | None = None
    zsk: object | None = None
    ksk_dnskey: object | None = None
    zsk_dnskey: object | None = None
    signed: bool = False

    def add(self, name: str, rdtype: str, *values: str, ttl: int = 300) -> None:
        n = dns.name.from_text(name, origin=None) if name.endswith(".") else dns.name.from_text(name, self.origin)
        t = dns.rdatatype.from_text(rdtype)
        key = (n, t)
        rrset = self.records.get(key) or dns.rrset.RRset(n, dns.rdataclass.IN, t)
        rrset.ttl = ttl
        for v in values:
            rrset.add(dns.rdata.from_text(dns.rdataclass.IN, t, v, origin=self.origin, relativize=False))
        self.records[key] = rrset

    def sign_keys(self) -> None:
        self.ksk = ec.generate_private_key(ec.SECP256R1())
        self.zsk = ec.generate_private_key(ec.SECP256R1())
        self.ksk_dnskey = dns.dnssec.make_dnskey(self.ksk.public_key(), dns.dnssec.Algorithm.ECDSAP256SHA256, flags=257)
        self.zsk_dnskey = dns.dnssec.make_dnskey(self.zsk.public_key(), dns.dnssec.Algorithm.ECDSAP256SHA256, flags=256)
        rr = dns.rrset.RRset(self.origin, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
        rr.ttl = 3600
        rr.add(self.ksk_dnskey)
        rr.add(self.zsk_dnskey)
        self.records[(self.origin, dns.rdatatype.DNSKEY)] = rr
        self.signed = True

    def ds(self) -> str:
        return dns.dnssec.make_ds(self.origin, self.ksk_dnskey, "SHA256").to_text()


class Resolver:
    """Holds several zones and answers from the deepest one that contains the name."""

    def __init__(self):
        self.zones: dict[dns.name.Name, Zone] = {}
        self.extra_sigs: dict[tuple[dns.name.Name, int], tuple[Zone, dns.rrset.RRset]] = {}
        self.broken_signatures: set[dns.name.Name] = set()

    def zone(self, origin: str, signed: bool = False) -> Zone:
        z = Zone(dns.name.from_text(origin))
        if signed:
            z.sign_keys()
        self.zones[z.origin] = z
        return z

    def delegate_ds(self, parent: Zone, child: Zone) -> None:
        parent.add(child.origin.to_text(), "DS", child.ds(), ttl=3600)

    def _zone_for(self, name: dns.name.Name) -> Zone | None:
        best = None
        for origin, z in self.zones.items():
            if name.is_subdomain(origin) and (best is None or len(origin) > len(best.origin)):
                best = z
        return best

    def _sign(self, zone: Zone, rrset: dns.rrset.RRset) -> dns.rrset.RRset | None:
        if not zone.signed:
            return None
        key, dnskey = (zone.ksk, zone.ksk_dnskey) if rrset.rdtype == dns.rdatatype.DNSKEY else (zone.zsk, zone.zsk_dnskey)
        now = dt.datetime.now(dt.UTC)
        sig = dns.dnssec.sign(rrset, key, zone.origin, dnskey, inception=now - dt.timedelta(hours=1),
                              expiration=now + dt.timedelta(days=7))
        if zone.origin in self.broken_signatures and rrset.rdtype == dns.rdatatype.DNSKEY:
            sig = sig.replace(signature=bytes(len(sig.signature)))
        out = dns.rrset.RRset(rrset.name, dns.rdataclass.IN, dns.rdatatype.RRSIG, rrset.rdtype)
        out.ttl = rrset.ttl
        out.add(sig)
        return out

    def answer(self, query: dns.message.Message) -> dns.message.Message:
        resp = dns.message.make_response(query)
        resp.flags |= dns.flags.RA
        q = query.question[0]
        name, rdtype = q.name, q.rdtype
        want_sig = query.ednsflags & dns.flags.DO
        # DS records belong to the parent zone
        if rdtype == dns.rdatatype.DS and name.parent() != name:
            zone = self._zone_for(name.parent()) if name in self.zones else self._zone_for(name)
        else:
            zone = self._zone_for(name)
        if zone is None:
            resp.set_rcode(dns.rcode.REFUSED)
            return resp
        # follow CNAMEs inside our data
        current = name
        for _ in range(8):
            rr = zone.records.get((current, rdtype))
            cname = zone.records.get((current, dns.rdatatype.CNAME))
            if rr is not None:
                resp.answer.append(rr)
                if want_sig and (sig := self._sign(zone, rr)):
                    resp.answer.append(sig)
                return resp
            if cname is not None and rdtype != dns.rdatatype.CNAME:
                resp.answer.append(cname)
                if want_sig and (sig := self._sign(zone, cname)):
                    resp.answer.append(sig)
                current = cname[0].target
                zone = self._zone_for(current) or zone
                continue
            break
        exists = any(k[0] == current for k in zone.records) or any(
            k[0].is_subdomain(current) for k in zone.records)
        soa = zone.records.get((zone.origin, dns.rdatatype.SOA))
        if soa is not None:
            resp.authority.append(soa)
        if not exists:
            resp.set_rcode(dns.rcode.NXDOMAIN)
        return resp


class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        try:
            q = dns.message.from_wire(data)
        except Exception:
            return
        resp = self.server.resolver.answer(q)
        wire = resp.to_wire(max_size=65535)
        if len(wire) > 1232:
            resp2 = dns.message.make_response(q)
            resp2.flags |= dns.flags.TC
            wire = resp2.to_wire()
        sock.sendto(wire, self.client_address)


class _TCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            length = struct.unpack("!H", self.rfile.read(2))[0]
            q = dns.message.from_wire(self.rfile.read(length))
        except Exception:
            return
        wire = self.server.resolver.answer(q).to_wire(max_size=65535)
        self.wfile.write(struct.pack("!H", len(wire)) + wire)


class _UDP(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


class _TCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(resolver: Resolver, host: str = "127.0.0.1", port: int = 0) -> tuple[int, callable]:
    udp = _UDP((host, port), _UDPHandler)
    port = udp.server_address[1]
    tcp = _TCP((host, port), _TCPHandler)
    udp.resolver = resolver
    tcp.resolver = resolver
    for srv in (udp, tcp):
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    def stop():
        for srv in (udp, tcp):
            srv.shutdown()
            srv.server_close()
    return port, stop


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p
