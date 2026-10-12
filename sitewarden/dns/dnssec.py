"""Full DNSSEC chain-of-trust validation from the root trust anchor down to the domain."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from ..net import Network

# IANA root zone trust anchors (KSK-2017 and KSK-2024), https://data.iana.org/root-anchors/root-anchors.xml
ROOT_ANCHORS = [
    "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
    "38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
]
ALGORITHMS = {
    1: ("RSAMD5", "broken"), 3: ("DSA", "deprecated"), 5: ("RSASHA1", "deprecated"),
    6: ("DSA-NSEC3-SHA1", "deprecated"), 7: ("RSASHA1-NSEC3-SHA1", "deprecated"), 8: ("RSASHA256", "ok"),
    10: ("RSASHA512", "ok"), 12: ("ECC-GOST", "deprecated"), 13: ("ECDSAP256SHA256", "recommended"),
    14: ("ECDSAP384SHA384", "ok"), 15: ("ED25519", "recommended"), 16: ("ED448", "ok"),
}
DIGESTS = {1: "SHA-1", 2: "SHA-256", 3: "GOST", 4: "SHA-384"}


@dataclass
class ZoneStatus:
    zone: str
    signed: bool = False
    secure: bool = False
    ds: list[str] = field(default_factory=list)
    keys: list[str] = field(default_factory=list)
    algorithms: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class DNSSECResult:
    domain: str
    status: str = "unknown"  # secure | insecure | bogus | island | unknown
    chain: list[ZoneStatus] = field(default_factory=list)
    detail: str = ""
    weak_algorithms: list[str] = field(default_factory=list)
    resolver_ad: bool | None = None

    def to_dict(self) -> dict:
        return {"domain": self.domain, "status": self.status, "detail": self.detail,
                "weak_algorithms": self.weak_algorithms, "resolver_ad": self.resolver_ad,
                "chain": [z.__dict__ for z in self.chain]}


def _section_rrsets(msg: dns.message.Message, name: dns.name.Name, rdtype) -> tuple[dns.rrset.RRset | None, dns.rrset.RRset | None]:
    rrset = sig = None
    for rr in msg.answer:
        if rr.name != name:
            continue
        if rr.rdtype == rdtype:
            rrset = rr
        elif rr.rdtype == dns.rdatatype.RRSIG and rr.covers == rdtype:
            sig = rr
    return rrset, sig


def _has_ns(msg: dns.message.Message | None, name: dns.name.Name) -> bool:
    if msg is None:
        return False
    for section in (msg.answer, msg.authority):
        for rr in section:
            if rr.name == name and rr.rdtype in (dns.rdatatype.NS, dns.rdatatype.SOA):
                return True
    return False


def _key_desc(key) -> str:
    alg = ALGORITHMS.get(int(key.algorithm), (str(int(key.algorithm)), "?"))[0]
    role = "KSK" if key.flags & 0x0001 else "ZSK"
    return f"{role} {dns.dnssec.key_id(key)} {alg}"


def validate_chain(net: Network, domain: str, now: dt.datetime | None = None,
                   anchors: list[str] | None = None) -> DNSSECResult:
    res = DNSSECResult(domain=domain)
    when = (now or dt.datetime.now(dt.UTC)).timestamp()
    target = dns.name.from_text(domain)
    labels = target.labels
    names = [dns.name.Name(labels[i:]) for i in range(len(labels) - 1, -1, -1)]  # root ... domain

    # --- root ---
    root = dns.name.root
    msg = net.raw_query(".", "DNSKEY")
    if msg is None:
        res.status, res.detail = "unknown", "DNS queries failed (no resolver reachable)"
        return res
    keys, sig = _section_rrsets(msg, root, dns.rdatatype.DNSKEY)
    zs = ZoneStatus(".", signed=True)
    res.chain.append(zs)
    if keys is None or sig is None:
        zs.error = "resolver did not return signed root DNSKEYs (DNSSEC-unaware resolver?)"
        res.status, res.detail = "unknown", zs.error
        return res
    anchors = [dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, a) for a in (anchors or ROOT_ANCHORS)]
    if not _ds_matches(root, keys, anchors):
        zs.error = "root DNSKEY does not match the IANA trust anchor"
        res.status, res.detail = "bogus", zs.error
        return res
    try:
        dns.dnssec.validate(keys, sig, {root: keys}, now=when)
    except dns.dnssec.ValidationFailure as exc:
        zs.error = f"root DNSKEY signature invalid: {exc}"
        res.status, res.detail = "bogus", zs.error
        return res
    zs.secure = True
    zs.keys = [_key_desc(k) for k in keys]
    trusted_zone, trusted_keys = root, keys

    for name in names[1:]:
        ds_msg = net.raw_query(name.to_text(), "DS")
        if ds_msg is None:
            res.status, res.detail = "unknown", f"DS query for {name} failed"
            return res
        ds, ds_sig = _section_rrsets(ds_msg, name, dns.rdatatype.DS)
        if ds is None:
            # Either not a zone cut (keep walking with the parent's keys) or an unsigned delegation.
            ns_msg = net.raw_query(name.to_text(), "SOA", want_dnssec=True)
            is_cut = _has_ns(ns_msg, name) and any(rr.rdtype == dns.rdatatype.SOA and rr.name == name
                                                   for rr in (ns_msg.answer if ns_msg else []))
            if not is_cut:
                continue
            zs = ZoneStatus(name.to_text())
            key_msg = net.raw_query(name.to_text(), "DNSKEY")
            dnskeys, _ = _section_rrsets(key_msg, name, dns.rdatatype.DNSKEY) if key_msg else (None, None)
            res.chain.append(zs)
            if dnskeys is not None:
                zs.signed = True
                zs.keys = [_key_desc(k) for k in dnskeys]
                res.status = "island"
                res.detail = (f"{name} publishes DNSKEY records but its parent {trusted_zone} has no DS record, so "
                              "validating resolvers treat it as unsigned")
            else:
                res.status = "insecure"
                res.detail = f"{name} is not signed (no DS record at {trusted_zone})"
            return res
        zs = ZoneStatus(name.to_text(), signed=True)
        res.chain.append(zs)
        zs.ds = [f"{d.key_tag} {ALGORITHMS.get(d.algorithm, (str(d.algorithm),))[0]} {DIGESTS.get(d.digest_type, d.digest_type)}" for d in ds]
        if ds_sig is None:
            zs.error = f"DS for {name} is unsigned"
            res.status, res.detail = "bogus", zs.error
            return res
        try:
            dns.dnssec.validate(ds, ds_sig, {trusted_zone: trusted_keys}, now=when)
        except dns.dnssec.ValidationFailure as exc:
            zs.error = f"DS signature for {name} failed: {exc}"
            res.status, res.detail = "bogus", zs.error
            return res
        key_msg = net.raw_query(name.to_text(), "DNSKEY")
        dnskeys, key_sig = _section_rrsets(key_msg, name, dns.rdatatype.DNSKEY) if key_msg else (None, None)
        if dnskeys is None or key_sig is None:
            zs.error = f"{name} has a DS record but serves no signed DNSKEY"
            res.status, res.detail = "bogus", zs.error
            return res
        zs.keys = [_key_desc(k) for k in dnskeys]
        zs.algorithms = sorted({ALGORITHMS.get(int(k.algorithm), (str(int(k.algorithm)),))[0] for k in dnskeys})
        if not _ds_matches(name, dnskeys, list(ds)):
            zs.error = f"no DNSKEY of {name} matches its DS record (broken key rollover?)"
            res.status, res.detail = "bogus", zs.error
            return res
        try:
            dns.dnssec.validate(dnskeys, key_sig, {name: dnskeys}, now=when)
        except dns.dnssec.ValidationFailure as exc:
            zs.error = f"DNSKEY signature for {name} failed: {exc}"
            res.status, res.detail = "bogus", zs.error
            return res
        zs.secure = True
        trusted_zone, trusted_keys = name, dnskeys
        for k in dnskeys:
            alg = int(k.algorithm)
            name_s, status = ALGORITHMS.get(alg, (str(alg), "?"))
            if status in ("broken", "deprecated") and name == names[-1]:
                res.weak_algorithms.append(f"{name}: {name_s}")

    # finally prove the domain's own data validates (SOA of the deepest signed zone)
    soa_msg = net.raw_query(domain, "SOA")
    if soa_msg is not None:
        soa, soa_sig = _section_rrsets(soa_msg, target, dns.rdatatype.SOA)
        if soa is not None and trusted_zone == target:
            if soa_sig is None:
                res.status, res.detail = "bogus", "SOA record is not signed"
                return res
            try:
                dns.dnssec.validate(soa, soa_sig, {trusted_zone: trusted_keys}, now=when)
            except dns.dnssec.ValidationFailure as exc:
                res.status, res.detail = "bogus", f"SOA signature failed: {exc}"
                return res
    res.status = "secure"
    res.detail = "Chain of trust validated from the root: " + " -> ".join(z.zone for z in res.chain)
    res.weak_algorithms = sorted(set(res.weak_algorithms))
    return res


def _ds_matches(name: dns.name.Name, dnskeys, ds_list) -> bool:
    for ds in ds_list:
        for key in dnskeys:
            if dns.dnssec.key_id(key) != ds.key_tag or int(key.algorithm) != ds.algorithm:
                continue
            try:
                digest = {1: "SHA1", 2: "SHA256", 4: "SHA384"}.get(ds.digest_type)
                if digest and dns.dnssec.make_ds(name, key, digest) == ds:
                    return True
            except (dns.dnssec.UnsupportedAlgorithm, ValueError):
                continue
    return False
