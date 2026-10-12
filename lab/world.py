"""DNS data for the lab: a signed root, a signed and a broken TLD branch, and lab domains with
good and bad email configurations."""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .dnsserver import Resolver

SOA = "ns1.{o} hostmaster.{o} 2026101201 7200 3600 1209600 300"


def _dkim_txt(bits: int) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    b64 = base64.b64encode(der).decode()
    chunks = " ".join(f'"{b64[i:i + 200]}"' for i in range(0, len(b64), 200))
    return f'"v=DKIM1; k=rsa; p=" {chunks}'


def build(ip: str = "127.0.0.1", domain: str = "lab.test") -> tuple[Resolver, list[str]]:
    """Returns the resolver and the trust anchors (DS of the lab root) to validate against."""
    r = Resolver()
    root = r.zone(".", signed=True)
    root.add(".", "SOA", "a.root.test. hostmaster.root.test. 2026101201 1800 900 604800 86400")
    root.add(".", "NS", "a.root.test.")
    tld = r.zone("test.", signed=True)
    tld.add("test.", "SOA", SOA.format(o="test."))
    tld.add("test.", "NS", "ns1.test.")
    r.delegate_ds(root, tld)

    # --- the well-configured domain ---
    z = r.zone(f"{domain}.", signed=True)
    o = f"{domain}."
    z.add(o, "SOA", SOA.format(o=o))
    z.add(o, "NS", f"ns1.{o}", f"ns2.{o}")
    z.add(f"ns1.{o}", "A", "192.0.2.53")
    z.add(f"ns2.{o}", "A", "198.51.100.53")
    for host in ("modern", "legacy", "expired", "wronghost", "selfsigned", "incomplete", "sha1", "headers", "www", "mta-sts", "ca"):
        z.add(f"{host}.{o}", "A", ip)
    z.add(o, "A", ip)
    z.add(f"modern.{o}", "AAAA", "::1")
    z.add(o, "MX", f"10 mail.{o}")
    z.add(f"mail.{o}", "A", ip)
    z.add(o, "TXT", '"v=spf1 ip4:192.0.2.0/24 include:_spf.' + o + ' -all"')
    z.add(f"_spf.{o}", "TXT", '"v=spf1 ip4:198.51.100.0/24 -all"')
    z.add(f"_dmarc.{o}", "TXT", f'"v=DMARC1; p=reject; rua=mailto:dmarc@{domain}; adkim=s; aspf=s"')
    z.add(f"selector1._domainkey.{o}", "TXT", _dkim_txt(2048))
    z.add(f"_mta-sts.{o}", "TXT", '"v=STSv1; id=20261012"')
    z.add(f"_smtp._tls.{o}", "TXT", f'"v=TLSRPTv1; rua=mailto:tls@{domain}"')
    z.add(o, "CAA", '0 issue "letsencrypt.org"', f'0 iodef "mailto:security@{domain}"')
    z.add(f"old.{o}", "CNAME", "gone-app-7f3a.herokuapp.com.")
    r.delegate_ds(tld, z)

    # --- a domain with poor email and no DNSSEC ---
    w = r.zone("weak.test.")
    w.add("weak.test.", "SOA", SOA.format(o="weak.test."))
    w.add("weak.test.", "NS", "ns1.weak.test.")
    w.add("ns1.weak.test.", "A", "192.0.2.10")
    w.add("weak.test.", "A", ip)
    w.add("www.weak.test.", "A", ip)
    w.add("weak.test.", "MX", "10 mail.weak.test.")
    w.add("mail.weak.test.", "A", ip)
    w.add("weak.test.", "TXT", '"v=spf1 include:a.weak.test include:b.weak.test include:c.weak.test +all"')
    for sub in "abc":
        w.add(f"{sub}.weak.test.", "TXT", '"v=spf1 a mx include:missing.weak.test ?all"')
    w.add("_dmarc.weak.test.", "TXT", '"v=DMARC1; p=none"')
    w.add("s1._domainkey.weak.test.", "TXT", _dkim_txt(1024))

    # --- a signed domain whose DNSKEY signature is broken ---
    b = r.zone("bogus.test.", signed=True)
    b.add("bogus.test.", "SOA", SOA.format(o="bogus.test."))
    b.add("bogus.test.", "NS", "ns1.bogus.test.")
    b.add("bogus.test.", "A", ip)
    r.delegate_ds(tld, b)
    r.broken_signatures.add(b.origin)

    # --- an island of security: DNSKEY but no DS ---
    i = r.zone("island.test.", signed=True)
    i.add("island.test.", "SOA", SOA.format(o="island.test."))
    i.add("island.test.", "NS", "ns1.island.test.")
    i.add("island.test.", "A", ip)

    # a provider zone that does not contain the dangling target
    h = r.zone("herokuapp.com.")
    h.add("herokuapp.com.", "SOA", SOA.format(o="herokuapp.com."))
    return r, [root.ds()]
