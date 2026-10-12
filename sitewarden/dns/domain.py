"""Domain-level DNS checks: DNSSEC, CAA, name servers, IPv6, dangling CNAMEs and SMTP STARTTLS."""

from __future__ import annotations

import ipaddress
import ssl
from dataclasses import dataclass

from ..domains import registrable_domain
from ..models import Findings, Severity
from ..net import BlockedAddress, Network
from ..remediation import SNIPPETS
from . import dnssec

# CA organisation names (as they appear in certificate issuers) -> CAA identifiers that authorise them.
CA_CAA = {
    "let's encrypt": ["letsencrypt.org"],
    "internet security research group": ["letsencrypt.org"],
    "digicert": ["digicert.com", "symantec.com", "thawte.com", "geotrust.com", "rapidssl.com", "www.digicert.com"],
    "geotrust": ["digicert.com", "geotrust.com"],
    "rapidssl": ["digicert.com", "rapidssl.com"],
    "thawte": ["digicert.com", "thawte.com"],
    "sectigo": ["sectigo.com", "comodoca.com", "comodo.com", "usertrust.com", "trust-provider.com"],
    "comodo": ["sectigo.com", "comodoca.com", "comodo.com"],
    "zerossl": ["sectigo.com", "zerossl.com"],
    "google trust services": ["pki.goog", "google.com"],
    "amazon": ["amazon.com", "amazontrust.com", "awstrust.com", "amazonaws.com"],
    "globalsign": ["globalsign.com"],
    "godaddy": ["godaddy.com", "starfieldtech.com"],
    "starfield": ["starfieldtech.com", "godaddy.com"],
    "entrust": ["entrust.net", "affirmtrust.com"],
    "ssl corporation": ["ssl.com"],
    "ssl.com": ["ssl.com"],
    "buypass": ["buypass.com", "buypass.no"],
    "microsoft": ["microsoft.com"],
    "certum": ["certum.pl", "certum.eu"],
    "identrust": ["identrust.com"],
    "actalis": ["actalis.it"],
    "harica": ["harica.gr"],
    "cloudflare": ["digicert.com", "letsencrypt.org", "pki.goog", "sectigo.com", "ssl.com"],
}

# CNAME targets on platforms where an abandoned resource name can be re-registered by anyone.
TAKEOVER_SUFFIXES = {
    ".s3.amazonaws.com": "AWS S3", ".s3-website": "AWS S3 website", ".cloudfront.net": "AWS CloudFront",
    ".elasticbeanstalk.com": "AWS Elastic Beanstalk", ".herokuapp.com": "Heroku", ".herokudns.com": "Heroku",
    ".github.io": "GitHub Pages", ".azurewebsites.net": "Azure App Service", ".cloudapp.net": "Azure",
    ".cloudapp.azure.com": "Azure", ".trafficmanager.net": "Azure Traffic Manager",
    ".blob.core.windows.net": "Azure Storage", ".azureedge.net": "Azure CDN", ".azurefd.net": "Azure Front Door",
    ".netlify.app": "Netlify", ".netlify.com": "Netlify", ".vercel.app": "Vercel", ".now.sh": "Vercel",
    ".surge.sh": "Surge", ".bitbucket.io": "Bitbucket", ".ghost.io": "Ghost", ".myshopify.com": "Shopify",
    ".pantheonsite.io": "Pantheon", ".zendesk.com": "Zendesk", ".readthedocs.io": "Read the Docs",
    ".wpengine.com": "WP Engine", ".fly.dev": "Fly.io", ".pages.dev": "Cloudflare Pages",
    ".firebaseapp.com": "Firebase", ".web.app": "Firebase", ".appspot.com": "Google App Engine",
    ".helpscoutdocs.com": "Help Scout", ".statuspage.io": "Statuspage", ".unbouncepages.com": "Unbounce",
    ".webflow.io": "Webflow", ".strikinglyapp.com": "Strikingly", ".tumblr.com": "Tumblr",
}


@dataclass
class MXResult:
    host: str
    starttls: bool | None = None
    tls_version: str | None = None
    cert_valid: bool | None = None
    cert_error: str | None = None
    banner: str | None = None
    error: str | None = None


def smtp_starttls(net: Network, mx: str, timeout: float = 8.0) -> MXResult:
    """Connect to port 25 like any sending mail server would, and try STARTTLS."""
    res = MXResult(mx)
    try:
        ip = net.resolve(mx)
        sock = net.connect(ip, 25, timeout)
    except BlockedAddress as exc:
        res.error = str(exc)
        return res
    except OSError as exc:
        res.error = f"port 25 unreachable ({exc.__class__.__name__})"
        return res
    except Exception as exc:
        res.error = str(exc)
        return res
    try:
        f = sock.makefile("rb")

        def read_reply() -> list[str]:
            lines = []
            while True:
                line = f.readline(4096).decode("utf-8", "replace").rstrip("\r\n")
                if not line:
                    break
                lines.append(line)
                if len(line) < 4 or line[3] != "-":
                    break
            return lines

        banner = read_reply()
        res.banner = banner[0][:120] if banner else None
        if not banner or not banner[0].startswith("220"):
            res.error = "no SMTP greeting"
            return res
        sock.sendall(b"EHLO sitewarden.invalid\r\n")
        caps = read_reply()
        res.starttls = any("STARTTLS" in c.upper() for c in caps)
        if not res.starttls:
            sock.sendall(b"QUIT\r\n")
            return res
        sock.sendall(b"STARTTLS\r\n")
        reply = read_reply()
        if not reply or not reply[0].startswith("220"):
            res.error = "STARTTLS refused: " + (reply[0] if reply else "no reply")
            return res
        import certifi

        ctx = ssl.create_default_context(cafile=certifi.where())
        try:
            tls = ctx.wrap_socket(sock, server_hostname=mx)
            res.cert_valid = True
        except ssl.SSLCertVerificationError as exc:
            res.cert_valid = False
            res.cert_error = exc.verify_message
            return res
        res.tls_version = tls.version()
        try:
            tls.sendall(b"QUIT\r\n")
            tls.close()
        except OSError:
            pass
    except (OSError, ssl.SSLError) as exc:
        res.error = f"{exc.__class__.__name__}: {exc}"
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return res


def caa_lookup(net: Network, host: str) -> tuple[str | None, list[str]]:
    """RFC 8659 tree climbing: the closest ancestor with CAA records wins."""
    labels = host.rstrip(".").split(".")
    for i in range(len(labels) - 1):
        name = ".".join(labels[i:])
        ans = net.query(name, "CAA")
        if ans.rrset:
            return name, ans.rrset
    return None, []


def _caa_allows(records: list[str], issuer_org: str | None, wildcard: bool) -> bool | None:
    if not issuer_org:
        return None
    ids = None
    for org, caa_ids in CA_CAA.items():
        if org in issuer_org.lower():
            ids = caa_ids
            break
    if ids is None:
        return None
    issue, issuewild = [], []
    for r in records:
        parts = r.split(None, 2)
        if len(parts) < 3:
            continue
        tag, value = parts[1].lower(), parts[2].strip('"').split(";")[0].strip().lower()
        if tag == "issue":
            issue.append(value)
        elif tag == "issuewild":
            issuewild.append(value)
    relevant = issuewild if (wildcard and issuewild) else issue
    if not relevant and not (wildcard and issuewild):
        return True  # no issue property: CAA does not restrict this kind of issuance
    return any(v in ids for v in relevant if v)


def analyze(net: Network, host: str, cert_reports=None,
            dnssec_anchors: list[str] | None = None) -> tuple[Findings, dict]:
    f = Findings("dns")
    domain = registrable_domain(host)
    facts: dict = {"host": host, "domain": domain}

    # --- resolution & IPv6 ---
    a = net.query(host, "A")
    aaaa = net.query(host, "AAAA")
    facts["a"] = a.rrset
    facts["aaaa"] = aaaa.rrset
    soa = net.query(domain, "SOA")
    if not soa.rrset and "." in domain:
        # the registrable domain can sit inside a larger zone (e.g. user.github.io); its parent has the SOA
        soa = net.query(domain.split(".", 1)[1], "SOA")
    if not soa.rrset:
        # Every real zone has an SOA record at its apex. A resolver that returns none is blocked, filtered
        # or answering only some record types, and every other DNS and email result would mislead.
        facts["dns_unavailable"] = True
        why = "no address for the host" if not a.rrset and not aaaa.rrset else "no SOA record for the zone"
        f.add("dns.unavailable", Severity.INFO, f"DNS checks skipped: the DNS resolver returned {why}",
              a.error or f"A: {a.rcode}, AAAA: {aaaa.rcode}, SOA: {soa.rcode}")
        return f, facts
    if aaaa.rrset:
        f.ok("dns.ipv6", "Reachable over IPv6", evidence=", ".join(aaaa.rrset[:3]))
    else:
        f.add("dns.ipv6", Severity.INFO, "No IPv6 (AAAA) address", "IPv6-only clients and networks cannot connect directly.")

    # --- dangling CNAME / takeover ---
    for name in dict.fromkeys([host, f"www.{domain}"]):
        cn = net.query(name, "CNAME")
        if not cn.rrset:
            continue
        target = cn.rrset[0].rstrip(".").lower()
        t_a = net.query(target, "A")
        t_aaaa = net.query(target, "AAAA")
        provider = next((p for s, p in TAKEOVER_SUFFIXES.items() if s in "." + target), None)
        if t_a.nxdomain and not t_aaaa.rrset:
            f.add("dns.dangling_cname", Severity.CRITICAL if provider else Severity.HIGH,
                  f"Dangling CNAME: {name} points to a name that does not exist",
                  f"{name} is an alias for {target}, which returns NXDOMAIN." +
                  (f" On {provider}, anyone can usually claim that name and serve content on your domain "
                   "(subdomain takeover), including phishing pages and cookie theft." if provider else
                   " If the target domain or resource can be registered by someone else, they control this host."),
                  evidence=f"{name} CNAME {target} -> NXDOMAIN", fix="Delete the stale CNAME record.",
                  cap="F" if provider else "C", tags=["CWE-350"],
                  refs=["https://github.com/EdOverflow/can-i-take-over-xyz"])
        elif provider:
            facts.setdefault("cname_platforms", []).append({"name": name, "target": target, "platform": provider})

    # --- name servers ---
    ns = net.query(domain, "NS")
    facts["ns"] = ns.rrset
    if ns.rrset:
        nets = set()
        providers = set()
        for n in ns.rrset[:8]:
            n = n.rstrip(".")
            providers.add(registrable_domain(n))
            for ip in net.query(n, "A").rrset[:2]:
                nets.add(str(ipaddress.ip_network(ip + "/24", strict=False)))
        facts["ns_networks"] = sorted(nets)
        if len(ns.rrset) < 2:
            f.add("dns.single_ns", Severity.MEDIUM, "Only one name server", "If it fails, the whole domain disappears. "
                  "RFC 2182 asks for at least two on separate networks.", evidence=", ".join(ns.rrset))
        elif nets and len(nets) < 2:
            f.add("dns.ns_same_network", Severity.LOW, "All name servers are in the same /24 network",
                  "A single network outage or attack takes them all down.", evidence=", ".join(sorted(nets)))
        else:
            f.ok("dns.ns", f"{len(ns.rrset)} name servers" + (f" across {len(nets)} networks" if nets else ""),
                 evidence=", ".join(n.rstrip(".") for n in ns.rrset[:6]))

    # --- DNSSEC ---
    ds = dnssec.validate_chain(net, domain, anchors=dnssec_anchors)
    ad = net.query(domain, "SOA")
    ds.resolver_ad = ad.authenticated
    facts["dnssec"] = ds.to_dict()
    if ds.status == "secure":
        f.ok("dnssec.secure", "DNSSEC signed and validated from the root", ds.detail)
        for w in ds.weak_algorithms:
            f.add("dnssec.weak_alg", Severity.LOW, f"DNSSEC uses a deprecated algorithm ({w})",
                  "RFC 8624 deprecates RSA/SHA-1 for signing; move to ECDSA P-256 (13) or Ed25519 (15).")
    elif ds.status == "bogus":
        f.add("dnssec.bogus", Severity.CRITICAL, "DNSSEC is broken (validation fails)",
              "Validating resolvers (Google, Cloudflare, Quad9, most ISPs) return SERVFAIL, so the domain "
              "disappears for a large share of users. " + ds.detail,
              fix="Fix the key rollover or remove the DS record at the registrar.", cap="F")
    elif ds.status == "island":
        f.add("dnssec.island", Severity.MEDIUM, "DNSSEC keys published but no DS record at the parent", ds.detail,
              fix="Add the DS record at your registrar to complete the chain.", snippets=SNIPPETS["dnssec"])
    elif ds.status == "insecure":
        f.add("dnssec.unsigned", Severity.LOW, "DNSSEC not enabled",
              "DNS answers for the domain can be forged by cache poisoning or on-path attackers, redirecting users "
              "or mail. DNSSEC also enables DANE for mail servers.", evidence=ds.detail, snippets=SNIPPETS["dnssec"])
    else:
        f.add("dnssec.unknown", Severity.INFO, "DNSSEC status could not be determined", ds.detail)

    # --- CAA ---
    caa_name, caa = caa_lookup(net, host)
    facts["caa"] = {"name": caa_name, "records": caa}
    if not caa:
        f.add("caa.missing", Severity.LOW, "No CAA record",
              "CAA tells certificate authorities which of them may issue certificates for the domain, so a "
              "mis-issuance or social-engineering attempt at another CA is refused.", snippets=SNIPPETS["caa"],
              refs=["https://www.rfc-editor.org/rfc/rfc8659"])
    else:
        f.ok("caa.present", f"CAA restricts certificate issuance (at {caa_name})", evidence="; ".join(caa[:5]))
        for rep in cert_reports or []:
            issuer_org = rep.leaf.get("issuer_org") or rep.leaf.get("issuer")
            wildcard = any(n.startswith("*.") for n in rep.names)
            allowed = _caa_allows(caa, issuer_org, wildcard)
            if allowed is False:
                f.add("caa.mismatch", Severity.MEDIUM, "CAA does not authorise the CA that issued the current certificate",
                      f"The certificate comes from {issuer_org}, which is not in the CAA records. The next renewal "
                      "will be refused.", evidence="; ".join(caa[:5]))
                break
        if not any("iodef" in r for r in caa):
            f.add("caa.iodef", Severity.INFO, "CAA has no iodef contact",
                  "An iodef property lets CAs report refused issuance attempts to you.")

    return f, facts


def mail_servers(net: Network, domain: str, check_smtp: bool = True) -> tuple[Findings, dict, list[str], bool]:
    """MX lookup plus a STARTTLS handshake with the first two mail servers."""
    f = Findings("email")
    facts: dict = {}
    mx = net.query(domain, "MX")
    mx_hosts: list[str] = []
    null_mx = False
    for r in mx.rrset:
        parts = r.split()
        if len(parts) == 2:
            if parts[1] == ".":
                null_mx = True
            else:
                mx_hosts.append(parts[1].rstrip(".").lower())
    facts["mx"] = mx_hosts
    facts["null_mx"] = null_mx
    if check_smtp and mx_hosts:
        results = [smtp_starttls(net, h) for h in mx_hosts[:2]]
        facts["smtp"] = [r.__dict__ for r in results]
        reachable = [r for r in results if r.error is None or r.starttls is not None]
        if not reachable:
            f.add("smtp.untested", Severity.INFO, "Mail servers could not be tested",
                  "Outbound port 25 is often blocked by hosting providers and ISPs; run the scan from a network "
                  "that allows it.", evidence="; ".join(f"{r.host}: {r.error}" for r in results), category="email")
        for r in reachable:
            if r.starttls is False:
                f.add("smtp.no_starttls", Severity.HIGH, f"Mail server {r.host} does not offer STARTTLS",
                      "Mail to this domain travels across the internet unencrypted.", category="email",
                      tags=["CWE-319"])
            elif r.starttls and r.cert_valid is False:
                f.add("smtp.cert", Severity.LOW, f"Mail server {r.host} has an invalid certificate",
                      "Opportunistic SMTP TLS still encrypts, but MTA-STS and DANE cannot be enforced.",
                      evidence=r.cert_error, category="email")
            elif r.starttls:
                f.ok("smtp.starttls", f"Mail server {r.host} supports STARTTLS" +
                     (f" ({r.tls_version})" if r.tls_version else ""), category="email")
        tlsa = net.query(f"_25._tcp.{mx_hosts[0]}", "TLSA")
        if tlsa.rrset:
            f.ok("smtp.dane", f"DANE TLSA records published for {mx_hosts[0]}", category="email")
    return f, facts, mx_hosts, null_mx
