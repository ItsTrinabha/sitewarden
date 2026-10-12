"""Certificate chain retrieval, path validation, revocation and hygiene checks."""

from __future__ import annotations

import datetime as dt
import hashlib
import ssl
import warnings
from dataclasses import dataclass, field
from functools import lru_cache

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID

from ..models import Findings, Severity
from ..net import Network

EV_OID = "2.23.140.1.1"
OV_OID = "2.23.140.1.2.2"
DV_OID = "2.23.140.1.2.1"
IV_OID = "2.23.140.1.2.3"
MUST_STAPLE_FEATURE = 5  # status_request
TLS_FEATURE_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.1.24")


@lru_cache(maxsize=1)
def trust_store_certs() -> tuple[x509.Certificate, ...]:
    import certifi

    with open(certifi.where(), "rb") as fh, warnings.catch_warnings():
        # a few Mozilla roots have non-positive serial numbers; cryptography warns but loads them
        warnings.simplefilter("ignore")
        return tuple(x509.load_pem_x509_certificates(fh.read()))


def _utc(d: dt.datetime) -> dt.datetime:
    return d if d.tzinfo else d.replace(tzinfo=dt.UTC)


def _name(n: x509.Name) -> str:
    cn = n.get_attributes_for_oid(NameOID.COMMON_NAME)
    org = n.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    if cn:
        return str(cn[0].value)
    if org:
        return str(org[0].value)
    return n.rfc4514_string()


def _org(n: x509.Name) -> str | None:
    org = n.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    return str(org[0].value) if org else None


def key_info(cert: x509.Certificate) -> tuple[str, int, str | None]:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size, None
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "ECDSA", pub.curve.key_size, pub.curve.name
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, None
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448", 456, None
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA", pub.key_size, None
    return type(pub).__name__, 0, None


def _ext(cert: x509.Certificate, oid):
    try:
        return cert.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None
    except ValueError:
        return None


def sans(cert: x509.Certificate) -> list[str]:
    ext = _ext(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    if not ext:
        return []
    out = [str(n) for n in ext.get_values_for_type(x509.DNSName)]
    out += [str(ip) for ip in ext.get_values_for_type(x509.IPAddress)]
    return out


def hostname_matches(host: str, names: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for name in names:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*.") and "." in host:
            suffix = name[1:]
            label, _, rest = host.partition(".")
            if label and "." + rest == suffix:
                return True
    return False


def aia_urls(cert: x509.Certificate, method) -> list[str]:
    ext = _ext(cert, ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
    if not ext:
        return []
    return [d.access_location.value for d in ext
            if d.access_method == method and isinstance(d.access_location, x509.UniformResourceIdentifier)]


def crl_urls(cert: x509.Certificate) -> list[str]:
    ext = _ext(cert, ExtensionOID.CRL_DISTRIBUTION_POINTS)
    out = []
    for dp in ext or []:
        for n in dp.full_name or []:
            if isinstance(n, x509.UniformResourceIdentifier):
                out.append(n.value)
    return out


def sct_count(cert: x509.Certificate) -> int:
    ext = _ext(cert, ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
    return len(list(ext)) if ext else 0


def validation_level(cert: x509.Certificate) -> str:
    ext = _ext(cert, ExtensionOID.CERTIFICATE_POLICIES)
    oids = {p.policy_identifier.dotted_string for p in ext} if ext else set()
    if EV_OID in oids:
        return "EV"
    if OV_OID in oids:
        return "OV"
    if IV_OID in oids:
        return "IV"
    if DV_OID in oids:
        return "DV"
    return "unknown"


def must_staple(cert: x509.Certificate) -> bool:
    ext = _ext(cert, TLS_FEATURE_OID)
    if ext is None:
        return False
    try:
        return any(int(f.value) == MUST_STAPLE_FEATURE for f in ext)
    except (TypeError, AttributeError):
        return True


def describe(cert: x509.Certificate, now: dt.datetime) -> dict:
    ktype, kbits, curve = key_info(cert)
    nb, na = _utc(cert.not_valid_before_utc), _utc(cert.not_valid_after_utc)
    sig = cert.signature_hash_algorithm.name.upper() if cert.signature_hash_algorithm else "none"
    return {
        "subject": _name(cert.subject),
        "subject_dn": cert.subject.rfc4514_string(),
        "issuer": _name(cert.issuer),
        "issuer_dn": cert.issuer.rfc4514_string(),
        "issuer_org": _org(cert.issuer),
        "serial": format(cert.serial_number, "x"),
        "not_before": nb.isoformat(),
        "not_after": na.isoformat(),
        "days_left": (na - now).days,
        "lifetime_days": (na - nb).days,
        "key": f"{ktype} {kbits}" + (f" ({curve})" if curve else ""),
        "key_type": ktype,
        "key_bits": kbits,
        "signature": f"{sig} with {cert.signature_algorithm_oid._name}",
        "sha256": hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),
        "spki_sha256": hashlib.sha256(cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest(),
        "self_signed": cert.issuer == cert.subject,
        "is_ca": bool((bc := _ext(cert, ExtensionOID.BASIC_CONSTRAINTS)) and bc.ca),
    }


@dataclass
class ChainReport:
    auth: str
    presented: list[dict] = field(default_factory=list)
    leaf: dict = field(default_factory=dict)
    names: list[str] = field(default_factory=list)
    trusted: bool = False
    trust_error: str | None = None
    path: list[str] = field(default_factory=list)
    aia_fetched: bool = False
    hostname_ok: bool = False
    validation: str = "unknown"
    scts: int = 0
    must_staple: bool = False
    ocsp_urls: list[str] = field(default_factory=list)
    crl_urls: list[str] = field(default_factory=list)
    revocation: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class LocalHandshake:
    version: str | None = None
    cipher: str | None = None
    alpn: str | None = None
    chain: list[bytes] = field(default_factory=list)
    error: str | None = None


def local_handshake(net: Network, host: str, ip: str, port: int, timeout: float = 8.0) -> LocalHandshake:
    """A normal handshake through the local TLS stack: ALPN, and the chain for TLS 1.3-only servers."""
    out = LocalHandshake()
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
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    try:
        raw = net.connect(ip, port, timeout)
    except OSError as exc:
        out.error = str(exc)
        return out
    try:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            out.version = s.version()
            out.cipher = (s.cipher() or (None,))[0]
            out.alpn = s.selected_alpn_protocol()
            getter = getattr(s, "get_unverified_chain", None)
            if getter:
                chain = getter() or []
                out.chain = [c if isinstance(c, bytes) else c.public_bytes(ssl.ENCODING_DER) for c in chain]
            if not out.chain:
                der = s.getpeercert(binary_form=True)
                out.chain = [der] if der else []
    except (ssl.SSLError, OSError) as exc:
        out.error = str(exc)
    finally:
        try:
            raw.close()
        except OSError:
            pass
    return out


def _verify(leaf: x509.Certificate, intermediates: list[x509.Certificate], host: str | None,
            now: dt.datetime, extra_roots: list[bytes] | None = None) -> tuple[bool, str | None, list[x509.Certificate]]:
    from cryptography.x509.verification import DNSName, IPAddress, PolicyBuilder, Store, VerificationError

    roots = list(trust_store_certs())
    for pem in extra_roots or []:
        roots.extend(x509.load_pem_x509_certificates(pem))
    store = Store(roots)
    builder = PolicyBuilder().store(store).time(now.replace(tzinfo=None)).max_chain_depth(8)
    try:
        import ipaddress

        subject = IPAddress(ipaddress.ip_address(host)) if host and _is_ip(host) else DNSName(host or "invalid.example")
        verifier = builder.build_server_verifier(subject)
        chain = verifier.verify(leaf, intermediates)
        return True, None, list(chain)
    except VerificationError as exc:
        return False, str(exc), []
    except Exception as exc:  # malformed certificates make the verifier raise other errors
        return False, f"{exc.__class__.__name__}: {exc}", []


def _is_ip(h: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def _friendly_error(msg: str | None) -> str:
    if not msg:
        return "unknown reason"
    m = msg.lower()
    if "candidates exhausted" in m or "no valid" in m or "issuer" in m and "not found" in m:
        return "no path to a trusted root certificate (unknown, private or missing issuer)"
    if "expired" in m or "not valid after" in m or "validity" in m:
        return "a certificate in the chain is outside its validity period"
    return msg


def _fetch_aia(net: Network, cert: x509.Certificate) -> list[x509.Certificate]:
    from ..http.client import fetch

    out = []
    for url in aia_urls(cert, AuthorityInformationAccessOID.CA_ISSUERS)[:2]:
        r = fetch(net, url, max_body=256 * 1024, timeout=8, headers={"Accept": "*/*"})
        if not r.ok or r.status != 200:
            continue
        try:
            out.append(x509.load_der_x509_certificate(r.body))
            continue
        except ValueError:
            pass
        try:
            out.extend(x509.load_pem_x509_certificates(r.body))
        except ValueError:
            pass
    return out


def check_ocsp(net: Network, leaf: x509.Certificate, issuer: x509.Certificate, url: str) -> dict:
    from cryptography.x509 import ocsp

    from ..http.client import fetch

    req = ocsp.OCSPRequestBuilder().add_certificate(leaf, issuer, hashes.SHA1()).build()
    r = fetch(net, url, method="POST", body=req.public_bytes(serialization.Encoding.DER),
              headers={"Content-Type": "application/ocsp-request", "Accept": "application/ocsp-response"},
              max_body=64 * 1024, timeout=8)
    if not r.ok or r.status != 200:
        return {"method": "OCSP", "status": "error", "detail": r.error or f"HTTP {r.status}", "url": url}
    try:
        resp = ocsp.load_der_ocsp_response(r.body)
    except ValueError as exc:
        return {"method": "OCSP", "status": "error", "detail": f"unparseable response: {exc}", "url": url}
    return _ocsp_summary(resp, url)


def _ocsp_summary(resp, url: str | None = None) -> dict:
    from cryptography.x509 import ocsp

    if resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return {"method": "OCSP", "status": "error", "detail": resp.response_status.name, "url": url}
    status = resp.certificate_status.name.lower()
    out = {"method": "OCSP", "status": status, "url": url,
           "produced_at": _utc(resp.produced_at_utc).isoformat(),
           "next_update": _utc(resp.next_update_utc).isoformat() if resp.next_update_utc else None}
    if resp.certificate_status == ocsp.OCSPCertStatus.REVOKED:
        out["revoked_at"] = _utc(resp.revocation_time_utc).isoformat() if resp.revocation_time_utc else None
        out["reason"] = resp.revocation_reason.name if resp.revocation_reason else None
    return out


def check_crl(net: Network, leaf: x509.Certificate, issuer: x509.Certificate, url: str) -> dict:
    from ..http.client import fetch

    r = fetch(net, url, max_body=20 * 1024 * 1024, timeout=15, headers={"Accept": "*/*"})
    if not r.ok or r.status != 200:
        return {"method": "CRL", "status": "error", "detail": r.error or f"HTTP {r.status}", "url": url}
    try:
        crl = x509.load_der_x509_crl(r.body)
    except ValueError:
        try:
            crl = x509.load_pem_x509_crl(r.body)
        except ValueError as exc:
            return {"method": "CRL", "status": "error", "detail": f"unparseable CRL: {exc}", "url": url}
    try:
        sig_ok = crl.is_signature_valid(issuer.public_key())
    except Exception:
        sig_ok = False
    if not sig_ok:
        return {"method": "CRL", "status": "error", "detail": "CRL signature did not verify against the issuer", "url": url}
    entry = crl.get_revoked_certificate_by_serial_number(leaf.serial_number)
    out = {"method": "CRL", "url": url, "entries": len(crl),
           "next_update": _utc(crl.next_update_utc).isoformat() if crl.next_update_utc else None}
    if entry is None:
        out["status"] = "good"
    else:
        out["status"] = "revoked"
        out["revoked_at"] = _utc(entry.revocation_date_utc).isoformat()
    return out


def analyze_chain(net: Network, host: str, auth: str, ders: list[bytes], now: dt.datetime,
                  check_revocation: bool = True) -> ChainReport:
    rep = ChainReport(auth=auth)
    certs = []
    for der in ders:
        try:
            certs.append(x509.load_der_x509_certificate(der))
        except ValueError:
            continue
    if not certs:
        rep.trust_error = "no parseable certificate"
        return rep
    leaf = certs[0]
    rep.presented = [describe(c, now) for c in certs]
    rep.leaf = rep.presented[0]
    rep.names = sans(leaf)
    if not rep.names:
        cn = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        rep.names = [str(cn[0].value)] if cn else []
    rep.hostname_ok = hostname_matches(host, rep.names)
    rep.validation = validation_level(leaf)
    rep.scts = sct_count(leaf)
    rep.must_staple = must_staple(leaf)
    rep.ocsp_urls = aia_urls(leaf, AuthorityInformationAccessOID.OCSP)
    rep.crl_urls = crl_urls(leaf)

    # Evaluate trust independently of the host name so both problems can be reported.
    subject_for_trust = host if rep.hostname_ok else next((n for n in rep.names if "*" not in n), None)
    if subject_for_trust is None and rep.names:
        subject_for_trust = rep.names[0].replace("*.", "wildcard.")
    ok, err, path = _verify(leaf, certs[1:], subject_for_trust, now, net.extra_roots)
    if not ok:
        extra = _fetch_aia(net, certs[-1])
        if extra:
            ok2, err2, path2 = _verify(leaf, certs[1:] + extra, subject_for_trust, now, net.extra_roots)
            if ok2:
                ok, err, path = ok2, None, path2
                rep.aia_fetched = True
    rep.trusted = ok
    rep.trust_error = None if ok else _friendly_error(err)
    rep.path = [_name(c.subject) for c in path]

    if check_revocation and len(path) >= 2:
        issuer = path[1]
        rev = None
        for url in rep.ocsp_urls[:1]:
            rev = check_ocsp(net, leaf, issuer, url)
        if (rev is None or rev.get("status") == "error") and rep.crl_urls:
            rev = check_crl(net, leaf, issuer, rep.crl_urls[0])
        rep.revocation = rev or {"status": "not checked", "detail": "certificate lists no OCSP or CRL location"}
    return rep


def stapled_status(der: bytes | None) -> dict | None:
    if not der:
        return None
    from cryptography.x509 import ocsp

    try:
        return _ocsp_summary(ocsp.load_der_ocsp_response(der))
    except ValueError as exc:
        return {"method": "OCSP (stapled)", "status": "error", "detail": str(exc)}


def evaluate(net: Network, host: str, chains: dict[str, list[bytes]], *, ocsp_stapled: bool | None,
             stapled_der: bytes | None, sct_in_tls: bool | None, now: dt.datetime | None = None,
             check_revocation: bool = True) -> tuple[list[ChainReport], Findings]:
    now = now or dt.datetime.now(dt.UTC)
    f = Findings("certificate")
    reports = [analyze_chain(net, host, auth, ders, now, check_revocation) for auth, ders in chains.items() if ders]
    if not reports:
        f.add("cert.missing", Severity.CRITICAL, "No certificate could be retrieved",
              "The server completed no handshake that revealed a certificate.", cap="F")
        return reports, f

    multi = len(reports) > 1
    for rep in reports:
        label = f" ({rep.auth} certificate)" if multi else ""
        leaf = rep.leaf
        days = leaf["days_left"]
        not_before = dt.datetime.fromisoformat(leaf["not_before"])
        if days < 0:
            f.add("cert.expired", Severity.CRITICAL, f"Certificate expired {-days} days ago{label}",
                  "Every browser shows a full-page warning; visitors cannot reach the site safely.",
                  evidence=f"notAfter = {leaf['not_after']}",
                  fix="Renew the certificate and automate renewal (ACME / certbot / your CDN).",
                  cap="F", tags=["CWE-298"])
        elif not_before > now:
            f.add("cert.not_yet_valid", Severity.CRITICAL, f"Certificate is not valid yet{label}",
                  evidence=f"notBefore = {leaf['not_before']}", cap="F",
                  fix="Check the server clock and the certificate issue date.")
        elif days <= 7:
            f.add("cert.expiring", Severity.HIGH, f"Certificate expires in {days} days{label}",
                  "Renewal looks stuck: automated renewals normally happen 30 days before expiry.",
                  evidence=f"notAfter = {leaf['not_after']}", fix="Renew now and check the renewal job's logs.")
        elif days <= 21:
            f.add("cert.expiring", Severity.MEDIUM, f"Certificate expires in {days} days{label}",
                  "Automated renewal normally happens well before this point.",
                  evidence=f"notAfter = {leaf['not_after']}", fix="Confirm renewal is scheduled.")
        else:
            f.ok("cert.validity", f"Certificate valid for another {days} days{label}",
                 evidence=f"{leaf['not_before'][:10]} to {leaf['not_after'][:10]}")

        if not rep.hostname_ok:
            f.add("cert.hostname", Severity.CRITICAL, f"Certificate does not cover {host}{label}",
                  "Browsers reject the connection with a name-mismatch error.",
                  evidence="Certificate names: " + ", ".join(rep.names[:12]) + (" ..." if len(rep.names) > 12 else ""),
                  fix=f"Issue a certificate whose Subject Alternative Names include {host}.", cap="F",
                  tags=["CWE-297"])
        else:
            f.ok("cert.hostname", f"Certificate covers {host}{label}",
                 evidence=f"{len(rep.names)} name(s): " + ", ".join(rep.names[:6]))

        if not rep.trusted:
            if leaf["self_signed"]:
                title = f"Self-signed certificate{label}"
            else:
                title = f"Certificate is not trusted{label}"
            f.add("cert.untrusted", Severity.CRITICAL, title,
                  f"Validation against the Mozilla root store failed: {rep.trust_error}. Browsers will show a "
                  "security warning, and users trained to click through warnings can be intercepted.",
                  evidence="Presented chain: " + " -> ".join(c["subject"] for c in rep.presented),
                  fix="Use a certificate from a publicly trusted CA (Let's Encrypt is free) and serve the full chain.",
                  cap="F", tags=["CWE-295"])
        elif rep.aia_fetched:
            f.add("cert.incomplete_chain", Severity.MEDIUM, f"Incomplete certificate chain{label}",
                  "The server does not send the intermediate certificate. Desktop browsers can fetch it themselves "
                  "(AIA), but curl, Python, Java, Go, Android apps and many API clients fail with a trust error.",
                  evidence="Sent: " + " -> ".join(c["subject"] for c in rep.presented) +
                  " | Trusted path: " + " -> ".join(rep.path),
                  fix="Configure the full chain file (leaf + intermediates), e.g. fullchain.pem with certbot.",
                  snippets=_snip("fullchain"), cap="B")
        else:
            f.ok("cert.trusted", f"Trusted by the Mozilla root store{label}",
                 evidence=" -> ".join(rep.path))
            sent_root = any(c["self_signed"] for c in rep.presented[1:])
            if sent_root:
                f.add("cert.chain_root", Severity.INFO, "Server also sends the root certificate",
                      "Harmless but wasteful: clients already hold their roots, so it only adds handshake bytes.")
            subjects = [c["subject"] for c in rep.presented]
            issuers = [c["issuer"] for c in rep.presented]
            if len(subjects) > 1 and any(issuers[i] != subjects[i + 1] for i in range(len(subjects) - 1)):
                f.add("cert.chain_order", Severity.LOW, "Certificate chain is out of order or has extra certificates",
                      "Strict clients may fail. Each certificate should be followed by its issuer.",
                      evidence=" | ".join(f"{s} <- {i}" for s, i in zip(subjects, issuers, strict=True)))

        # key and signature
        kt, kb = leaf["key_type"], leaf["key_bits"]
        if kt == "RSA" and kb < 1024 or kt == "DSA":
            f.add("cert.key", Severity.CRITICAL, f"Certificate key is breakable ({leaf['key']}){label}", cap="F",
                  fix="Reissue with RSA 2048+ or ECDSA P-256.", tags=["CWE-326"])
        elif kt == "RSA" and kb < 2048:
            f.add("cert.key", Severity.HIGH, f"Weak certificate key ({leaf['key']}){label}",
                  "1024-bit RSA has been within reach of well-funded attackers for years and is no longer issued by "
                  "public CAs.", cap="B", fix="Reissue with RSA 2048+ or ECDSA P-256.", tags=["CWE-326"])
        elif kt == "ECDSA" and kb < 256:
            f.add("cert.key", Severity.HIGH, f"Weak certificate key ({leaf['key']}){label}", cap="B",
                  tags=["CWE-326"])
        else:
            f.ok("cert.key", f"Strong certificate key: {leaf['key']}{label}")
        if leaf["signature"].startswith(("SHA1", "MD5", "MD2")):
            f.add("cert.signature", Severity.HIGH, f"Certificate signed with a broken hash ({leaf['signature']}){label}",
                  "SHA-1 collisions are practical (SHAttered, 2017); browsers reject SHA-1 leaf certificates.",
                  cap="C", fix="Reissue the certificate; every public CA signs with SHA-256 or better.")
        for c in rep.presented[1:]:
            if not c["self_signed"] and c["signature"].startswith(("SHA1", "MD5")):
                f.add("cert.chain_signature", Severity.MEDIUM, f"Intermediate {c['subject']} uses {c['signature']}",
                      "Update the chain your server sends.")

        # lifetime rules (CA/Browser Forum baseline requirements)
        lifetime = leaf["lifetime_days"]
        if rep.trusted and not_before >= dt.datetime(2020, 9, 1, tzinfo=dt.UTC) and lifetime > 398:
            f.add("cert.lifetime", Severity.HIGH, f"Certificate lifetime of {lifetime} days exceeds 398",
                  "Apple, Google and Mozilla reject publicly trusted TLS certificates valid for more than 398 days.",
                  cap="C")

        # certificate transparency
        if rep.trusted and rep.validation != "unknown" and rep.scts == 0 and not sct_in_tls:
            f.add("cert.ct", Severity.MEDIUM, "No Certificate Transparency proof found",
                  "Chrome and Safari require SCTs for publicly trusted certificates. None are embedded, and none "
                  "came in the TLS extension. They may still arrive in a stapled OCSP response.")
        elif rep.scts:
            f.ok("cert.ct", f"Logged in Certificate Transparency ({rep.scts} embedded SCTs)")

        # revocation
        rev = rep.revocation
        if rev.get("status") == "revoked":
            f.add("cert.revoked", Severity.CRITICAL, f"Certificate has been revoked{label}",
                  f"The CA reports this certificate as revoked ({rev.get('reason') or 'no reason given'}).",
                  evidence=f"{rev.get('method')} {rev.get('url') or ''} revoked at {rev.get('revoked_at')}",
                  cap="F", fix="Deploy a newly issued certificate.")
        elif rev.get("status") == "good":
            f.ok("cert.revocation", f"Not revoked (checked via {rev.get('method')})", evidence=rev.get("url"))
        elif rev.get("status") == "error":
            f.add("cert.revocation", Severity.INFO, "Revocation status could not be checked",
                  evidence=f"{rev.get('method')}: {rev.get('detail')}")

        if rep.must_staple and not ocsp_stapled:
            f.add("cert.must_staple", Severity.HIGH, "Certificate requires OCSP stapling but none was stapled",
                  "Firefox hard-fails OCSP Must-Staple certificates when no stapled response is sent.",
                  fix="Enable OCSP stapling (nginx: ssl_stapling on;) or reissue without Must-Staple.", cap="C")

    # facts that hold for the whole host
    rep = reports[0]
    if multi:
        f.add("cert.dual", Severity.PASS, "Serves both " + " and ".join(r.auth for r in reports) + " certificates",
              "Modern clients get the faster ECDSA certificate while legacy clients still connect.")
    level = rep.validation
    if level in ("EV", "OV"):
        f.add("cert.validation", Severity.INFO, f"{level} certificate",
              f"Issued after {'extended ' if level == 'EV' else ''}organization validation of {rep.leaf.get('subject_dn')}.")
    if any(n.startswith("*.") for n in rep.names):
        f.add("cert.wildcard", Severity.INFO, "Wildcard certificate",
              "One private key protects every subdomain it covers, so a compromise of any server holding it "
              "exposes all of them. Prefer per-service certificates where practical.")
    stapled = stapled_status(stapled_der)
    if stapled:
        rep.revocation.setdefault("stapled", stapled)
    if ocsp_stapled:
        f.ok("cert.ocsp_stapling", "OCSP stapling enabled", evidence=(stapled or {}).get("status"))
    elif ocsp_stapled is False and rep.ocsp_urls:
        f.add("cert.ocsp_stapling", Severity.LOW, "OCSP stapling not enabled",
              "Without stapling, clients that check revocation contact the CA themselves, which is slower and "
              "tells the CA who visits the site.",
              fix="Enable OCSP stapling.", snippets=_snip("ocsp_stapling"))
    return reports, f


def _snip(key: str) -> dict[str, str]:
    from ..remediation import SNIPPETS

    return SNIPPETS.get(key, {})
