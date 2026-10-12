"""Turn raw TLS probe results into findings, vulnerability verdicts and profile compliance."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources

from ..models import Findings, Severity
from . import ciphers as C
from .scanner import TLSScan
from .wire import GROUPS, PQ_GROUPS

MOZILLA_CURVE_NAMES = {"prime256v1": "secp256r1", "secp384r1": "secp384r1", "X25519": "x25519",
                       "X25519MLKEM768": "X25519MLKEM768", "secp521r1": "secp521r1"}


@lru_cache(maxsize=1)
def mozilla_guidelines() -> dict:
    data = resources.files("sitewarden.data").joinpath("mozilla-guidelines.json").read_text()
    return json.loads(data)


def _names(codes) -> str:
    return ", ".join(C.get(c).name for c in codes)


def _snip(key: str) -> dict[str, str]:
    from ..remediation import SNIPPETS

    return SNIPPETS.get(key, {})


def analyze(scan: TLSScan) -> Findings:
    f = Findings("tls")
    p = scan.protocols
    all_suites = scan.all_ciphers()
    suites = [C.get(c) for c in all_suites]

    # ---- protocol versions ----
    if p.get(C.SSL2):
        f.add("tls.sslv2", Severity.CRITICAL, "SSL 2.0 is enabled (DROWN)",
              "SSL 2.0 has been broken since 1996. DROWN (CVE-2016-0800) lets an attacker use an SSLv2 server to "
              "decrypt TLS sessions that share its RSA key.",
              fix="Disable SSL 2.0 entirely.", cap="F", tags=["CVE-2016-0800", "CWE-327"],
              refs=["https://drownattack.com/"])
    if p.get(C.SSL3):
        cbc3 = [c for c in scan.ciphers.get(C.SSL3, []) if C.get(c).cbc]
        f.add("tls.sslv3", Severity.HIGH, "SSL 3.0 is enabled" + (" (POODLE)" if cbc3 else ""),
              "SSL 3.0 is obsolete (RFC 7568). With CBC suites it is open to POODLE (CVE-2014-3566), which recovers "
              "secrets such as session cookies byte by byte.",
              fix="Disable SSL 3.0.", snippets=_snip("protocols"), cap="C",
              tags=["CVE-2014-3566", "CWE-327"])
    old = [n for v, n in ((C.TLS10, "TLS 1.0"), (C.TLS11, "TLS 1.1")) if p.get(v)]
    if old:
        f.add("tls.legacy_protocols", Severity.MEDIUM, f"{' and '.join(old)} enabled",
              "These versions are deprecated by RFC 8996, rely on MD5/SHA-1 in the handshake, and are banned for "
              "cardholder data by PCI DSS. Every browser removed support in 2020.",
              fix="Allow only TLS 1.2 and TLS 1.3.", snippets=_snip("protocols"), cap="B",
              tags=["CWE-327", "PCI-DSS 4.2.1"], refs=["https://www.rfc-editor.org/rfc/rfc8996"])
    if p.get(C.TLS13):
        f.ok("tls.tls13", "TLS 1.3 supported",
             "TLS 1.3 removes legacy algorithms, always uses forward secrecy, and encrypts most of the handshake.")
    else:
        f.add("tls.tls13", Severity.LOW, "TLS 1.3 not supported",
              "TLS 1.3 is faster (one round trip) and drops every legacy algorithm. All current browsers use it.",
              fix="Enable TLS 1.3 (OpenSSL 1.1.1+, nginx 1.13+).", snippets=_snip("protocols"), cap="A-")
    if p.get(C.TLS12):
        f.ok("tls.tls12", "TLS 1.2 supported")
    elif p.get(C.TLS13):
        f.add("tls.tls13_only", Severity.INFO, "Only TLS 1.3 is offered",
              "The strictest choice. Clients older than roughly 2018 (Android 9, Java 8, Windows 10 before 2021) "
              "cannot connect.")
    if not old and not p.get(C.SSL3) and not p.get(C.SSL2):
        f.ok("tls.no_legacy", "No deprecated protocol versions (SSL 2/3, TLS 1.0/1.1)")

    # ---- cipher suites ----
    export = [s.code for s in suites if s.export]
    null_anon = [s.code for s in suites if s.null_cipher or s.anonymous]
    rc4 = [s.code for s in suites if s.rc4]
    des = [s.code for s in suites if s.cipher.startswith("DES") or "RC2" in s.cipher]
    triple = [s.code for s in suites if s.cipher.startswith("3DES") or s.cipher.startswith("IDEA")]
    md5 = [s.code for s in suites if s.mac == "MD5" and not s.rc4]
    if export:
        f.add("tls.export", Severity.CRITICAL, "Export-grade cipher suites accepted (FREAK)",
              "40- and 56-bit export suites from the 1990s can be broken in hours. FREAK (CVE-2015-0204) and "
              "Logjam downgrade clients to them.",
              evidence=_names(export), fix="Remove all EXPORT suites.", snippets=_snip("ciphers"), cap="F",
              tags=["CVE-2015-0204", "CWE-327"])
    if null_anon:
        f.add("tls.null_anon", Severity.CRITICAL, "NULL or anonymous cipher suites accepted",
              "NULL suites send traffic unencrypted; anonymous suites skip server authentication, so anyone in the "
              "middle can impersonate the site.", evidence=_names(null_anon), cap="F", snippets=_snip("ciphers"),
              tags=["CWE-319"])
    if rc4:
        f.add("tls.rc4", Severity.HIGH, "RC4 cipher suites accepted",
              "RC4 keystream biases allow plaintext recovery (RFC 7465 prohibits RC4).",
              evidence=_names(rc4), fix="Remove RC4 suites.", snippets=_snip("ciphers"), cap="C",
              tags=["CVE-2013-2566", "CVE-2015-2808", "CWE-327"])
    if des:
        f.add("tls.des", Severity.HIGH, "DES or RC2 cipher suites accepted",
              "Single DES has a 56-bit key and can be brute-forced.", evidence=_names(des), cap="C",
              snippets=_snip("ciphers"), tags=["CWE-327"])
    if triple:
        f.add("tls.sweet32", Severity.MEDIUM, "64-bit block ciphers accepted (SWEET32)",
              "3DES and IDEA use 64-bit blocks; birthday collisions on long-lived connections leak plaintext "
              "(CVE-2016-2183).", evidence=_names(triple), fix="Remove 3DES/IDEA suites.",
              snippets=_snip("ciphers"), cap="B", tags=["CVE-2016-2183"])
    if md5:
        f.add("tls.md5", Severity.MEDIUM, "Cipher suites with MD5 MACs accepted", evidence=_names(md5), cap="B")

    non_fs = [s for s in suites if not s.forward_secret and not s.anonymous and not s.null_cipher]
    fs = [s for s in suites if s.forward_secret]
    if suites and not fs:
        f.add("tls.no_fs", Severity.HIGH, "No forward secrecy",
              "Every suite uses static RSA key exchange: anyone who later obtains the private key (breach, "
              "subpoena, cloud snapshot) can decrypt all recorded past traffic.",
              fix="Offer ECDHE suites.", snippets=_snip("ciphers"), cap="B", tags=["CWE-327"])
    elif non_fs:
        best = max((v for v in scan.ciphers if v != C.TLS13), default=None)
        preferred_non_fs = False
        if best is not None and scan.server_preference.get(best) and scan.ciphers.get(best):
            preferred_non_fs = not C.get(scan.ciphers[best][0]).forward_secret
        f.add("tls.partial_fs", Severity.MEDIUM if preferred_non_fs else Severity.LOW,
              "Some cipher suites lack forward secrecy" + (" and the server prefers one" if preferred_non_fs else ""),
              "Static-RSA suites (TLS_RSA_*) let a stolen private key decrypt recorded sessions. Modern clients "
              "negotiate ECDHE, but the RSA suites remain available to downgrade-prone or misconfigured clients.",
              evidence=_names([s.code for s in non_fs][:8]) + (" ..." if len(non_fs) > 8 else ""),
              fix="Drop TLS_RSA_* suites.", snippets=_snip("ciphers"), cap="B" if preferred_non_fs else None)
    elif suites:
        f.ok("tls.fs", "Forward secrecy with every cipher suite")

    cbc12 = [c for c in scan.ciphers.get(C.TLS12, []) if C.get(c).cbc]
    if cbc12 and scan.supported(C.TLS12):
        f.add("tls.cbc", Severity.LOW, f"{len(cbc12)} CBC-mode suites offered with TLS 1.2",
              "CBC with MAC-then-encrypt has a long history of padding-oracle bugs (Lucky13, POODLE-TLS, "
              "GOLDENDOODLE). Mozilla's Intermediate profile uses AEAD suites only.",
              evidence=_names(cbc12[:6]) + (" ..." if len(cbc12) > 6 else ""),
              fix="Offer only AES-GCM and ChaCha20-Poly1305 suites.", snippets=_snip("ciphers"))
    if p.get(C.TLS10) and any(C.get(c).cbc for c in scan.ciphers.get(C.TLS10, [])):
        f.add("tls.beast", Severity.INFO, "TLS 1.0 with CBC suites (BEAST)",
              "BEAST (CVE-2011-3389) is mitigated in every modern browser by record splitting; it is listed for "
              "completeness.", tags=["CVE-2011-3389"])
    if suites and not any([export, null_anon, rc4, des, triple, md5]):
        f.ok("tls.no_weak_ciphers", "No insecure cipher suites (export, NULL, anonymous, RC4, DES, 3DES)")

    # ---- key exchange ----
    dh = {c: b for c, b in scan.dh_bits.items()}
    if dh:
        weakest = min(dh.values())
        if weakest < 1024:
            f.add("tls.logjam", Severity.CRITICAL, f"Breakable Diffie-Hellman group ({weakest} bits, Logjam)",
                  "DH groups under 1024 bits can be broken in real time by academic teams (CVE-2015-4000).",
                  fix="Use a 2048-bit (ffdhe2048) or larger group, or drop DHE suites.", snippets=_snip("dhparam"),
                  cap="F", tags=["CVE-2015-4000"])
        elif weakest < 2048:
            f.add("tls.weak_dh", Severity.MEDIUM, f"Weak Diffie-Hellman group ({weakest} bits)",
                  "1024-bit DH is within reach of nation-state attackers who precompute against common primes "
                  "(Logjam paper, 2015).", fix="Use ffdhe2048 or larger, or drop DHE suites.",
                  snippets=_snip("dhparam"), cap="B", tags=["CVE-2015-4000"])
    pq = [g for g in scan.groups if g in PQ_GROUPS]
    if pq:
        f.ok("tls.pq", "Post-quantum key exchange supported (" + ", ".join(GROUPS[g] for g in pq) + ")",
             "Hybrid ML-KEM key exchange protects today's traffic against 'harvest now, decrypt later' attacks by "
             "future quantum computers.")
    elif scan.supported(C.TLS13):
        f.add("tls.pq", Severity.INFO, "No post-quantum key exchange",
              "Chrome, Firefox, Safari and Edge already offer the hybrid X25519MLKEM768 group. Recorded traffic "
              "could be decrypted once large quantum computers exist ('harvest now, decrypt later').",
              fix="Upgrade to OpenSSL 3.5+, BoringSSL or a CDN that enables X25519MLKEM768.",
              snippets=_snip("pq"))
    weak_groups = [g for g in scan.groups + scan.groups_tls12 if g in (0x0013, 0x0015)]
    if weak_groups:
        f.add("tls.weak_curves", Severity.LOW, "Small elliptic curves accepted",
              evidence=", ".join(sorted({GROUPS[g] for g in weak_groups})))
    if scan.groups:
        top = GROUPS.get(scan.groups[0], hex(scan.groups[0]))
        f.add("tls.groups", Severity.INFO, f"Key exchange groups: {', '.join(GROUPS.get(g, hex(g)) for g in scan.groups)}",
              f"Most preferred: {top}.")

    # ---- features & legacy vulnerabilities ----
    legacy_ok = any(p.get(v) for v in (C.TLS12, C.TLS11, C.TLS10, C.SSL3))
    if scan.compression:
        f.add("tls.crime", Severity.HIGH, "TLS compression enabled (CRIME)",
              "Compressing secrets alongside attacker-controlled data leaks them through ciphertext length "
              "(CVE-2012-4929).", cap="C", tags=["CVE-2012-4929"])
    if legacy_ok and scan.secure_renegotiation is False:
        f.add("tls.renegotiation", Severity.HIGH, "Secure renegotiation (RFC 5746) not supported",
              "Servers without the renegotiation_info extension are exposed to the 2009 renegotiation injection "
              "attack (CVE-2009-3555) if renegotiation is allowed.", cap="C", tags=["CVE-2009-3555"])
    elif legacy_ok and scan.secure_renegotiation:
        f.ok("tls.renegotiation", "Secure renegotiation supported")
    if scan.supported(C.TLS12) and scan.extended_master_secret is False:
        f.add("tls.ems", Severity.LOW, "Extended Master Secret not supported",
              "RFC 7627 binds the session keys to the full handshake and closes the triple-handshake attack.")
    if scan.fallback_scsv is False and (old or p.get(C.SSL3)):
        f.add("tls.fallback_scsv", Severity.MEDIUM, "No downgrade protection (TLS_FALLBACK_SCSV)",
              "The server accepted a downgraded retry carrying TLS_FALLBACK_SCSV. Combined with the older versions "
              "it still enables, an attacker can force clients down to them.", cap="B",
              refs=["https://www.rfc-editor.org/rfc/rfc7507"])
    elif scan.fallback_scsv:
        f.ok("tls.fallback_scsv", "Downgrade protection (TLS_FALLBACK_SCSV) works")
    if scan.supported(C.TLS13) and scan.downgrade_sentinel is False:
        f.add("tls.downgrade_sentinel", Severity.LOW, "TLS 1.3 downgrade sentinel missing",
              "A TLS 1.3 server must mark TLS 1.2 ServerHellos with the DOWNGRD value (RFC 8446 4.1.3) so clients "
              "can detect forced downgrades.")
    if scan.heartbeat:
        f.add("tls.heartbeat", Severity.INFO, "TLS heartbeat extension enabled",
              "Heartbeat is unused by browsers and was the vector for Heartbleed (CVE-2014-0160). Sitewarden does "
              "not send heartbeat requests, so Heartbleed itself is not tested.", tags=["CVE-2014-0160"])
    pref = scan.server_preference.get(C.TLS12)
    weak_present = any(s.strength in ("weak", "insecure") for s in suites)
    if pref is False and weak_present:
        f.add("tls.client_preference", Severity.LOW, "Server follows client cipher order while weak suites exist",
              "With weak suites still enabled, the server should enforce its own (strong-first) order.",
              fix="Enable server cipher preference or remove the weak suites.", snippets=_snip("ciphers"))
    if scan.sni_required:
        f.add("tls.sni", Severity.INFO, "Server requires SNI", "Very old clients without SNI (Windows XP) cannot connect.")
    return f


def mozilla_compliance(scan: TLSScan, cert_reports) -> dict:
    """Which Mozilla server-side TLS profile (guidelines v6) the server satisfies, with reasons."""
    g = mozilla_guidelines()
    results = {}
    supported_versions = {C.PROTOCOL_NAMES[v].replace(" ", "v") for v, ok in scan.protocols.items() if ok}
    suites12 = {C.get(c).name for v in (C.TLS12, C.TLS11, C.TLS10, C.SSL3) for c in scan.ciphers.get(v, [])}
    suites13 = {C.get(c).name for c in scan.ciphers.get(C.TLS13, [])}
    groups = {GROUPS.get(x) for x in scan.groups + scan.groups_tls12}
    for profile in ("modern", "intermediate"):
        conf = g["configurations"][profile]
        problems = []
        allowed_versions = set(conf["tls_versions"])
        extra = supported_versions - allowed_versions
        if extra:
            problems.append("protocols not in profile: " + ", ".join(sorted(extra)))
        if "TLSv1.3" in allowed_versions and "TLSv1.3" not in supported_versions:
            problems.append("TLS 1.3 missing")
        bad12 = suites12 - set(conf["ciphers"]["iana"])
        if bad12:
            problems.append(f"{len(bad12)} TLS 1.2 suites outside the profile")
        bad13 = suites13 - set(conf["ciphersuites"])
        if bad13:
            problems.append("TLS 1.3 suites outside the profile: " + ", ".join(sorted(bad13)))
        allowed_groups = {MOZILLA_CURVE_NAMES.get(x, x) for x in conf["tls_curves"]}
        bad_groups = {x for x in groups if x and x not in allowed_groups and not x.startswith("ffdhe")}
        if bad_groups:
            problems.append("extra key exchange groups: " + ", ".join(sorted(bad_groups)))
        if conf.get("dh_param_size") and scan.dh_bits and min(scan.dh_bits.values()) < conf["dh_param_size"]:
            problems.append(f"DH parameters below {conf['dh_param_size']} bits")
        for rep in cert_reports:
            kt = rep.leaf.get("key_type", "").lower()
            if kt and kt not in conf["certificate_types"]:
                problems.append(f"{rep.leaf.get('key_type')} certificate not allowed")
            if kt == "rsa" and conf.get("rsa_key_size") and rep.leaf.get("key_bits", 0) < conf["rsa_key_size"]:
                problems.append(f"RSA key below {conf['rsa_key_size']} bits")
            if rep.leaf.get("lifetime_days", 0) > conf["maximum_certificate_lifespan"]:
                problems.append(f"certificate lifetime above {conf['maximum_certificate_lifespan']} days")
        results[profile] = {"compliant": not problems, "problems": problems,
                            "oldest_clients": conf.get("oldest_clients", [])}
    results["guidelines_version"] = g.get("version")
    return results
