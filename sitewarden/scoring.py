"""Grading: per-category scores, the overall letter grade, grade caps and compliance summaries."""

from __future__ import annotations

from .models import CATEGORIES, GRADES, Finding, Severity, worse_grade
from .tls import ciphers as C

WEIGHTS = {"tls": 22, "certificate": 20, "headers": 22, "cookies": 8, "content": 10, "dns": 8, "email": 10}
PENALTY = {Severity.CRITICAL: 60, Severity.HIGH: 30, Severity.MEDIUM: 15, Severity.LOW: 5,
           Severity.INFO: 0, Severity.PASS: 0}


def letter(score: float) -> str:
    if score >= 95:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 85:
        return "A-"
    if score >= 75:
        return "B"
    if score >= 65:
        return "C"
    if score >= 55:
        return "D"
    if score >= 45:
        return "E"
    return "F"


def grade(findings: list[Finding], skipped: set[str]) -> dict:
    cats = {}
    for cat, label in CATEGORIES.items():
        fs = [f for f in findings if f.category == cat]
        counts = {s.value: 0 for s in Severity}
        for x in fs:
            counts[x.severity.value] += 1
        if cat in skipped:
            cats[cat] = {"label": label, "score": None, "grade": None, "counts": counts, "skipped": True}
            continue
        score = max(0, 100 - sum(PENALTY[x.severity] for x in fs))
        cats[cat] = {"label": label, "score": score, "grade": letter(score), "counts": counts, "skipped": False}

    active = {c: w for c, w in WEIGHTS.items() if not cats[c]["skipped"]}
    total_w = sum(active.values()) or 1
    score = round(sum(cats[c]["score"] * w for c, w in active.items()) / total_w, 1)
    g = letter(score)
    caps = [f.cap for f in findings if f.cap]
    cap = None
    for c in caps:
        cap = worse_grade(cap, c)
    cap_reasons = [f.title for f in findings if f.cap and f.cap == cap]
    if cap and GRADES.index(cap) > GRADES.index(g):
        g = cap
    else:
        cap_reasons = []
    # A+ is reserved for sites with no medium-or-worse issues anywhere.
    serious = [f for f in findings if f.severity.rank >= Severity.MEDIUM.rank and f.category not in skipped]
    if g == "A+" and serious:
        g = "A"
    return {"grade": g, "score": score, "categories": cats, "capped_by": cap_reasons[:3]}


def compliance(tls_scan, cert_reports, mozilla: dict, findings: list[Finding]) -> dict:
    out: dict = {}
    ids = {f.id for f in findings if f.severity.rank >= Severity.LOW.rank}
    if tls_scan is not None and tls_scan.reachable:
        p = tls_scan.protocols
        suites = [C.get(c) for c in tls_scan.all_ciphers()]
        trusted = all(r.trusted and r.hostname_ok and r.leaf.get("days_left", -1) >= 0 for r in cert_reports) and bool(cert_reports)
        pci = []
        if p.get(C.SSL2) or p.get(C.SSL3) or p.get(C.TLS10):
            pci.append("SSL or early TLS (1.0) enabled")
        if p.get(C.TLS11):
            pci.append("TLS 1.1 enabled (PCI SSC guidance treats it as insecure)")
        if any(s.strength == "insecure" or s.cipher.startswith("3DES") for s in suites):
            pci.append("insecure cipher suites (export/NULL/RC4/DES/3DES)")
        if not trusted:
            pci.append("certificate not valid and trusted")
        out["pci_dss_4"] = {"name": "PCI DSS v4.0 req. 4.2.1 (strong cryptography in transit)", "compliant": not pci,
                            "problems": pci}
        nist = []
        if not p.get(C.TLS12):
            nist.append("TLS 1.2 not supported")
        if not p.get(C.TLS13):
            nist.append("TLS 1.3 not supported (required since January 2024)")
        if p.get(C.TLS10) or p.get(C.TLS11) or p.get(C.SSL3) or p.get(C.SSL2):
            nist.append("protocols older than TLS 1.2 enabled")
        bad = [s.name for s in suites if s.strength == "insecure" or s.block_64bit or "CHACHA20" in s.cipher
               or "CAMELLIA" in s.cipher or "ARIA" in s.cipher or "SEED" in s.cipher or (not s.tls13 and not s.forward_secret)]
        if bad:
            nist.append(f"{len(bad)} suites outside the SP 800-52r2 approved list (e.g. {bad[0]})")
        for r in cert_reports:
            if r.leaf.get("key_type") == "RSA" and r.leaf.get("key_bits", 0) < 2048:
                nist.append("RSA key below 2048 bits")
        out["nist_800_52r2"] = {"name": "NIST SP 800-52 Rev. 2 (US federal TLS guidelines)", "compliant": not nist,
                                "problems": nist}
        for prof in ("modern", "intermediate"):
            if prof in mozilla:
                out[f"mozilla_{prof}"] = {"name": f"Mozilla {prof.capitalize()} profile (v{mozilla.get('guidelines_version')})",
                                          "compliant": mozilla[prof]["compliant"], "problems": mozilla[prof]["problems"]}
    owasp = []
    for fid, label in (("hsts.missing", "Strict-Transport-Security"), ("csp.missing", "Content-Security-Policy"),
                       ("hdr.framing", "frame-ancestors / X-Frame-Options"), ("hdr.nosniff", "X-Content-Type-Options")):
        if fid in ids:
            owasp.append(f"missing or weak {label}")
    out["owasp_headers"] = {"name": "OWASP Secure Headers baseline", "compliant": not owasp, "problems": owasp}
    email_ids = {f.id for f in findings if f.category == "email" and f.severity.rank >= Severity.MEDIUM.rank}
    bulk = []
    if {"spf.missing", "spf.error"} & email_ids:
        bulk.append("SPF missing or broken")
    if {"dmarc.missing", "dmarc.invalid", "dmarc.multiple"} & email_ids:
        bulk.append("no valid DMARC record")
    out["bulk_sender"] = {"name": "Gmail / Yahoo bulk-sender authentication (2024)", "compliant": not bulk,
                          "problems": bulk}
    return out
