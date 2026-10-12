"""Scan orchestration: runs every check family and assembles the report."""

from __future__ import annotations

import concurrent.futures as cf
import datetime as dt
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from . import __version__, scoring
from .dns import domain as dns_domain
from .dns import email as dns_email
from .domains import registrable_domain
from .http import client as http_client
from .http import content as http_content
from .http import cookies as http_cookies
from .http import csp as http_csp
from .http import headers as http_headers
from .http import wellknown
from .models import Finding, Findings, Severity
from .net import BlockedAddress, Network, ResolutionError, split_host
from .tls import analysis as tls_analysis
from .tls import certificate as tls_cert
from .tls.scanner import TLSScanner

HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.?$")

STAGES = ["resolve", "tls", "certificate", "http", "content", "dns", "email", "grade"]


class ScanError(Exception):
    pass


@dataclass
class ScanOptions:
    port: int | None = None
    http_port: int = 80
    tls: bool = True
    http: bool = True
    dns: bool = True
    email: bool = True
    smtp: bool = True
    fetch_scripts: bool = True
    revocation: bool = True
    tls_workers: int = 4
    timeout: float = 6.0
    dnssec_anchors: list[str] | None = None


ProgressFn = Callable[[str, str], None]


def normalize_target(target: str) -> tuple[str, int | None]:
    host, port = split_host(target)
    if not host:
        raise ScanError("Enter a domain name such as example.com")
    try:
        host = host.encode("idna").decode("ascii") if not host.isascii() else host
    except UnicodeError as exc:
        raise ScanError(f"Invalid internationalised domain name: {exc}") from exc
    import ipaddress

    try:
        ipaddress.ip_address(host)
        return host, port
    except ValueError:
        pass
    if not HOST_RE.match(host) or "." not in host:
        raise ScanError(f"'{host}' is not a valid public host name")
    return host.rstrip("."), port


def run_scan(target: str, net: Network | None = None, options: ScanOptions | None = None,
             progress: ProgressFn | None = None) -> dict:
    net = net or Network.from_env()
    opt = options or ScanOptions()
    say = progress or (lambda stage, msg: None)
    lock = threading.Lock()
    started = time.monotonic()
    now = dt.datetime.now(dt.UTC)

    host, port_in_url = normalize_target(target)
    port = opt.port or port_in_url or 443
    report: dict = {
        "tool": "sitewarden", "version": __version__, "target": host, "port": port,
        "scanned_at": now.isoformat(timespec="seconds"), "notes": [], "errors": {},
    }
    findings: list[Finding] = []

    def add(fs):
        with lock:
            findings.extend(fs)

    say("resolve", f"Resolving {host}")
    ip = None
    if net.proxy:
        report["notes"].append("Proxy mode: HTTP checks ran through a proxy, so TLS and certificate results "
                               "would describe the proxy and were skipped.")
    else:
        try:
            ip = net.resolve(host)
        except BlockedAddress as exc:
            raise ScanError(str(exc)) from exc
        except ResolutionError as exc:
            cname = net.query(host, "CNAME").rrset
            if cname:
                raise ScanError(f"{host} is a CNAME for {cname[0].rstrip('.')}, which does not resolve. A dangling "
                                "CNAME like this can allow subdomain takeover: remove the record if the service "
                                "is gone.") from exc
            raise ScanError(f"{host} could not be resolved. Check the spelling, or the domain may not exist.") from exc
    report["ip"] = ip
    report["registrable_domain"] = registrable_domain(host) if not _is_ip(host) else host

    skipped: set[str] = set()
    state: dict = {"tls": None, "certs": []}

    # ---------------------------------------------------------------- TLS + certificate
    def tls_phase():
        if not opt.tls or ip is None:
            skipped.update({"tls", "certificate"})
            return
        say("tls", "Handshaking: protocol versions, cipher suites, key exchange")
        scanner = TLSScanner(host, ip, port, timeout=opt.timeout, workers=opt.tls_workers,
                             progress=lambda m: say("tls", m), connect=net.connect)
        scan = scanner.run()
        state["tls"] = scan
        report["tls"] = scan.to_dict()
        if not scan.reachable:
            f = Findings("tls")
            f.add("tls.unavailable", Severity.CRITICAL, f"No HTTPS on port {port}",
                  f"The server did not answer a TLS handshake ({scan.error}). Everything sent to this site travels "
                  "unencrypted and can be read or changed by anyone on the network.",
                  fix="Install a certificate (Let's Encrypt is free) and serve the site over HTTPS.", cap="F",
                  tags=["CWE-319"])
            add(f)
            skipped.add("certificate")
            return
        add(tls_analysis.analyze(scan))
        say("certificate", "Validating the certificate chain and revocation status")
        local = tls_cert.local_handshake(net, host, ip, port)
        chains = dict(scan.chains)
        if not chains and local.chain:
            chains = {"server": local.chain}  # TLS 1.3-only servers: chain via the local stack
        if local.alpn and not scan.alpn:
            scan.alpn = [local.alpn]
            report["tls"]["features"]["alpn"] = scan.alpn
        reports, cf_ = tls_cert.evaluate(net, host, chains, ocsp_stapled=scan.ocsp_stapled,
                                         stapled_der=scan.ocsp_response, sct_in_tls=scan.sct_in_tls, now=now,
                                         check_revocation=opt.revocation)
        state["certs"] = reports
        report["certificates"] = [r.to_dict() for r in reports]
        add(cf_)
        report["mozilla"] = tls_analysis.mozilla_compliance(scan, reports)
        if local.alpn == "h2":
            add([Finding("hdr.http2", "headers", Severity.PASS, "HTTP/2 supported")])

    # ---------------------------------------------------------------- HTTP + content
    def http_phase():
        if not opt.http:
            skipped.update({"headers", "cookies", "content"})
            return
        say("http", "Fetching the site over HTTPS and HTTP")
        suffix = f":{port}" if port != 443 else ""
        https_hops = http_client.fetch_chain(net, f"https://{host}{suffix}/")
        hsuffix = f":{opt.http_port}" if opt.http_port != 80 else ""
        http_hops = http_client.fetch_chain(net, f"http://{host}{hsuffix}/") if opt.http_port else []
        final = https_hops[-1] if https_hops else None
        report["http"] = {"https_chain": [_hop(h) for h in https_hops], "http_chain": [_hop(h) for h in http_hops]}
        if final is None or not final.ok:
            http_final = http_hops[-1] if http_hops else None
            if http_final is not None and http_final.ok:
                final = http_final
                report["notes"].append("The HTTPS site did not respond; header checks used the plain-HTTP response.")
            else:
                err = (final.error if final else None) or "no response"
                report["errors"]["http"] = err
                f = Findings("headers")
                f.add("http.unreachable", Severity.HIGH, "The website did not respond to HTTP requests", err)
                add(f)
                skipped.update({"cookies", "content"})
                return
        tf, tfacts = http_headers.analyze_transport(host, http_hops, https_hops)
        add(tf)
        cors = http_client.fetch(net, final.url, headers={"Origin": http_headers.CORS_PROBE_ORIGIN}, max_body=1024)
        hf, hfacts = http_headers.analyze_headers(host, final, cors)
        add(hf)
        report["http"].update(tfacts)
        report["http"].update({k: v for k, v in hfacts.items() if k != "headers"})
        report["http"]["response_headers"] = hfacts["headers"]
        report["http"]["final_url"] = final.url

        # cookies from every hop (HTTP hops count as cleartext)
        cookies = []
        for h in http_hops + https_hops:
            for v in h.header_all("set-cookie"):
                c = http_cookies.parse_set_cookie(v, h.url, h.url.startswith("https://"))
                if c:
                    cookies.append(c)
        cf_, cdicts = http_cookies.analyze(host, cookies)
        add(cf_)
        report["cookies"] = cdicts

        say("content", "Parsing the page: scripts, mixed content, libraries")
        page = None
        is_html = "html" in (final.header("content-type") or "").lower()
        if is_html:
            page = http_content.parse_page(final.url, final.text())
        enforced = final.header_all("content-security-policy")
        nonce_sets = None
        if page and page.nonces:
            again = http_client.fetch(net, final.url)
            if again.ok and "html" in (again.header("content-type") or "").lower():
                page2 = http_content.parse_page(again.url, again.text())
                csp_nonces = lambda vals: {m for v in vals for m in re.findall(r"'nonce-([^']+)'", v)}  # noqa: E731
                nonce_sets = [csp_nonces(enforced) or page.nonces, csp_nonces(again.header_all("content-security-policy")) or page2.nonces]
        cspf, verdict = http_csp.evaluate(enforced, final.header_all("content-security-policy-report-only"),
                                         http_content.meta_csp(page) if page else [], nonce_sets)
        if is_html or enforced:
            add(cspf)
        report["http"]["csp"] = {"level": verdict.level, "policies": verdict.policies}
        if page is not None:
            contf, cfacts = http_content.analyze(net, final, page, fetch_scripts=opt.fetch_scripts)
            add(contf)
            report["content"] = cfacts
        else:
            skipped.add("content")
            report["content"] = {"note": "The final response is not an HTML page."}
        sf, sfacts = wellknown.check_security_txt(net, host, now, base=f"https://{host}{suffix}")
        add(sf)
        report["http"]["security_txt"] = sfacts

    # ---------------------------------------------------------------- DNS + email
    def dns_phase():
        if not opt.dns:
            skipped.update({"dns", "email"})
            return
        say("dns", "Checking DNSSEC, CAA and name servers")
        df, dfacts = dns_domain.analyze(net, host, None, dnssec_anchors=opt.dnssec_anchors)
        report["dns"] = dfacts
        if dfacts.get("dns_unavailable"):
            skipped.update({"dns", "email"})
            report["notes"].append("DNS checks were skipped because no DNS resolver was reachable.")
            return
        add(df)
        if not opt.email:
            skipped.add("email")
            return
        say("email", "Checking SPF, DMARC, DKIM, MTA-STS and mail servers")
        domain = registrable_domain(host)
        mf, mfacts, mx_hosts, null_mx = dns_domain.mail_servers(net, domain, opt.smtp)
        ef, efacts = dns_email.analyze(net, domain, mx_hosts, null_mx)
        add(mf)
        add(ef)
        efacts.update(mfacts)
        report["email"] = efacts

    with cf.ThreadPoolExecutor(3) as pool:
        futs = {pool.submit(fn): name for fn, name in ((tls_phase, "tls"), (http_phase, "http"), (dns_phase, "dns"))}
        for fut in cf.as_completed(futs):
            try:
                fut.result()
            except Exception as exc:  # one failing family must not lose the rest of the report
                name = futs[fut]
                report["errors"][name] = f"{exc.__class__.__name__}: {exc}"
                if name == "tls":
                    skipped.update({"tls", "certificate"})
                elif name == "http":
                    skipped.update({"headers", "cookies", "content"})
                else:
                    skipped.update({"dns", "email"})

    # CAA vs. the issuing CA needs both the DNS and certificate phases
    if state["certs"] and "dns" not in skipped and report.get("dns", {}).get("caa", {}).get("records"):
        caa = report["dns"]["caa"]["records"]
        for rep in state["certs"]:
            allowed = dns_domain._caa_allows(caa, rep.leaf.get("issuer_org") or rep.leaf.get("issuer"),
                                             any(n.startswith("*.") for n in rep.names))
            if allowed is False:
                f = Findings("dns")
                f.add("caa.mismatch", Severity.MEDIUM, "CAA does not authorise the CA that issued the current certificate",
                      f"The certificate comes from {rep.leaf.get('issuer_org') or rep.leaf.get('issuer')}, which the CAA "
                      "records do not list. The next renewal will be refused.", evidence="; ".join(caa[:5]))
                add(f)
                break

    say("grade", "Calculating the grade")
    findings = _dedupe(findings)
    findings.sort(key=lambda f: (-f.severity.rank, f.category, f.id))
    g = scoring.grade(findings, skipped)
    report.update(g)
    report["skipped"] = sorted(skipped)
    report["compliance"] = scoring.compliance(state["tls"], state["certs"], report.get("mozilla", {}), findings)
    if "email" in skipped:
        report["compliance"].pop("bulk_sender", None)
    report["findings"] = [f.to_dict() for f in findings]
    report["summary"] = {s.value: sum(1 for f in findings if f.severity == s) for s in Severity}
    report["duration_ms"] = int((time.monotonic() - started) * 1000)
    report["limitations"] = [
        "Passive checks only: Sitewarden sends ordinary TLS handshakes, page requests and DNS queries, "
        "the same traffic a browser or mail server produces.",
        "Not tested: Heartbleed, ROBOT, application-level flaws (SQL injection, XSS) and anything behind a login.",
    ]
    return report


def _hop(h) -> dict:
    return {"url": h.url, "status": h.status, "error": h.error, "location": h.location,
            "elapsed_ms": h.elapsed_ms, "tls": h.tls_version}


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen = set()
    out = []
    for f in findings:
        key = (f.id, f.title)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _is_ip(h: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False
