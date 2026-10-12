"""Page content analysis: mixed content, Subresource Integrity, third-party scripts and libraries."""

from __future__ import annotations

import concurrent.futures as cf
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from ..domains import registrable_domain
from ..models import Findings, Severity
from ..net import Network
from ..remediation import SNIPPETS
from . import jslibs
from .client import Response, fetch

# Script hosts tied to real supply-chain incidents. Loading anything from them is dangerous.
COMPROMISED_HOSTS = {
    "polyfill.io": "Sold in 2024 and used to inject malware into more than 100,000 sites (Sansec, June 2024).",
    "cdn.polyfill.io": "Sold in 2024 and used to inject malware into more than 100,000 sites (Sansec, June 2024).",
    "bootcss.com": "Operated by the same group as the malicious polyfill.io CDN (Funnull, 2024).",
    "bootcdn.net": "Operated by the same group as the malicious polyfill.io CDN (Funnull, 2024).",
    "staticfile.net": "Operated by the same group as the malicious polyfill.io CDN (Funnull, 2024).",
    "staticfile.org": "Operated by the same group as the malicious polyfill.io CDN (Funnull, 2024).",
    "unionadjs.com": "Linked to the 2024 polyfill.io malware campaign.",
    "xhsbpza.com": "Linked to the 2024 polyfill.io malware campaign.",
    "union.macoms.la": "Linked to the 2024 polyfill.io malware campaign.",
    "newcrbpc.com": "Linked to the 2024 polyfill.io malware campaign.",
}
# Static CDNs where file content is immutable per version, so SRI is always feasible.
STATIC_CDNS = ("cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com", "ajax.googleapis.com",
               "code.jquery.com", "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com",
               "cdn.datatables.net", "use.fontawesome.com", "ajax.aspnetcdn.com")
MAX_SCRIPT_FETCH = 20
MAX_SCRIPT_BYTES = 1_500_000


@dataclass
class Resource:
    tag: str
    attr: str
    url: str
    integrity: str | None = None
    rel: str | None = None
    kind: str = "passive"  # active | passive


@dataclass
class PageParser(HTMLParser):
    base_url: str = ""
    resources: list[Resource] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    inline_scripts: list[str] = field(default_factory=list)
    meta: list[dict] = field(default_factory=list)
    inline_handlers: int = 0
    nonces: set[str] = field(default_factory=set)
    _in_script: bool = False
    _script_buf: list[str] = field(default_factory=list)
    _current_form: dict | None = None

    def __post_init__(self):
        HTMLParser.__init__(self, convert_charrefs=True)

    def _abs(self, url: str) -> str:
        return urljoin(self.base_url, url.strip())

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if any(k.startswith("on") for k in a):
            self.inline_handlers += 1
        if a.get("nonce"):
            self.nonces.add(a["nonce"])
        if tag == "base" and a.get("href"):
            self.base_url = self._abs(a["href"])
        elif tag == "script":
            if a.get("src"):
                self.resources.append(Resource("script", "src", self._abs(a["src"]), a.get("integrity"), kind="active"))
            else:
                t = a.get("type", "").lower()
                if t in ("", "text/javascript", "module", "application/javascript"):
                    self._in_script = True
                    self._script_buf = []
        elif tag == "link" and a.get("href"):
            rel = a.get("rel", "").lower()
            if "stylesheet" in rel or ("preload" in rel and a.get("as") in ("script", "style")) or "modulepreload" in rel:
                self.resources.append(Resource("link", "href", self._abs(a["href"]), a.get("integrity"), rel, "active"))
            elif "icon" in rel or "manifest" in rel:
                self.resources.append(Resource("link", "href", self._abs(a["href"]), None, rel, "passive"))
        elif tag in ("iframe", "frame", "object", "embed") and (a.get("src") or a.get("data")):
            self.resources.append(Resource(tag, "src", self._abs(a.get("src") or a.get("data")), kind="active"))
        elif tag in ("img", "audio", "video", "source", "track") and a.get("src"):
            self.resources.append(Resource(tag, "src", self._abs(a["src"]), kind="passive"))
        elif tag == "form":
            self._current_form = {"action": self._abs(a.get("action") or self.base_url),
                                  "method": (a.get("method") or "get").lower(), "password": False}
            self.forms.append(self._current_form)
        elif tag == "input" and self._current_form is not None and a.get("type", "").lower() == "password":
            self._current_form["password"] = True
        elif tag == "meta":
            self.meta.append(a)

    def handle_endtag(self, tag):
        if tag == "script" and self._in_script:
            self.inline_scripts.append("".join(self._script_buf))
            self._in_script = False
        elif tag == "form":
            self._current_form = None

    def handle_data(self, data):
        if self._in_script:
            self._script_buf.append(data)


def parse_page(url: str, html: str) -> PageParser:
    p = PageParser(base_url=url)
    try:
        p.feed(html)
        p.close()
    except Exception:  # html.parser is lenient, but never let a weird page break the scan
        pass
    return p


def meta_csp(page: PageParser) -> list[str]:
    return [m.get("content", "") for m in page.meta
            if m.get("http-equiv", "").lower() == "content-security-policy" and m.get("content")]


def analyze(net: Network, final: Response, page: PageParser, fetch_scripts: bool = True) -> tuple[Findings, dict]:
    f = Findings("content")
    host = urlsplit(final.url).hostname or ""
    site = registrable_domain(host) if host else ""
    https = final.url.startswith("https://")
    facts: dict = {"resources": len(page.resources), "inline_scripts": len(page.inline_scripts),
                   "inline_event_handlers": page.inline_handlers, "forms": len(page.forms)}

    # --- mixed content ---
    if https:
        active = [r for r in page.resources if r.url.startswith("http://") and r.kind == "active"]
        passive = [r for r in page.resources if r.url.startswith("http://") and r.kind == "passive"]
        if active:
            f.add("content.mixed_active", Severity.HIGH, f"Active mixed content: {len(active)} script/style/frame URL(s) over HTTP",
                  "Browsers block these, which breaks the page; where they are not blocked (older browsers, some "
                  "WebViews) a network attacker can replace them and take over the page.",
                  evidence=", ".join(r.url for r in active[:5]), fix="Load every subresource over HTTPS.",
                  tags=["CWE-319", "CWE-311"])
        if passive:
            f.add("content.mixed_passive", Severity.LOW, f"Passive mixed content: {len(passive)} media URL(s) over HTTP",
                  "Images and media over HTTP can be swapped or used to track users; browsers now auto-upgrade or "
                  "block them.", evidence=", ".join(r.url for r in passive[:5]), tags=["CWE-319"])
        if not active and not passive and page.resources:
            f.ok("content.no_mixed", "No mixed content")

    # --- forms ---
    for form in page.forms:
        action = form["action"]
        if action.startswith("http://"):
            f.add("content.form_http", Severity.HIGH if form["password"] else Severity.MEDIUM,
                  "Form submits over plain HTTP" + (" (password field)" if form["password"] else ""),
                  "Whatever the user types is sent unencrypted.", evidence=f"<form action=\"{action}\">",
                  tags=["CWE-319"])
    if not https and any(fm["password"] for fm in page.forms):
        f.add("content.password_http", Severity.CRITICAL, "Password form on a page served over HTTP",
              "Credentials can be captured or the form rewritten by anyone on the network.", cap="F",
              tags=["CWE-319", "CWE-523"])

    # --- third-party scripts and SRI ---
    def third_party(url: str) -> bool:
        h = urlsplit(url).hostname or ""
        return bool(h) and registrable_domain(h) != site

    scripts = [r for r in page.resources if r.tag == "script"]
    styles = [r for r in page.resources if r.tag == "link" and r.kind == "active"]
    tp_scripts = [r for r in scripts if third_party(r.url)]
    tp_domains = sorted({urlsplit(r.url).hostname for r in tp_scripts if urlsplit(r.url).hostname})
    facts["third_party_script_hosts"] = tp_domains
    facts["scripts"] = [r.url for r in scripts]
    bad = []
    for r in scripts + styles:
        h = (urlsplit(r.url).hostname or "").lower()
        for ch, why in COMPROMISED_HOSTS.items():
            if h == ch or h.endswith("." + ch):
                bad.append((r.url, why))
    if bad:
        f.add("content.compromised_cdn", Severity.CRITICAL, "Loads script from a known-compromised CDN",
              bad[0][1] + " Whoever controls that host can run any code in your visitors' browsers.",
              evidence=", ".join(u for u, _ in bad[:4]), fix="Remove the script tag immediately.", cap="F",
              tags=["CWE-829", "CWE-506"], refs=["https://sansec.io/research/polyfill-supply-chain-attack"])
    no_sri = [r for r in tp_scripts + [s for s in styles if third_party(s.url)] if not r.integrity]
    static_no_sri = [r for r in no_sri if (urlsplit(r.url).hostname or "") in STATIC_CDNS]
    if static_no_sri:
        f.add("content.sri", Severity.MEDIUM, f"{len(static_no_sri)} CDN resource(s) without Subresource Integrity",
              "If the CDN or the package is compromised, the modified file runs on your site. These are fixed, "
              "versioned files, so an integrity hash costs nothing.",
              evidence=", ".join(r.url for r in static_no_sri[:5]), snippets=SNIPPETS["sri"],
              tags=["CWE-353", "CWE-829"], refs=["https://www.w3.org/TR/SRI/"])
    other_no_sri = [r for r in no_sri if r not in static_no_sri and r.tag == "script"]
    if other_no_sri:
        f.add("content.third_party", Severity.INFO,
              f"{len(tp_domains)} third-party script host(s) can run code on this page",
              "Every one of these providers, and anyone who compromises them, has full control over the page. "
              "Dynamic analytics/tag scripts cannot use SRI, so keep the list short and use CSP to pin it.",
              evidence=", ".join(tp_domains[:12]))
    with_sri = [r for r in scripts + styles if r.integrity]
    if with_sri:
        f.ok("content.sri_used", f"Subresource Integrity on {len(with_sri)} resource(s)")

    # --- vulnerable libraries ---
    detections: list[jslibs.Detection] = []
    for r in scripts:
        detections.extend(jslibs.scan_url(r.url))
    for i, code in enumerate(page.inline_scripts[:30]):
        detections.extend(jslibs.scan_content(f"inline script #{i + 1}", code))
    if fetch_scripts:
        todo = [r.url for r in scripts if r.url.startswith(("https://", "http://"))]
        todo = sorted(dict.fromkeys(todo), key=lambda u: third_party(u))[:MAX_SCRIPT_FETCH]

        def grab(u):
            resp = fetch(net, u, max_body=MAX_SCRIPT_BYTES, timeout=10, headers={"Accept": "*/*"})
            if resp.ok and resp.status == 200:
                return jslibs.scan_content(u, resp.text())
            return []

        with cf.ThreadPoolExecutor(6) as pool:
            for dets in pool.map(grab, todo):
                detections.extend(dets)
    detections = jslibs.dedupe(detections)
    facts["libraries"] = [d.to_dict() for d in detections]
    sev_map = {"critical": Severity.HIGH, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}
    for d in detections:
        if not d.vulnerabilities:
            continue
        cves = sorted({c for v in d.vulnerabilities for c in v["cve"]})
        fixed = [v["below"] for v in d.vulnerabilities if v.get("below")]
        upgrade = max(fixed, key=_vkey) if fixed else None
        f.add("content.vulnerable_library", sev_map.get(d.worst or "low", Severity.LOW),
              f"{d.library} {d.version} has {len(d.vulnerabilities)} known vulnerabilit{'y' if len(d.vulnerabilities) == 1 else 'ies'}",
              "; ".join(sorted({v["summary"] for v in d.vulnerabilities}))[:400],
              evidence=f"{d.source} ({d.method})" + (f" | {', '.join(cves[:6])}" if cves else ""),
              fix=f"Upgrade {d.library} to {upgrade} or later." if upgrade else f"Upgrade {d.library}.",
              refs=[i for v in d.vulnerabilities for i in v["info"]][:3],
              tags=["CWE-1104", "OWASP A06:2021"] + cves[:4])
    clean = [d for d in detections if not d.vulnerabilities]
    if clean:
        f.ok("content.libraries_ok", "No known vulnerabilities in " + ", ".join(f"{d.library} {d.version}" for d in clean[:6]))

    # --- meta details ---
    gen = next((m.get("content") for m in page.meta if m.get("name", "").lower() == "generator"), None)
    if gen and re.search(r"\d", gen):
        f.add("content.generator", Severity.LOW, f"CMS version disclosed: {gen}",
              "The generator tag tells attackers exactly which CMS release (and known bugs) to target.",
              fix="Remove the generator meta tag.", tags=["CWE-200"])
    refresh = next((m.get("content") for m in page.meta if m.get("http-equiv", "").lower() == "refresh"), None)
    if refresh and "http://" in refresh.lower():
        f.add("content.meta_refresh_http", Severity.MEDIUM, "Meta refresh to a plain-HTTP URL", evidence=refresh)
    return f, facts


def _vkey(v: str):
    return [int(x) if x.isdigit() else -1 for x in re.split(r"[.\-]", v)]
