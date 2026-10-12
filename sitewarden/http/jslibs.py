"""Known-vulnerable JavaScript library detection using the Retire.js repository (Apache-2.0)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache

from ..domains import data_path

VERSION_RE = r"[0-9][0-9.a-z_\-]+"


@dataclass
class Detection:
    library: str
    version: str
    source: str  # URL or "inline script"
    method: str  # uri | filename | filecontent
    vulnerabilities: list[dict] = field(default_factory=list)

    @property
    def worst(self) -> str | None:
        order = ["low", "medium", "high", "critical"]
        sev = [v.get("severity", "low") for v in self.vulnerabilities]
        sev = [s for s in sev if s in order]
        return max(sev, key=order.index) if sev else None

    def to_dict(self) -> dict:
        return {"library": self.library, "version": self.version, "source": self.source, "method": self.method,
                "vulnerabilities": self.vulnerabilities, "worst": self.worst}


def _comparable(tok: str | None):
    if not tok:
        return 0
    if tok.isdigit():
        return int(tok)
    return tok


def is_at_or_above(v1: str, v2: str) -> bool:
    """Port of retire.js isAtOrAbove: numeric segments outrank pre-release strings."""
    a = re.split(r"[.\-]", v1)
    b = re.split(r"[.\-]", v2)
    for i in range(max(len(a), len(b))):
        x = _comparable(a[i] if i < len(a) else None)
        y = _comparable(b[i] if i < len(b) else None)
        if type(x) is not type(y):
            return isinstance(x, int)
        if x > y:
            return True
        if x < y:
            return False
    return True


def affected(version: str, vuln: dict) -> bool:
    if "below" in vuln and is_at_or_above(version, vuln["below"]):
        return False
    if "atOrAbove" in vuln and not is_at_or_above(version, vuln["atOrAbove"]):
        return False
    if "above" in vuln and (not is_at_or_above(version, vuln["above"]) or version == vuln["above"]):
        return False
    return True


@lru_cache(maxsize=1)
def repository() -> dict:
    with open(data_path("retirejs-repository.json"), encoding="utf-8") as fh:
        repo = json.load(fh)
    compiled = {}
    for lib, entry in repo.items():
        if lib == "retire-example":
            continue
        ex = entry.get("extractors", {})
        c = {}
        for kind in ("uri", "filename", "filecontent"):
            pats = []
            for p in ex.get(kind, []):
                try:
                    pats.append(re.compile(p.replace("§§version§§", VERSION_RE)))
                except re.error:
                    continue
            c[kind] = pats
        compiled[lib] = (c, entry.get("vulnerabilities", []))
    return compiled


def _vulns_for(lib: str, version: str) -> list[dict]:
    _, vulns = repository()[lib]
    out = []
    for v in vulns:
        if affected(version, v):
            ids = v.get("identifiers", {})
            out.append({
                "severity": v.get("severity", "low"),
                "summary": ids.get("summary") or (ids.get("CVE") or ["vulnerability"])[0],
                "cve": ids.get("CVE", []),
                "ghsa": ids.get("githubID"),
                "below": v.get("below"),
                "info": v.get("info", [])[:3],
            })
    return out


def _version_from(match: re.Match) -> str | None:
    ver = match.group(1) if match.re.groups else None
    if not ver:
        return None
    m = re.match(r"\d+(?:\.\d+)*(?:-(?:alpha|beta|rc|pre|dev)[0-9a-z.]*)?", ver, re.I)
    return m.group(0).rstrip(".-_") if m else None


# Package names on public CDNs that differ from the Retire.js library keys.
CDN_ALIASES = {
    "angular.js": "angularjs", "angular": "angularjs", "twitter-bootstrap": "bootstrap", "lodash.js": "lodash",
    "jqueryui": "jquery-ui", "jquery-ui-dist": "jquery-ui", "handlebars.js": "handlebars",
    "dompurify": "DOMPurify", "three.js": "threejs", "three": "threejs", "highlight.js": "highlightjs",
    "Chart.js": "chart.js", "chart.js": "chart.js", "datatables": "jquery.datatables",
    "datatables.net": "jquery.datatables", "jquery-validate": "jquery-validation",
    "jquery-validation": "jquery-validation", "tinymce": "tinyMCE", "ember.js": "ember", "prototype": "prototypejs",
    "d3js": "d3", "pdfjs-dist": "pdf.js", "moment": "moment.js", "underscore": "underscore.js",
    "backbone": "backbone.js", "mustache": "mustache.js", "next": "nextjs", "jquery-migrate": "jquery-migrate",
}
CDN_PATTERNS = [
    re.compile(r"cdn\.jsdelivr\.net/npm/((?:@[\w.-]+/)?[\w.-]+)@([0-9][\w.\-]*)"),
    re.compile(r"unpkg\.com/((?:@[\w.-]+/)?[\w.-]+)@([0-9][\w.\-]*)"),
    re.compile(r"cdnjs\.cloudflare\.com/ajax/libs/([\w.-]+)/([0-9][\w.\-]*)/"),
    re.compile(r"ajax\.googleapis\.com/ajax/libs/([\w.-]+)/([0-9][\w.\-]*)/"),
    re.compile(r"(?:stackpath|maxcdn|netdna)\.bootstrapcdn\.com/(bootstrap|twitter-bootstrap)/([0-9][\w.\-]*)/"),
    re.compile(r"code\.jquery\.com/(jquery|ui|jquery-migrate)[-/]([0-9][\w.\-]*?)(?:\.min|\.slim)*(?:\.js|/)"),
]


def _lib_key(pkg: str) -> str | None:
    repo = repository()
    if pkg in CDN_ALIASES:
        pkg = CDN_ALIASES[pkg]
    if pkg == "ui":
        pkg = "jquery-ui"
    if pkg in repo:
        return pkg
    low = pkg.lower()
    for key in repo:
        if key.lower() == low:
            return key
    return None


def scan_cdn_url(url: str) -> list[Detection]:
    for pat in CDN_PATTERNS:
        m = pat.search(url)
        if m:
            key = _lib_key(m.group(1))
            ver = m.group(2).rstrip(".-_")
            if key and ver:
                return [Detection(key, ver, url, "cdn-url", _vulns_for(key, ver))]
    return []


def scan_url(url: str) -> list[Detection]:
    out = scan_cdn_url(url)
    if out:
        return out
    filename = url.split("?")[0].rstrip("/").split("/")[-1]
    for lib, (pats, _) in repository().items():
        for kind, target in (("uri", url), ("filename", filename)):
            for p in pats[kind]:
                m = p.search(target)
                if m and (ver := _version_from(m)):
                    out.append(Detection(lib, ver, url, kind, _vulns_for(lib, ver)))
                    break
            else:
                continue
            break
    return out


def scan_content(source: str, text: str) -> list[Detection]:
    out = []
    head = text[:300000]
    for lib, (pats, _) in repository().items():
        for p in pats["filecontent"]:
            m = p.search(head)
            if m and (ver := _version_from(m)):
                out.append(Detection(lib, ver, source, "filecontent", _vulns_for(lib, ver)))
                break
    return out


def dedupe(dets: list[Detection]) -> list[Detection]:
    best: dict[tuple[str, str], Detection] = {}
    for d in dets:
        key = (d.library, d.version)
        if key not in best or (d.method == "filecontent" and best[key].method != "filecontent"):
            best[key] = d
    return list(best.values())
