"""Content Security Policy parser and evaluator.

The checks follow the CSP Level 3 specification and the "strict CSP" guidance
from Google's CSP Evaluator research (Weichselbaum et al., "CSP Is Dead, Long
Live CSP!", CCS 2016): allowlists are routinely bypassable, so a policy is
only considered strong when scripts are gated by nonces or hashes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..models import Findings, Severity

FETCH_DIRECTIVES = {
    "child-src", "connect-src", "default-src", "fenced-frame-src", "font-src", "frame-src", "img-src",
    "manifest-src", "media-src", "object-src", "prefetch-src", "script-src", "script-src-elem",
    "script-src-attr", "style-src", "style-src-elem", "style-src-attr", "worker-src",
}
OTHER_DIRECTIVES = {
    "base-uri", "sandbox", "form-action", "frame-ancestors", "navigate-to", "report-uri", "report-to",
    "require-trusted-types-for", "trusted-types", "upgrade-insecure-requests", "block-all-mixed-content",
    "plugin-types", "referrer", "require-sri-for", "webrtc", "reflected-xss", "disown-opener",
    "treat-as-public-address",
}
DEPRECATED = {"block-all-mixed-content", "plugin-types", "referrer", "reflected-xss", "prefetch-src",
              "require-sri-for", "disown-opener", "navigate-to"}
META_IGNORED = {"frame-ancestors", "report-uri", "sandbox"}
KEYWORDS = {"'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "'strict-dynamic'", "'unsafe-hashes'",
            "'report-sample'", "'wasm-unsafe-eval'", "'unsafe-allow-redirects'", "'inline-speculation-rules'"}

# Hosts where anyone can publish JavaScript (open CDNs, user-content hosting) or that serve
# JSONP endpoints / AngularJS, which turn an allowlist entry into a script-execution gadget.
BYPASS_HOSTS = {
    "cdnjs.cloudflare.com": "public CDN hosting AngularJS and arbitrary libraries",
    "cdn.jsdelivr.net": "serves any npm package or GitHub repository",
    "unpkg.com": "serves any npm package",
    "ajax.googleapis.com": "hosts AngularJS",
    "code.angularjs.org": "hosts AngularJS",
    "www.googletagmanager.com": "loads any GTM container, including an attacker's",
    "www.google.com": "has JSONP endpoints",
    "accounts.google.com": "has JSONP endpoints",
    "www.google-analytics.com": "documented script gadgets",
    "*.googleapis.com": "includes storage.googleapis.com user content",
    "storage.googleapis.com": "anyone can host files",
    "*.amazonaws.com": "anyone can host files on S3",
    "*.s3.amazonaws.com": "anyone can host files on S3",
    "*.cloudfront.net": "anyone can create a CloudFront distribution",
    "*.herokuapp.com": "anyone can deploy an app",
    "*.github.io": "anyone can publish GitHub Pages",
    "raw.githack.com": "proxies arbitrary GitHub files",
    "*.firebaseapp.com": "anyone can deploy an app",
    "*.web.app": "anyone can deploy an app",
    "*.appspot.com": "anyone can deploy an app",
    "*.azurewebsites.net": "anyone can deploy an app",
    "*.blob.core.windows.net": "anyone can host files",
    "*.netlify.app": "anyone can deploy a site",
    "*.vercel.app": "anyone can deploy a site",
    "*.pages.dev": "anyone can deploy a site",
    "*.workers.dev": "anyone can deploy a worker",
    "*.glitch.me": "anyone can deploy an app",
}


@dataclass
class Policy:
    raw: str
    directives: dict[str, list[str]] = field(default_factory=dict)
    duplicates: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)
    source: str = "header"  # header | report-only | meta

    def get(self, name: str) -> list[str] | None:
        return self.directives.get(name)

    def effective(self, name: str) -> list[str] | None:
        """Fallback chain per CSP3 for script/style/object/frame."""
        chains = {
            "script-src-elem": ["script-src-elem", "script-src", "default-src"],
            "script-src": ["script-src", "default-src"],
            "object-src": ["object-src", "default-src"],
            "style-src": ["style-src", "default-src"],
            "img-src": ["img-src", "default-src"],
            "frame-src": ["frame-src", "child-src", "default-src"],
            "connect-src": ["connect-src", "default-src"],
        }
        for d in chains.get(name, [name]):
            if d in self.directives:
                return self.directives[d]
        return None


def parse(header_value: str, source: str = "header") -> list[Policy]:
    """A header may carry several comma-separated policies; each is enforced independently."""
    policies = []
    for raw in header_value.split(","):
        raw = raw.strip()
        if not raw:
            continue
        pol = Policy(raw=raw, source=source)
        for part in raw.split(";"):
            tokens = part.strip().split()
            if not tokens:
                continue
            name = tokens[0].lower()
            if not re.fullmatch(r"[a-z0-9-]+", name):
                pol.unknown.append(name)
                continue
            if name in pol.directives:
                pol.duplicates.append(name)  # browsers ignore repeats
                continue
            if name not in FETCH_DIRECTIVES and name not in OTHER_DIRECTIVES:
                pol.unknown.append(name)
            pol.directives[name] = tokens[1:]
        policies.append(pol)
    return policies


def _host_of(src: str) -> str:
    s = src.lower()
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s)
    return s.split("/")[0].split(":")[0]


def _bypass_hosts(sources: list[str]) -> list[str]:
    hits = []
    for src in sources:
        if src.startswith("'") or src.endswith(":"):
            continue
        host = _host_of(src)
        for pattern, why in BYPASS_HOSTS.items():
            if host == pattern or (pattern.startswith("*.") and (host.endswith(pattern[1:]) or host == pattern)):
                hits.append(f"{src} ({why})")
                break
    return hits


@dataclass
class CSPVerdict:
    level: str  # none | report-only | weak | moderate | strict
    policies: list[dict]
    script_policy: list[str] | None = None


def evaluate(enforced: list[str], report_only: list[str], meta: list[str],
             nonce_values: list[set[str]] | None = None) -> tuple[Findings, CSPVerdict]:
    f = Findings("headers")
    pols: list[Policy] = []
    for h in enforced:
        pols.extend(parse(h, "header"))
    for m in meta:
        pols.extend(parse(m, "meta"))
    ro: list[Policy] = []
    for h in report_only:
        ro.extend(parse(h, "report-only"))
    info = [{"source": p.source, "directives": p.directives} for p in pols + ro]

    if not pols:
        if ro:
            f.add("csp.report_only", Severity.MEDIUM, "Content Security Policy is report-only",
                  "Content-Security-Policy-Report-Only only reports violations; it blocks nothing. Promote it to "
                  "an enforced header once the reports are clean.", evidence=ro[0].raw[:300],
                  tags=["CWE-1021", "CWE-79"])
            return f, CSPVerdict("report-only", info)
        from ..remediation import SNIPPETS

        f.add("csp.missing", Severity.MEDIUM, "No Content Security Policy",
              "CSP is the main browser-side defence that stops injected scripts (XSS) from running. Without it, "
              "any markup-injection bug becomes code execution in your users' sessions.",
              fix="Start with a nonce-based strict policy, deployed first as Report-Only.",
              snippets=SNIPPETS["csp"], tags=["CWE-79", "OWASP A05:2021"],
              refs=["https://web.dev/articles/strict-csp", "https://csp-evaluator.withgoogle.com/"])
        return f, CSPVerdict("none", info)

    # Several enforced policies: a script must satisfy all of them, so the strictest wins.
    verdicts = [_evaluate_one(p, f) for p in pols]
    order = ["weak", "moderate", "strict"]
    level = max(verdicts, key=order.index)
    script_pol = next((p.effective("script-src") for p in pols if p.effective("script-src") is not None), None)

    if nonce_values and len(nonce_values) >= 2:
        a, b = nonce_values[0], nonce_values[1]
        if a and a == b:
            f.add("csp.static_nonce", Severity.HIGH, "CSP nonce does not change between page loads",
                  "A nonce must be unpredictable and unique per response. A fixed nonce lets an attacker copy it "
                  "into injected <script> tags, so the policy no longer stops XSS.",
                  evidence=f"nonce-{sorted(a)[0][:24]}... seen on two separate requests", cap="B")
            level = "weak"
    return f, CSPVerdict(level, info, script_pol)


def _evaluate_one(p: Policy, f: Findings) -> str:
    where = " (meta tag)" if p.source == "meta" else ""
    scripts = p.effective("script-src")
    nonce = any(s.startswith("'nonce-") for s in scripts or [])
    hashes = any(re.match(r"'sha(256|384|512)-", s) for s in scripts or [])
    strict_dynamic = "'strict-dynamic'" in (scripts or [])
    level = "moderate"

    for name in p.unknown:
        f.add("csp.unknown_directive", Severity.LOW, f"Unknown CSP directive '{name}'{where}",
              "Browsers ignore unknown directives, so whatever this was meant to restrict is not restricted. "
              "Check for typos or a missing semicolon.")
    for name in p.duplicates:
        f.add("csp.duplicate", Severity.LOW, f"Duplicate CSP directive '{name}'{where}",
              "Only the first occurrence is used; later ones are silently ignored.")
    for name in set(p.directives) & DEPRECATED:
        f.add("csp.deprecated", Severity.INFO, f"Deprecated CSP directive '{name}'{where}")
    for name, values in p.directives.items():
        for v in values:
            if v.lower() in ("self", "none", "unsafe-inline", "unsafe-eval", "strict-dynamic"):
                f.add("csp.unquoted_keyword", Severity.MEDIUM, f"CSP keyword {v} is not quoted in {name}",
                      f"Unquoted, '{v}' is read as a host name, not the keyword. Write '{v}' with single quotes.")
            if v.rstrip(":").lower() in FETCH_DIRECTIVES | OTHER_DIRECTIVES and not v.endswith(":"):
                f.add("csp.missing_semicolon", Severity.MEDIUM, f"'{v}' appears as a value inside {name}",
                      "Probably a missing semicolon: the second directive is being read as a source.")

    if p.source == "meta":
        for name in set(p.directives) & META_IGNORED:
            f.add("csp.meta_ignored", Severity.LOW, f"'{name}' has no effect in a <meta> CSP",
                  "frame-ancestors, report-uri and sandbox only work in the HTTP header.")

    if scripts is None:
        f.add("csp.no_script_src", Severity.HIGH, f"CSP does not restrict scripts{where}",
              "Neither script-src nor default-src is set, so injected scripts from anywhere still run.",
              evidence=p.raw[:240], tags=["CWE-79"])
        return "weak"

    src_lower = [s.lower() for s in scripts]
    if "'unsafe-inline'" in src_lower and not (nonce or hashes):
        f.add("csp.unsafe_inline", Severity.HIGH, f"CSP allows inline scripts ('unsafe-inline'){where}",
              "Inline script execution is exactly what XSS payloads use, so this policy does not prevent XSS.",
              evidence="script-src " + " ".join(scripts)[:240],
              fix="Replace 'unsafe-inline' with per-response nonces or hashes.", tags=["CWE-79"])
        level = "weak"
    if "'unsafe-eval'" in src_lower:
        f.add("csp.unsafe_eval", Severity.MEDIUM, f"CSP allows eval() ('unsafe-eval'){where}",
              "String-to-code functions (eval, new Function, setTimeout with strings) turn DOM-XSS sinks into "
              "code execution.", tags=["CWE-95"])
    if not strict_dynamic:
        wide = [s for s in scripts if s in ("*", "http:", "https:", "data:", "blob:") or s.lower().startswith("http://")]
        if wide:
            f.add("csp.wildcard_scripts", Severity.HIGH, f"CSP allows scripts from any host or insecure origins{where}",
                  "Sources like *, https: or data: let an attacker load script from a server they control.",
                  evidence=" ".join(wide), tags=["CWE-79"])
            level = "weak"
        bypass = _bypass_hosts(scripts)
        if bypass:
            f.add("csp.bypassable_allowlist", Severity.MEDIUM, f"Script allowlist includes bypassable hosts{where}",
                  "These hosts let anyone publish JavaScript or expose JSONP/AngularJS gadgets, which defeats a "
                  "host allowlist.", evidence="; ".join(bypass[:6]),
                  fix="Move to a nonce-based policy with 'strict-dynamic'.",
                  refs=["https://research.google/pubs/csp-is-dead-long-live-csp-on-the-insecurity-of-whitelists-and-the-future-of-content-security-policy/"])
            if level != "weak":
                level = "moderate"
    if (nonce or hashes) and level != "weak":
        # With a nonce or hash, CSP2+ browsers ignore 'unsafe-inline'; with 'strict-dynamic'
        # they also ignore host allowlists and scheme sources.
        level = "strict"
    if nonce:
        short = [s for s in scripts if s.startswith("'nonce-") and len(s) - len("'nonce-'") < 16]
        if short:
            f.add("csp.short_nonce", Severity.LOW, "CSP nonce is shorter than 128 bits",
                  "Nonces should carry at least 128 bits of randomness (22+ base64 characters).",
                  evidence=short[0])

    obj = p.effective("object-src")
    if not obj or [x.lower() for x in obj] != ["'none'"]:
        f.add("csp.object_src", Severity.LOW, f"object-src is not 'none'{where}",
              "<object> and <embed> can load content that executes script. Set object-src 'none'.")
    if "base-uri" not in p.directives and (nonce or hashes or strict_dynamic):
        f.add("csp.base_uri", Severity.MEDIUM, f"Nonce-based CSP without base-uri{where}",
              "An injected <base href> re-points relative script URLs at the attacker, and nonced scripts load "
              "from there. Add base-uri 'none' (or 'self').")
    elif "base-uri" not in p.directives:
        f.add("csp.base_uri", Severity.LOW, f"CSP does not set base-uri{where}",
              "Without base-uri, injected <base> tags can redirect relative URLs.")
    if "require-trusted-types-for" in p.directives:
        f.ok("csp.trusted_types", "Trusted Types enforced",
             "DOM XSS sinks only accept vetted objects: the strongest client-side XSS defence available.")
    if "upgrade-insecure-requests" in p.directives:
        f.ok("csp.upgrade", "upgrade-insecure-requests is set")
    if level == "strict":
        f.ok("csp.strict", f"Strict, nonce/hash-based Content Security Policy{where}",
             "Scripts must carry a per-response nonce or matching hash, the design Google recommends.",
             evidence="script-src " + " ".join(scripts)[:200])
    elif level == "moderate":
        f.add("csp.allowlist", Severity.INFO, f"Allowlist-based Content Security Policy{where}",
              "Better than nothing: it blocks inline and unknown-host scripts. Allowlists are hard to keep tight; "
              "a nonce-based policy is stronger.", evidence="script-src " + " ".join(scripts)[:200])
    return level
