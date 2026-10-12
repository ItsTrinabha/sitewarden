"""HTTPS enforcement, HSTS and response-header analysis."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..domains import hsts_preloaded, registrable_domain
from ..models import Findings, Severity
from ..remediation import SNIPPETS
from .client import Response

SIX_MONTHS = 15768000
ONE_YEAR = 31536000

# End-of-life releases that commonly leak through Server / X-Powered-By banners.
EOL_BANNERS = [
    (re.compile(r"PHP/(5\.\d+|7\.\d+|8\.0)\b"), "PHP {0} is end-of-life and no longer receives security fixes"),
    (re.compile(r"PHP/(8\.1)\b"), "PHP {0} reached end-of-life on 31 Dec 2025"),
    (re.compile(r"Apache/(2\.[02])\.\d+"), "Apache httpd {0} has been end-of-life since 2017 or earlier"),
    (re.compile(r"OpenSSL/(0\.9\.\d\w*|1\.0\.\d\w*)"), "OpenSSL {0} is end-of-life (1.0.2 ended in 2019)"),
    (re.compile(r"OpenSSL/(1\.1\.\d\w*)"), "OpenSSL {0} reached end-of-life in September 2023"),
    (re.compile(r"Microsoft-IIS/([5-7]\.\d)"), "IIS {0} ships with an end-of-life version of Windows Server"),
    (re.compile(r"ASP\.NET.*?\b([1-3]\.\d)"), "ASP.NET {0} is end-of-life"),
    (re.compile(r"nginx/(0\.\d+\.\d+|1\.(?:[0-9]|1[0-9])\.\d+)\b"), "nginx {0} is several years out of date"),
]


def _duration(seconds: int) -> str:
    if seconds >= 86400 * 365:
        y = seconds / (86400 * 365)
        return f"{y:g} year" + ("s" if y != 1 else "") if y == int(y) else f"{seconds // 86400} days"
    if seconds >= 86400:
        return f"{seconds // 86400} days"
    if seconds >= 3600:
        return f"{seconds // 3600} hour" + ("s" if seconds >= 7200 else "")
    return f"{seconds} seconds"


def parse_hsts(value: str) -> dict:
    out = {"max_age": None, "include_subdomains": False, "preload": False, "valid": True, "raw": value}
    seen = set()
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        name, _, val = part.partition("=")
        name = name.strip().lower()
        if name in seen:
            out["valid"] = False  # RFC 6797: duplicate directives invalidate the header
        seen.add(name)
        if name == "max-age":
            try:
                out["max_age"] = int(val.strip().strip('"'))
            except ValueError:
                out["valid"] = False
        elif name == "includesubdomains":
            out["include_subdomains"] = True
        elif name == "preload":
            out["preload"] = True
    if out["max_age"] is None:
        out["valid"] = False
    return out


def _is_html(r: Response) -> bool:
    ctype = (r.header("content-type") or "").lower()
    return "html" in ctype or (not ctype and r.body[:200].lstrip().lower().startswith((b"<!doctype", b"<html")))


def analyze_transport(host: str, http_hops: list[Response], https_hops: list[Response]) -> tuple[Findings, dict]:
    """HTTP->HTTPS redirect behaviour and HSTS."""
    f = Findings("headers")
    facts: dict = {}
    first_http = http_hops[0] if http_hops else None
    final_http = http_hops[-1] if http_hops else None
    final_https = https_hops[-1] if https_hops else None
    preloaded, entry = hsts_preloaded(host)
    facts["hsts_preloaded"] = preloaded
    facts["hsts_preload_entry"] = entry
    facts["http_redirects"] = [{"url": h.url, "status": h.status, "error": h.error} for h in http_hops]
    facts["https_redirects"] = [{"url": h.url, "status": h.status, "error": h.error} for h in https_hops]

    # --- plain HTTP behaviour ---
    if first_http is None or not first_http.ok:
        facts["http_listening"] = False
        f.add("http.port80_closed", Severity.INFO, "Port 80 (plain HTTP) is closed or unreachable",
              "Visitors who type the bare domain rely on HSTS or the browser's HTTPS-first mode to reach you.",
              evidence=first_http.error if first_http else None)
    else:
        facts["http_listening"] = True
        final_scheme = urlsplit(final_http.url).scheme if final_http else "http"
        if final_scheme != "https":
            sev = Severity.LOW if preloaded else Severity.HIGH
            f.add("http.no_redirect", sev, "Plain HTTP is served without redirecting to HTTPS",
                  "Visitors arriving over http:// stay on an unencrypted connection that anyone on the network "
                  "can read or modify." + (" The domain is HSTS-preloaded, so modern browsers never use it." if preloaded else ""),
                  evidence=f"GET http://{host}/ -> {final_http.status} at {final_http.url}",
                  fix="Redirect every HTTP request to HTTPS with a 301.", snippets=SNIPPETS["https_redirect"],
                  cap=None if preloaded else "C", tags=["CWE-319"])
        else:
            first_hop = urlsplit(http_hops[1].url) if len(http_hops) > 1 else None
            insecure_mid = [h.url for h in http_hops[1:-1] if urlsplit(h.url).scheme == "http"]
            if insecure_mid:
                f.add("http.redirect_via_http", Severity.MEDIUM, "Redirect chain passes through another plain-HTTP URL",
                      "Each unencrypted hop can be intercepted or rewritten.", evidence=" -> ".join(h.url for h in http_hops))
            elif first_hop and first_hop.hostname != host:
                f.add("http.redirect_other_host", Severity.INFO, "HTTP redirects straight to a different host",
                      f"http://{host} goes to {first_hop.scheme}://{first_hop.hostname} first. HSTS preloading "
                      f"requires redirecting to https://{host} before switching hosts, so the browser can pick up "
                      "this host's HSTS header.", evidence=" -> ".join(h.url for h in http_hops))
            else:
                f.ok("http.redirect", "HTTP redirects to HTTPS",
                     evidence=" -> ".join(f"{h.url} [{h.status}]" for h in http_hops[:4]))
            if first_http.status in (302, 303, 307):
                f.add("http.temporary_redirect", Severity.INFO, f"HTTP-to-HTTPS redirect is temporary ({first_http.status})",
                      "A 301 or 308 is cached by browsers and passes search ranking to the HTTPS URL.")

    # --- HTTPS-side redirects ---
    if https_hops and len(https_hops) > 1:
        downgrade = [h.url for h in https_hops[1:] if urlsplit(h.url).scheme == "http"]
        if downgrade:
            f.add("http.https_downgrade", Severity.HIGH, "HTTPS redirects back to plain HTTP",
                  "Users who reach the secure site are sent to an unencrypted URL.",
                  evidence=" -> ".join(h.url for h in https_hops), cap="C", tags=["CWE-319"])

    # --- HSTS ---
    if final_https is None or not final_https.ok:
        return f, facts
    https_on_host = [h for h in https_hops if urlsplit(h.url).hostname == host and h.ok]
    hsts_resp = https_on_host[0] if https_on_host else final_https
    raw = hsts_resp.header_all("strict-transport-security")
    final_raw = final_https.header_all("strict-transport-security")
    if not raw and final_raw and hsts_resp is not final_https:
        f.add("hsts.redirect_missing", Severity.LOW, f"HSTS is set on {urlsplit(final_https.url).hostname} but not on {host}",
              f"The redirect from https://{host} does not carry the header, so the bare host never gets HSTS.")
    if not raw:
        raw = final_raw
    if not raw:
        sev = Severity.LOW if preloaded else Severity.MEDIUM
        f.add("hsts.missing", sev, "HTTP Strict Transport Security (HSTS) not enabled",
              "Without HSTS a network attacker can strip HTTPS (sslstrip) whenever a user follows an http:// link "
              "or types the bare domain, and users can click through certificate warnings.",
              fix="Send Strict-Transport-Security with max-age of at least one year.", snippets=SNIPPETS["hsts"],
              tags=["CWE-319", "CWE-523"], refs=["https://www.rfc-editor.org/rfc/rfc6797"])
        facts["hsts"] = None
    else:
        h = parse_hsts(raw[0])
        facts["hsts"] = h
        if not h["valid"]:
            f.add("hsts.invalid", Severity.MEDIUM, "HSTS header is malformed and ignored by browsers",
                  evidence=raw[0], fix="Use: max-age=63072000; includeSubDomains; preload", snippets=SNIPPETS["hsts"])
        elif h["max_age"] == 0:
            f.add("hsts.disabled", Severity.MEDIUM, "HSTS is explicitly disabled (max-age=0)", evidence=raw[0])
        elif h["max_age"] < SIX_MONTHS:
            f.add("hsts.short", Severity.LOW, f"HSTS max-age is short ({_duration(h['max_age'])})",
                  "Protection lapses for users who have not visited within that window. Six months is the "
                  "usual minimum and one year is required for preloading.", evidence=raw[0], snippets=SNIPPETS["hsts"])
        else:
            f.ok("hsts.enabled", f"HSTS enabled (max-age {_duration(h['max_age'])})", evidence=raw[0])
        if h["valid"] and h["max_age"] and not h["include_subdomains"]:
            f.add("hsts.subdomains", Severity.INFO, "HSTS does not include subdomains",
                  "An attacker can use an unprotected subdomain to set cookies for the parent domain.")
        if len(raw) > 1:
            f.add("hsts.multiple", Severity.LOW, "Multiple HSTS headers", "Browsers use only the first one.",
                  evidence=" | ".join(raw))

    reg = registrable_domain(host)
    if preloaded:
        f.ok("hsts.preloaded", "In the browser HSTS preload list",
             f"Browsers use HTTPS for this host before the first visit (entry: {entry}).")
    elif host == reg and facts.get("hsts") and facts["hsts"]["valid"]:
        h = facts["hsts"]
        missing = []
        if (h["max_age"] or 0) < ONE_YEAR:
            missing.append("max-age >= 31536000")
        if not h["include_subdomains"]:
            missing.append("includeSubDomains")
        if not h["preload"]:
            missing.append("preload")
        if facts.get("http_listening") and any(x.startswith("http.no_redirect") or x == "http.redirect_other_host"
                                               for x in (g.id for g in f)):
            missing.append("HTTP redirect to https://" + host)
        if missing:
            f.add("hsts.preload_ready", Severity.INFO, "Not yet eligible for HSTS preloading",
                  "Missing: " + ", ".join(missing) + ".", refs=["https://hstspreload.org/"])
        else:
            f.add("hsts.preload_ready", Severity.INFO, "Eligible for HSTS preloading, but not on the list yet",
                  "Submit the domain at hstspreload.org.", refs=["https://hstspreload.org/"])
    return f, facts


def analyze_headers(host: str, resp: Response, cors_resp: Response | None = None) -> tuple[Findings, dict]:
    f = Findings("headers")
    facts: dict = {"status": resp.status, "url": resp.url}
    html = _is_html(resp)
    csp_values = [v.lower() for v in resp.header_all("content-security-policy")]
    has_frame_ancestors = any("frame-ancestors" in v for v in csp_values)

    # --- clickjacking ---
    xfo = resp.header("x-frame-options")
    if has_frame_ancestors:
        f.ok("hdr.framing", "Framing controlled by CSP frame-ancestors")
    elif xfo:
        v = xfo.strip().upper()
        if v in ("DENY", "SAMEORIGIN"):
            f.ok("hdr.framing", f"X-Frame-Options: {v}")
        else:
            f.add("hdr.framing", Severity.MEDIUM, f"Invalid X-Frame-Options value '{xfo}'",
                  "ALLOW-FROM is ignored by every current browser; unknown values give no protection.",
                  fix="Use frame-ancestors in CSP, or X-Frame-Options: SAMEORIGIN.", snippets=SNIPPETS["frame"],
                  tags=["CWE-1021"])
    elif html:
        f.add("hdr.framing", Severity.MEDIUM, "Page can be embedded by any site (clickjacking)",
              "No X-Frame-Options or CSP frame-ancestors. A malicious page can load this site in an invisible "
              "frame and trick users into clicking buttons on it.",
              fix="Send CSP frame-ancestors 'self' (and X-Frame-Options: SAMEORIGIN for old browsers).",
              snippets=SNIPPETS["frame"], tags=["CWE-1021", "OWASP A04:2021"])

    # --- MIME sniffing ---
    xcto = (resp.header("x-content-type-options") or "").strip().lower()
    if xcto == "nosniff":
        f.ok("hdr.nosniff", "X-Content-Type-Options: nosniff")
    else:
        f.add("hdr.nosniff", Severity.LOW, "X-Content-Type-Options: nosniff not set" if not xcto else f"Invalid X-Content-Type-Options '{xcto}'",
              "Browsers may guess ('sniff') content types and run an uploaded file as script or HTML.",
              snippets=SNIPPETS["nosniff"], tags=["CWE-430"])

    # --- referrer ---
    rp = resp.header("referrer-policy")
    if rp:
        last = [t.strip().lower() for t in rp.split(",") if t.strip()]
        effective = last[-1] if last else ""
        if effective in ("unsafe-url", "no-referrer-when-downgrade"):
            f.add("hdr.referrer", Severity.LOW, f"Referrer-Policy '{effective}' leaks full URLs",
                  "Complete URLs, including paths and query strings that may hold tokens or personal data, are sent "
                  "to every third party the page links to or loads.", snippets=SNIPPETS["referrer"],
                  tags=["CWE-200"])
        else:
            f.ok("hdr.referrer", f"Referrer-Policy: {effective}")
    elif html:
        f.add("hdr.referrer", Severity.INFO, "No Referrer-Policy header",
              "Browsers default to strict-origin-when-cross-origin, which is reasonable. Setting it explicitly "
              "protects users of older browsers.", snippets=SNIPPETS["referrer"])

    # --- permissions / isolation ---
    pp = resp.header("permissions-policy")
    if pp:
        f.ok("hdr.permissions", "Permissions-Policy set", evidence=pp[:200])
    elif resp.header("feature-policy"):
        f.add("hdr.permissions", Severity.INFO, "Uses the obsolete Feature-Policy header",
              "Browsers now read Permissions-Policy.", snippets=SNIPPETS["permissions"])
    elif html:
        f.add("hdr.permissions", Severity.INFO, "No Permissions-Policy",
              "Restricting powerful features (camera, microphone, geolocation, payment) limits what injected or "
              "third-party code can do.", snippets=SNIPPETS["permissions"])
    coop = (resp.header("cross-origin-opener-policy") or "").lower()
    if coop.startswith("same-origin"):
        f.ok("hdr.coop", f"Cross-Origin-Opener-Policy: {coop}")
    elif html:
        f.add("hdr.coop", Severity.INFO, "No Cross-Origin-Opener-Policy",
              "COOP severs window references from cross-origin popups, blocking a class of cross-site leaks "
              "(XS-Leaks) and tabnabbing.", snippets=SNIPPETS["isolation"])
    corp = resp.header("cross-origin-resource-policy")
    if corp:
        f.ok("hdr.corp", f"Cross-Origin-Resource-Policy: {corp}")
    if resp.header("cross-origin-embedder-policy"):
        f.ok("hdr.coep", f"Cross-Origin-Embedder-Policy: {resp.header('cross-origin-embedder-policy')}")

    # --- legacy / deprecated ---
    xxp = (resp.header("x-xss-protection") or "").strip()
    if xxp and not xxp.startswith("0"):
        f.add("hdr.xss_protection", Severity.INFO, f"Legacy X-XSS-Protection: {xxp}",
              "The XSS auditor was removed from browsers; in old ones its blocking mode could itself be abused to "
              "leak data. Set it to 0 and rely on CSP.")
    if resp.header("public-key-pins") or resp.header("public-key-pins-report-only"):
        f.add("hdr.hpkp", Severity.LOW, "Deprecated HTTP Public Key Pinning header",
              "HPKP was removed from browsers because a wrong pin can lock users out for months. Remove it.")
    if resp.header("expect-ct"):
        f.add("hdr.expect_ct", Severity.INFO, "Obsolete Expect-CT header",
              "Certificate Transparency is now enforced by default; Expect-CT can be removed.")

    # --- information disclosure ---
    leaks = []
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator",
                 "x-runtime", "x-version", "x-drupal-cache", "x-varnish-version"):
        for v in resp.header_all(name):
            if re.search(r"\d", v) or name not in ("server",):
                leaks.append(f"{name}: {v}")
    if leaks:
        f.add("hdr.disclosure", Severity.LOW, "Software versions disclosed in headers",
              "Exact version banners let attackers match the server against public exploits without probing.",
              evidence="; ".join(leaks[:6]), snippets=SNIPPETS["server_tokens"], tags=["CWE-200"])
    for pattern, msg in EOL_BANNERS:
        for name in ("server", "x-powered-by", "x-aspnet-version"):
            for v in resp.header_all(name):
                m = pattern.search(v)
                if m:
                    f.add("hdr.eol_software", Severity.HIGH, "End-of-life software advertised: " + m.group(0),
                          msg.format(m.group(1)) + ". Known vulnerabilities in it will not be patched.",
                          evidence=f"{name}: {v}", tags=["CWE-1104", "OWASP A06:2021"])

    # --- caching of personalised responses ---
    cc = (resp.header("cache-control") or "").lower()
    if resp.header_all("set-cookie") and "public" in cc and "private" not in cc:
        f.add("hdr.cache_cookie", Severity.MEDIUM, "Response sets cookies but is marked publicly cacheable",
              "A shared cache (CDN, proxy) may store this response, including its Set-Cookie header, and serve "
              "one visitor's session cookie to others.", evidence=f"Cache-Control: {cc}", tags=["CWE-524"])

    # --- CORS ---
    acao = resp.header("access-control-allow-origin")
    acac = (resp.header("access-control-allow-credentials") or "").lower() == "true"
    facts["cors"] = {"allow_origin": acao, "allow_credentials": acac}
    if cors_resp is not None and cors_resp.ok:
        r_acao = cors_resp.header("access-control-allow-origin")
        r_acac = (cors_resp.header("access-control-allow-credentials") or "").lower() == "true"
        facts["cors"]["reflects_origin"] = r_acao == CORS_PROBE_ORIGIN
        if r_acao == CORS_PROBE_ORIGIN and r_acac:
            f.add("cors.reflect_credentials", Severity.HIGH, "CORS reflects any origin and allows credentials",
                  "Any website a logged-in user visits can read this site's authenticated responses.",
                  evidence=f"Origin: {CORS_PROBE_ORIGIN} -> Access-Control-Allow-Origin: {r_acao}, "
                           "Access-Control-Allow-Credentials: true",
                  fix="Allow only an explicit list of trusted origins.", snippets=SNIPPETS["cors"],
                  tags=["CWE-942", "OWASP A05:2021"])
        elif r_acao == CORS_PROBE_ORIGIN:
            f.add("cors.reflect", Severity.LOW, "CORS reflects any origin (without credentials)",
                  "Unauthenticated responses are readable cross-origin. Fine for public APIs; risky for intranet "
                  "or IP-restricted content.", evidence=f"Origin: {CORS_PROBE_ORIGIN} -> {r_acao}", tags=["CWE-942"])
        elif r_acao == "null" and r_acac:
            f.add("cors.null_origin", Severity.HIGH, "CORS trusts the 'null' origin with credentials",
                  "Sandboxed iframes and data: URLs send Origin: null, so any site can pose as it.", tags=["CWE-942"])
    if acao == "*" and acac:
        f.add("cors.wildcard_credentials", Severity.INFO, "CORS wildcard combined with credentials",
              "Browsers refuse this combination, so it does nothing, but it suggests a misunderstood CORS setup.")

    # --- protocol niceties ---
    if resp.alpn == "h2":
        f.ok("hdr.http2", "HTTP/2 supported")
    alt = resp.header("alt-svc") or ""
    if "h3" in alt:
        f.ok("hdr.http3", "HTTP/3 (QUIC) advertised", evidence=f"Alt-Svc: {alt[:120]}")
    facts["technology"] = fingerprint(resp)
    facts["headers"] = resp.headers
    return f, facts


CORS_PROBE_ORIGIN = "https://sitewarden-cors-check.invalid"


def fingerprint(resp: Response) -> dict:
    """Best-effort server, CDN and framework identification from headers and cookies."""
    h = {k.lower(): v for k, v in resp.headers}
    cookies = " ".join(resp.header_all("set-cookie")).lower()
    tech = {}
    server = h.get("server")
    if server:
        tech["server"] = server
    if h.get("x-powered-by"):
        tech["powered_by"] = h["x-powered-by"]
    cdn = None
    if "cf-ray" in h or (server or "").lower() == "cloudflare":
        cdn = "Cloudflare"
    elif "x-amz-cf-id" in h or "cloudfront" in (h.get("via") or "").lower():
        cdn = "Amazon CloudFront"
    elif "x-fastly-request-id" in h or "fastly" in (h.get("x-served-by") or "").lower() or "x-fastly" in " ".join(h):
        cdn = "Fastly"
    elif "akamai" in (server or "").lower() or "x-akamai-transformed" in h or "akamai-grn" in h:
        cdn = "Akamai"
    elif "x-vercel-id" in h:
        cdn = "Vercel"
    elif "x-nf-request-id" in h:
        cdn = "Netlify"
    elif "x-azure-ref" in h:
        cdn = "Azure Front Door"
    elif (server or "").lower().startswith("gws") or "x-goog" in " ".join(h):
        cdn = "Google"
    elif "x-github-request-id" in h:
        cdn = "GitHub"
    if cdn:
        tech["edge"] = cdn
    frameworks = []
    for needle, name in (("phpsessid", "PHP"), ("jsessionid", "Java servlet"), ("asp.net_sessionid", "ASP.NET"),
                         ("laravel_session", "Laravel"), ("csrftoken", "Django"), ("_rails", "Ruby on Rails"),
                         ("connect.sid", "Express"), ("wordpress_", "WordPress"), ("wp-settings", "WordPress"),
                         ("__cf_bm", "Cloudflare Bot Management"), ("_shopify", "Shopify")):
        if needle in cookies:
            frameworks.append(name)
    body = resp.body[:200000].decode("utf-8", "replace") if resp.body else ""
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if gen:
        frameworks.append(gen.group(1))
    if "/wp-content/" in body:
        frameworks.append("WordPress")
    if "__NEXT_DATA__" in body:
        frameworks.append("Next.js")
    if "data-reactroot" in body or "react-dom" in body:
        frameworks.append("React")
    if frameworks:
        tech["frameworks"] = sorted(set(frameworks))
    return tech
