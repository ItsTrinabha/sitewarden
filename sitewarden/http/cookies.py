"""Set-Cookie analysis: Secure, HttpOnly, SameSite, prefixes, scope and lifetime."""

from __future__ import annotations

import base64
import datetime as dt
import email.utils
import json
import re
from dataclasses import dataclass, field

from ..models import Findings, Severity
from ..remediation import SNIPPETS

SESSION_RE = re.compile(
    r"(sess|sid$|^sid|token|auth|login|jwt|remember|identity|account|user_?id|^id$|connect\.sid|"
    r"phpsessid|jsessionid|asp\.net_sessionid|aspxauth|laravel_session|_session$|access|refresh|bearer)",
    re.I,
)
NOT_SESSION_RE = re.compile(r"(csrf|xsrf|consent|cookieconsent|lang|locale|theme|_ga|_gid|_fbp|optanon|"
                            r"__utm|ab_?test|timezone|currency)", re.I)


@dataclass
class Cookie:
    name: str
    value: str
    attrs: dict[str, str] = field(default_factory=dict)
    flags: set[str] = field(default_factory=set)
    url: str = ""
    over_https: bool = True

    @property
    def secure(self) -> bool:
        return "secure" in self.flags

    @property
    def httponly(self) -> bool:
        return "httponly" in self.flags

    @property
    def samesite(self) -> str | None:
        v = self.attrs.get("samesite")
        return v.capitalize() if v else None

    @property
    def session_like(self) -> bool:
        return bool(SESSION_RE.search(self.name)) and not NOT_SESSION_RE.search(self.name)

    def lifetime_days(self) -> float | None:
        if "max-age" in self.attrs:
            try:
                return int(self.attrs["max-age"]) / 86400
            except ValueError:
                return None
        if "expires" in self.attrs:
            try:
                exp = email.utils.parsedate_to_datetime(self.attrs["expires"])
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=dt.UTC)
                return (exp - dt.datetime.now(dt.UTC)).total_seconds() / 86400
            except (TypeError, ValueError):
                return None
        return None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "value_length": len(self.value),
            "secure": self.secure,
            "httponly": self.httponly,
            "samesite": self.samesite,
            "domain": self.attrs.get("domain"),
            "path": self.attrs.get("path"),
            "lifetime_days": None if (d := self.lifetime_days()) is None else round(d, 1),
            "partitioned": "partitioned" in self.flags,
            "session_like": self.session_like,
            "set_by": self.url,
            "over_https": self.over_https,
        }


def parse_set_cookie(header: str, url: str = "", over_https: bool = True) -> Cookie | None:
    parts = header.split(";")
    name, sep, value = parts[0].partition("=")
    if not sep:
        return None
    c = Cookie(name.strip(), value.strip(), url=url, over_https=over_https)
    for p in parts[1:]:
        k, eq, v = p.strip().partition("=")
        k = k.strip().lower()
        if not k:
            continue
        if eq:
            c.attrs[k] = v.strip()
        else:
            c.flags.add(k)
    return c


def _jwt_alg(value: str) -> str | None:
    m = re.fullmatch(r"(eyJ[A-Za-z0-9_-]+)\.([A-Za-z0-9_-]*)\.([A-Za-z0-9_-]*)", value.strip('"'))
    if not m:
        return None
    try:
        pad = "=" * (-len(m.group(1)) % 4)
        header = json.loads(base64.urlsafe_b64decode(m.group(1) + pad))
        return str(header.get("alg", "?"))
    except (ValueError, json.JSONDecodeError):
        return None


def analyze(host: str, cookies: list[Cookie]) -> tuple[Findings, list[dict]]:
    f = Findings("cookies")
    if not cookies:
        f.add("cookie.none", Severity.INFO, "No cookies set on the scanned pages")
        return f, []

    def names(cs):
        return ", ".join(sorted({c.name for c in cs}))

    sess = [c for c in cookies if c.session_like]
    insecure = [c for c in cookies if c.over_https and not c.secure]
    insecure_sess = [c for c in insecure if c.session_like]
    if insecure_sess:
        f.add("cookie.secure_session", Severity.HIGH, "Session cookies without the Secure flag",
              "The browser will also send these cookies over plain HTTP, where a network attacker can steal the "
              "session (for example by injecting an http:// image into any page the user visits).",
              evidence=names(insecure_sess), snippets=SNIPPETS["cookies"], cap="B",
              tags=["CWE-614", "OWASP A02:2021"])
    other = [c for c in insecure if not c.session_like]
    if other:
        f.add("cookie.secure", Severity.LOW, f"{len(other)} cookie(s) without the Secure flag",
              "Cookies set over HTTPS should be marked Secure so they never travel over plain HTTP.",
              evidence=names(other), snippets=SNIPPETS["cookies"], tags=["CWE-614"])
    over_http = [c for c in cookies if not c.over_https]
    if over_http:
        f.add("cookie.set_over_http", Severity.MEDIUM, "Cookies are set over an unencrypted HTTP response",
              "Anyone on the network path can read or overwrite them before the redirect to HTTPS happens.",
              evidence=names(over_http), tags=["CWE-319"])
    no_httponly = [c for c in sess if not c.httponly]
    if no_httponly:
        f.add("cookie.httponly", Severity.MEDIUM, "Session cookies readable by JavaScript (no HttpOnly)",
              "Any XSS bug, or any compromised third-party script, can read and exfiltrate the session.",
              evidence=names(no_httponly), snippets=SNIPPETS["cookies"], tags=["CWE-1004"])
    no_samesite = [c for c in sess if not c.samesite]
    if no_samesite:
        f.add("cookie.samesite", Severity.LOW, "Session cookies without a SameSite attribute",
              "Chrome treats them as Lax, but Firefox and Safari do not, leaving cross-site request forgery "
              "protection to the application.", evidence=names(no_samesite), snippets=SNIPPETS["cookies"],
              tags=["CWE-1275", "CWE-352"])
    bad_none = [c for c in cookies if c.samesite == "None" and not c.secure]
    if bad_none:
        f.add("cookie.samesite_none", Severity.LOW, "SameSite=None cookies without Secure are rejected",
              "Browsers drop SameSite=None cookies that are not also Secure, so these cookies are never stored.",
              evidence=names(bad_none))
    for c in cookies:
        if c.name.startswith("__Host-") and (not c.secure or c.attrs.get("path", "/") != "/" or "domain" in c.attrs):
            f.add("cookie.prefix", Severity.MEDIUM, f"Cookie {c.name} violates the __Host- prefix rules",
                  "__Host- cookies must be Secure, Path=/ and have no Domain; browsers reject this one.")
        elif c.name.startswith("__Secure-") and not c.secure:
            f.add("cookie.prefix", Severity.MEDIUM, f"Cookie {c.name} violates the __Secure- prefix rule",
                  "__Secure- cookies must carry the Secure flag; browsers reject this one.")
        alg = _jwt_alg(c.value)
        if alg and alg.lower() == "none":
            f.add("cookie.jwt_none", Severity.HIGH, f"Cookie {c.name} holds an unsigned JWT (alg=none)",
                  "An unsigned token can be forged by anyone if the server accepts it.", tags=["CWE-347"])
        elif alg and not c.httponly:
            f.add("cookie.jwt_js", Severity.LOW, f"JWT in cookie {c.name} is readable by JavaScript",
                  "Bearer tokens in script-readable cookies are stolen by any XSS.", tags=["CWE-1004"])
    broad = [c for c in sess if c.attrs.get("domain")]
    if broad:
        f.add("cookie.domain", Severity.INFO, "Session cookies are shared with all subdomains",
              "A Domain attribute sends the cookie to every subdomain, so a compromised or taken-over subdomain "
              "receives the session.", evidence=", ".join(f"{c.name} (Domain={c.attrs['domain']})" for c in broad[:5]))
    long_lived = [c for c in sess if (d := c.lifetime_days()) is not None and d > 400]
    if long_lived:
        f.add("cookie.lifetime", Severity.INFO, "Session cookies live for more than 400 days",
              "Chrome caps cookie lifetime at 400 days; long sessions widen the window for stolen-cookie reuse.",
              evidence=names(long_lived))
    if sess and not (insecure_sess or no_httponly or no_samesite):
        f.ok("cookie.session_flags", "Session cookies use Secure, HttpOnly and SameSite", evidence=names(sess))
    elif not sess and not insecure:
        f.ok("cookie.flags", "All cookies carry the Secure flag", evidence=names(cookies))
    if any(c.name.startswith("__Host-") for c in cookies if c.secure):
        f.ok("cookie.host_prefix", "Uses __Host- prefixed cookies",
             "The strongest cookie scoping: bound to this exact host and HTTPS.")
    return f, [c.to_dict() for c in cookies]
