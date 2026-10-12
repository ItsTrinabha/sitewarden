import pytest

from sitewarden import scoring
from sitewarden.domains import hsts_preloaded, public_suffix, registrable_domain
from sitewarden.http import cookies, csp, jslibs
from sitewarden.http.client import Response
from sitewarden.http.headers import CORS_PROBE_ORIGIN, analyze_headers, analyze_transport, parse_hsts
from sitewarden.models import Finding, Severity
from sitewarden.net import is_public_ip, split_host
from sitewarden.scan import ScanError, normalize_target
from sitewarden.tls import ciphers


def ids(findings):
    return {f.id for f in findings}


# ---------- targets and addresses ----------

@pytest.mark.parametrize("raw,host,port", [
    ("example.com", "example.com", None),
    ("https://Example.com/path?q=1", "example.com", None),
    ("example.com:8443", "example.com", 8443),
    ("bücher.de", "xn--bcher-kva.de", None),
])
def test_normalize_target(raw, host, port):
    assert normalize_target(raw) == (host, port)


@pytest.mark.parametrize("bad", ["", "localhost", "exa mple.com", "-bad-.com"])
def test_normalize_rejects(bad):
    with pytest.raises(ScanError):
        normalize_target(bad)


@pytest.mark.parametrize("ip,public", [
    ("8.8.8.8", True), ("10.0.0.1", False), ("127.0.0.1", False), ("169.254.169.254", False),
    ("100.64.0.1", False), ("::1", False), ("fd00::1", False), ("2606:4700::1111", True),
    ("::ffff:10.0.0.1", False), ("0.0.0.0", False),
])
def test_is_public_ip(ip, public):
    assert is_public_ip(ip) is public


def test_split_host_ipv6():
    assert split_host("[2001:db8::1]:8443") == ("2001:db8::1", 8443)


# ---------- public suffix list and HSTS preload ----------

def test_psl():
    assert public_suffix("www.bbc.co.uk") == "co.uk"
    assert registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert registrable_domain("foo.github.io") == "foo.github.io"


def test_hsts_preload_list():
    assert hsts_preloaded("github.com")[0]
    assert hsts_preloaded("sub.anything.dev")[0]  # the whole .dev TLD is preloaded
    assert not hsts_preloaded("example.com")[0]


# ---------- ciphers ----------

def test_cipher_classification():
    reg = ciphers.registry()
    assert len(reg) > 200
    rc4 = ciphers.get(0x0005)
    assert rc4.rc4 and rc4.strength == "insecure"
    gcm = ciphers.get(0xC02F)
    assert gcm.aead and gcm.forward_secret and gcm.strength == "strong"
    cbc = ciphers.get(0x002F)
    assert cbc.cbc and not cbc.forward_secret
    assert ciphers.get(0x000A).block_64bit
    assert ciphers.get(0x1301).min_version == 0x0304


def test_probe_suites_no_tls13_in_tls12():
    suites = ciphers.probe_suites(0x0303)
    assert 0x1301 not in suites and 0xC02F in suites


# ---------- HSTS ----------

def test_parse_hsts():
    h = parse_hsts("max-age=63072000; includeSubDomains; preload")
    assert h["max_age"] == 63072000 and h["include_subdomains"] and h["preload"]
    assert parse_hsts("max-age=abc").get("max_age") in (None, 0) or parse_hsts("max-age=abc").get("errors")


def _resp(url, status=200, headers=(), body=b"<html></html>"):
    return Response(url=url, status=status, headers=list(headers), body=body)


def test_transport_redirect_and_hsts():
    http = [_resp("http://example.com/", 301, [("Location", "https://example.com/")]),
            _resp("https://example.com/", 200, [("Strict-Transport-Security", "max-age=31536000")])]
    f, facts = analyze_transport("example.com", http, http[1:])
    assert "transport.no_redirect" not in ids(f)
    assert facts is not None


def test_transport_no_redirect():
    http = [_resp("http://example.com/", 200, [("Content-Type", "text/html")])]
    https = [_resp("https://example.com/", 200, [("Content-Type", "text/html")])]
    f, _ = analyze_transport("example.com", http, https)
    titles = " ".join(x.title for x in f)
    assert "without redirecting" in titles
    assert "HSTS" in titles


def test_headers_good_site():
    resp = _resp("https://example.com/", 200, [
        ("Content-Type", "text/html"),
        ("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"),
        ("Content-Security-Policy", "script-src 'nonce-abc' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("Permissions-Policy", "camera=()"),
        ("Cross-Origin-Opener-Policy", "same-origin"),
    ])
    f, _ = analyze_headers("example.com", resp)
    bad = [x for x in f if x.severity.rank >= Severity.LOW.rank]
    assert not bad, [x.title for x in bad]


def test_cors_reflection():
    resp = _resp("https://example.com/", 200, [("Content-Type", "text/html")])
    cors = _resp("https://example.com/", 200, [("Access-Control-Allow-Origin", CORS_PROBE_ORIGIN),
                                                ("Access-Control-Allow-Credentials", "true")])
    f, _ = analyze_headers("example.com", resp, cors)
    assert any("CORS" in x.title and x.severity == Severity.HIGH for x in f)


def test_eol_banner():
    resp = _resp("https://example.com/", 200, [("Server", "Apache/2.2.15 (CentOS)"), ("X-Powered-By", "PHP/5.6.40")])
    f, _ = analyze_headers("example.com", resp)
    assert sum("End-of-life" in x.title for x in f) == 2


# ---------- CSP ----------

def test_csp_strict():
    f, v = csp.evaluate(["script-src 'nonce-r4nd0m' 'strict-dynamic'; object-src 'none'; base-uri 'none'"], [], [])
    assert v.level == "strict"


def test_csp_unsafe_inline_is_weak():
    f, v = csp.evaluate(["default-src 'self' 'unsafe-inline' 'unsafe-eval'"], [], [])
    assert v.level == "weak"
    assert any("unsafe-inline" in (x.title + x.detail) for x in f)


def test_csp_bypass_host():
    f, v = csp.evaluate(["script-src 'self' https://ajax.googleapis.com; object-src 'none'"], [], [])
    assert any("googleapis" in (x.evidence or "") + x.detail for x in f)


def test_csp_static_nonce():
    f, v = csp.evaluate(["script-src 'nonce-abc' 'strict-dynamic'; object-src 'none'; base-uri 'none'"], [], [],
                        nonce_values=[{"abc"}, {"abc"}])
    assert "csp.static_nonce" in ids(f) and v.level == "weak"


def test_csp_report_only_and_missing():
    assert csp.evaluate([], ["default-src 'self'"], [])[1].level == "report-only"
    assert csp.evaluate([], [], [])[1].level == "none"


def test_csp_wildcard():
    f, v = csp.evaluate(["script-src *; object-src 'none'"], [], [])
    assert v.level == "weak"


# ---------- cookies ----------

def test_cookie_flags():
    good = cookies.parse_set_cookie("__Host-sid=x; Path=/; Secure; HttpOnly; SameSite=Lax", "https://e.com/")
    assert good.secure and good.httponly and good.samesite.lower() == "lax"
    f, _ = cookies.analyze("e.com", [good])
    assert not [x for x in f if x.severity.rank >= Severity.LOW.rank]
    bad = cookies.parse_set_cookie("PHPSESSID=abc; path=/", "https://e.com/")
    f, _ = cookies.analyze("e.com", [bad])
    sev = {x.title: x.severity for x in f}
    assert any("Secure" in t for t in sev)


def test_cookie_jwt_none():
    c = cookies.parse_set_cookie("t=eyJhbGciOiJub25lIn0.eyJ1IjoxfQ.; Secure; HttpOnly; SameSite=Strict", "https://e.com/")
    f, _ = cookies.analyze("e.com", [c])
    assert any("alg=none" in x.title for x in f)


def test_cookie_bad_host_prefix():
    c = cookies.parse_set_cookie("__Host-x=1; Secure; Path=/; Domain=e.com", "https://e.com/")
    f, _ = cookies.analyze("e.com", [c])
    assert any("__Host-" in x.title or "prefix" in x.title.lower() for x in f)


# ---------- JavaScript libraries ----------

def test_jslib_version_compare():
    assert jslibs.is_at_or_above("3.5.0", "3.4.1")
    assert not jslibs.is_at_or_above("1.12.4", "3.0.0")
    assert jslibs.is_at_or_above("3.0.0", "3.0.0-rc1")


def test_jslib_cdn_url():
    dets = jslibs.scan_url("https://code.jquery.com/jquery-1.12.4.min.js")
    assert dets and dets[0].library.lower() == "jquery" and dets[0].version == "1.12.4" and dets[0].vulnerabilities


def test_jslib_content_banner():
    dets = jslibs.scan_content("x.js", "/*! jQuery v3.7.1 | (c) OpenJS Foundation */")
    assert dets and dets[0].version == "3.7.1" and not dets[0].vulnerabilities


def test_jslib_hash_suffix_not_in_version():
    dets = jslibs.scan_url("https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.11/lodash.min.js")
    assert dets and dets[0].version == "4.17.11"


# ---------- scoring ----------

def _f(sev, cat="tls", cap=None):
    return Finding(id=f"x.{sev}", category=cat, severity=sev, title=str(sev), detail="", cap=cap)


def test_grade_perfect_is_a_plus():
    g = scoring.grade([_f(Severity.PASS)], set())
    assert g["grade"] == "A+" and g["score"] == 100


def test_grade_medium_blocks_a_plus():
    g = scoring.grade([_f(Severity.MEDIUM, "email")], set())
    assert g["grade"] == "A"


def test_grade_cap_applies():
    g = scoring.grade([_f(Severity.LOW, cap="F")], set())
    assert g["grade"] == "F" and g["capped_by"]


def test_skipped_category_excluded():
    g = scoring.grade([_f(Severity.CRITICAL, "email")], {"email"})
    assert g["grade"] == "A+" and g["categories"]["email"]["skipped"]


def test_letters_monotonic():
    order = scoring.GRADES if hasattr(scoring, "GRADES") else None
    prev = None
    for s in range(100, -1, -5):
        g = scoring.letter(s)
        if prev and order:
            assert order.index(g) >= order.index(prev)
        prev = g
