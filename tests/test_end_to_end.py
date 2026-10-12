"""Full scans (TLS, certificate, HTTP, content, DNS, email) of local sites resolved through the lab DNS."""

import pytest

from lab import pki
from sitewarden.net import Network
from sitewarden.report import html as html_report
from sitewarden.report import markdown
from sitewarden.report.console import render
from sitewarden.scan import ScanOptions, run_scan

from .localsite import Site


@pytest.fixture(scope="module")
def certs(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki")
    return d, pki.build_range_pki(d, "lab.test")


@pytest.fixture(scope="module")
def sites(certs):
    d, c = certs
    good = Site(*c["modern"], host="modern.lab.test", hardened=True)
    bad = Site(*c["legacy"], host="legacy.lab.test", hardened=False)
    yield good, bad
    good.close()
    bad.close()


def _scan(lab_dns, certs, site, host):
    port, anchors = lab_dns
    d, _ = certs
    net = Network(allow_private=True, nameservers=["127.0.0.1"], dns_port=port,
                  extra_roots=[(d / "root.pem").read_bytes()], dns_timeout=2)
    opts = ScanOptions(port=site.https_port, http_port=site.http_port, smtp=False, dnssec_anchors=anchors,
                       timeout=4, revocation=False)
    return run_scan(host, net, opts)


def test_hardened_site(lab_dns, certs, sites):
    good, _ = sites
    r = _scan(lab_dns, certs, good, "modern.lab.test")
    assert not r.get("errors"), r.get("errors")
    assert r["grade"] in ("A+", "A", "A-"), [(f["severity"], f["title"]) for f in r["findings"] if f["severity"] != "pass"]
    assert r["tls"]["protocols"]["TLS 1.3"]
    assert r["dns"]["dnssec"]["status"] == "secure"
    assert r["categories"]["cookies"]["score"] == 100
    # every report format renders
    assert "Sitewarden" in render(r)
    assert r["target"] in markdown.render(r)
    assert "<html" in html_report.render(r).lower()


def test_weak_site(lab_dns, certs, sites):
    _, bad = sites
    r = _scan(lab_dns, certs, bad, "legacy.lab.test")
    titles = " | ".join(f["title"] for f in r["findings"])
    assert r["grade"] in ("D", "E", "F")
    assert "compromised CDN" in titles
    assert "without redirecting" in titles
    assert "End-of-life" in titles
    assert "jquery 1.12.4" in titles


def test_untrusted_root_is_flagged(lab_dns, certs, sites):
    good, _ = sites
    port, anchors = lab_dns
    net = Network(allow_private=True, nameservers=["127.0.0.1"], dns_port=port, dns_timeout=2)  # no lab root
    r = run_scan("modern.lab.test", net, ScanOptions(port=good.https_port, http_port=good.http_port, smtp=False,
                                                     dnssec_anchors=anchors, timeout=4, revocation=False))
    assert r["grade"] == "F" or any("not trusted" in f["title"] for f in r["findings"])
    assert any(f["category"] == "certificate" and f["severity"] in ("critical", "high") for f in r["findings"])


def test_private_address_refused_by_default(lab_dns):
    port, _ = lab_dns
    from sitewarden.scan import ScanError

    net = Network(nameservers=["127.0.0.1"], dns_port=port, dns_timeout=2)
    with pytest.raises(ScanError):
        run_scan("modern.lab.test", net, ScanOptions())
