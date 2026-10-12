"""The web API, driven end to end against a local lab site."""

import time

import pytest
from fastapi.testclient import TestClient

from lab import pki
from sitewarden.net import Network
from sitewarden.scan import ScanOptions
from sitewarden.web.app import RateLimiter, create_app

from .localsite import Site


@pytest.fixture(scope="module")
def site(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki")
    c = pki.build_range_pki(d, "lab.test")
    s = Site(*c["modern"], host="modern.lab.test")
    yield d, s
    s.close()


@pytest.fixture
def client(tmp_path, site, lab_dns):
    d, s = site
    port, anchors = lab_dns

    def net():
        return Network(allow_private=True, nameservers=["127.0.0.1"], dns_port=port,
                       extra_roots=[(d / "root.pem").read_bytes()], dns_timeout=2)

    app = create_app(str(tmp_path / "t.db"), net_factory=net,
                     scan_options=ScanOptions(port=s.https_port, http_port=s.http_port, smtp=False,
                                              dnssec_anchors=anchors, timeout=4, revocation=False))
    with TestClient(app) as c:
        yield c


def _wait(client, scan_id, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        r = client.get(f"/api/scans/{scan_id}").json()
        if r["status"] in ("done", "error"):
            return r
        time.sleep(0.3)
    raise AssertionError("scan did not finish")


def test_security_headers_on_app(client):
    r = client.get("/")
    assert r.status_code == 200
    csp = r.headers["content-security-policy"]
    assert "require-trusted-types-for 'script'" in csp and "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "max-age" in r.headers["strict-transport-security"]
    assert client.get("/api/health").json()["ok"]


def test_scan_lifecycle(client):
    r = client.post("/api/scans", json={"target": "https://modern.lab.test/"})
    assert r.status_code == 202
    scan_id = r.json()["id"]
    done = _wait(client, scan_id)
    assert done["status"] == "done", done
    assert done["report"]["grade"].startswith("A")
    # cached on the second request
    again = client.post("/api/scans", json={"target": "modern.lab.test"}).json()
    assert again["cached"] and again["id"] == scan_id
    for fmt, needle in (("json", '"grade"'), ("md", "modern.lab.test"), ("html", "<html")):
        exp = client.get(f"/api/scans/{scan_id}/report.{fmt}")
        assert exp.status_code == 200 and needle in exp.text.lower() if fmt == "html" else needle in exp.text
    badge = client.get("/badge/modern.lab.test.svg")
    assert badge.status_code == 200 and "<svg" in badge.text and done["report"]["grade"] in badge.text
    events = client.get(f"/api/scans/{scan_id}/events")
    assert "event: end" in events.text
    assert any(x["target"] == "modern.lab.test" for x in client.get("/api/recent").json()["recent"])


def test_hidden_scans_not_listed(client):
    scan_id = client.post("/api/scans", json={"target": "www.lab.test", "hidden": True}).json()["id"]
    _wait(client, scan_id)
    assert all(x["target"] != "www.lab.test" for x in client.get("/api/recent").json()["recent"])


@pytest.mark.parametrize("target,code", [("not a domain", 400), ("example.com:8443", 400), ("", 400), ("x" * 400, 422)])
def test_bad_targets(client, target, code):
    assert client.post("/api/scans", json={"target": target}).status_code == code


def test_unknown_scan(client):
    assert client.get("/api/scans/doesnotexist123").status_code == 404
    assert client.get("/api/scans/..%2f..%2fetc%2fpasswd").status_code == 404


def test_static_traversal(client):
    assert client.get("/static/..%2f..%2fapp.py").status_code == 404
    assert client.get("/static/app.js").status_code == 200


def test_rate_limiter():
    rl = RateLimiter(2)
    assert rl.allow("a")[0] and rl.allow("a")[0]
    ok, retry = rl.allow("a")
    assert not ok and retry > 0
    assert rl.allow("b")[0]


def test_security_txt_is_current(client):
    txt = client.get("/.well-known/security.txt").text
    year = int(txt.split("Expires: ")[1][:4])
    assert year >= time.gmtime().tm_year
