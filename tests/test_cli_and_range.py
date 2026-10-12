import json
import subprocess
import sys

import pytest

from lab import pki

from .localsite import Site


@pytest.fixture(scope="module")
def site(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki")
    c = pki.build_range_pki(d, "lab.test")
    s = Site(*c["legacy"], host="legacy.lab.test", hardened=False)
    yield d, s
    s.close()


def test_cli_scan_json_and_fail_under(site, lab_dns, tmp_path):
    d, s = site
    port, _ = lab_dns
    out = tmp_path / "r.json"
    cmd = [sys.executable, "-m", "sitewarden", "scan", "legacy.lab.test", "--port", str(s.https_port),
           "--http-port", str(s.http_port), "--dns", "127.0.0.1", "--dns-port", str(port),
           "--ca-file", str(d / "root.pem"), "--allow-private", "--no-smtp", "--no-revocation",
           "--json", str(out), "--fail-under", "B", "-q"]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    report = json.loads(out.read_text())
    assert report["grade"] in ("D", "E", "F")
    assert p.returncode != 0, p.stdout + p.stderr  # below B, so the CI gate fails


def test_cli_refuses_private_without_flag(lab_dns):
    port, _ = lab_dns
    p = subprocess.run([sys.executable, "-m", "sitewarden", "scan", "legacy.lab.test", "--dns", "127.0.0.1",
                        "--dns-port", str(port), "-q"], capture_output=True, text=True, timeout=60)
    assert p.returncode != 0
    assert "private" in (p.stdout + p.stderr).lower() or "public" in (p.stdout + p.stderr).lower()


def test_cli_version():
    p = subprocess.run([sys.executable, "-m", "sitewarden", "--version"], capture_output=True, text=True)
    assert "1.0.0" in p.stdout + p.stderr


@pytest.mark.docker
def test_docker_range():
    """Real nginx 1.10 / OpenSSL 1.0.1 and current nginx / OpenSSL 3.5 in Docker."""
    from lab import range as lab_range

    try:
        lab_range.up()
    except (subprocess.CalledProcessError, SystemExit) as exc:
        pytest.skip(f"docker range could not start: {exc}")
    try:
        reports = {r["target"].split(".")[0]: r for r in lab_range.scan_all()}
    finally:
        lab_range.down()
    modern, legacy = reports["modern"], reports["legacy"]
    assert modern["grade"] in ("A+", "A")
    assert "X25519MLKEM768" in modern["tls"]["groups"]
    assert modern["tls"]["post_quantum"]
    assert legacy["grade"] == "F"
    assert legacy["tls"]["protocols"]["TLS 1.0"]
    assert any("RC4" in f["title"] for f in legacy["findings"])
    assert any("Diffie-Hellman" in f["title"] for f in legacy["findings"])
    assert any(f["id"].startswith("cert.") and "expired" in f["title"].lower() for f in reports["expired"]["findings"])
    assert any("does not cover" in f["title"] for f in reports["wronghost"]["findings"])
    assert any("Incomplete" in f["title"] for f in reports["incomplete"]["findings"])
    assert any("SHA1" in f["title"] for f in reports["sha1"]["findings"])
