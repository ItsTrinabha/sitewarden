"""The raw TLS scanner against real `openssl s_server` processes."""

import socket
import subprocess
import time

import pytest

from lab import pki
from sitewarden.tls.analysis import analyze
from sitewarden.tls.scanner import TLSScanner


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture(scope="module")
def certs(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki")
    return d, pki.build_range_pki(d, "lab.test")


def _server(openssl, cert, key, *args):
    port = _free_port()
    proc = subprocess.Popen([openssl, "s_server", "-accept", str(port), "-cert", str(cert), "-key", str(key),
                             "-www", "-quiet", *args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    return proc, port


def _scan(port):
    return TLSScanner("modern.lab.test", "127.0.0.1", port, timeout=3, workers=4).run()


def test_modern_server(openssl, certs):
    _, c = certs
    cert, key = c["modern_rsa"]
    proc, port = _server(openssl, cert, key, "-no_tls1", "-no_tls1_1",
                         "-cipher", "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305")
    try:
        scan = _scan(port)
    finally:
        proc.kill()
    d = scan.to_dict()
    assert d["protocols"]["TLS 1.3"] and d["protocols"]["TLS 1.2"]
    assert not d["protocols"]["TLS 1.0"] and not d["protocols"]["TLS 1.1"]
    tls12 = {s["name"] for s in d["ciphers"]["TLS 1.2"]}
    assert tls12 == {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"}
    assert "x25519" in d["groups"]
    f = analyze(scan)
    assert not [x for x in f if x.severity.value in ("critical", "high", "medium")], [x.title for x in f]


def test_weak_server(openssl, certs):
    _, c = certs
    cert, key = c["modern_rsa"]
    proc, port = _server(openssl, cert, key, "-no_tls1_3", "-cipher", "AES128-SHA:ECDHE-RSA-AES128-SHA@SECLEVEL=0")
    try:
        scan = _scan(port)
    finally:
        proc.kill()
    d = scan.to_dict()
    assert not d["protocols"]["TLS 1.3"]
    f = analyze(scan)
    titles = " | ".join(x.title for x in f)
    assert "TLS 1.3 not supported" in titles
    assert "forward secrecy" in titles


def test_unreachable_port():
    scan = _scan(_free_port())
    assert not scan.to_dict()["reachable"]
