"""Sitewarden test range: real nginx servers (a 2016-era build and the current release), a test PKI
and a DNSSEC-signed DNS server, all on localhost. Used to verify the scanner end to end.

    python -m lab.range up        # start everything, print the scan commands
    python -m lab.range scan      # start, scan every target, write lab/results/, stop
    python -m lab.range down

Needs Docker. Images: nginx:1.10 (OpenSSL 1.0.1t) and nginx:latest (OpenSSL 3.5).
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time

from . import dnsserver, pki, world

HERE = pathlib.Path(__file__).resolve().parent
GEN = HERE / "generated"
RESULTS = HERE / "results"
REGISTRY = os.environ.get("LAB_REGISTRY", "mirror.gcr.io/library")
LEGACY_IMAGE = f"{REGISTRY}/nginx:1.10"
MODERN_IMAGE = f"{REGISTRY}/nginx:latest"
DOMAIN = "lab.test"

LEGACY_PAGE = """<!doctype html><html><head><title>Legacy Shop</title>
<meta name="generator" content="WordPress 4.9.8">
<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.5.8/angular.min.js"></script>
<script src="/js/legacy.js"></script>
<link rel="stylesheet" href="http://legacy.lab.test:10080/style.css">
</head><body><h1>Legacy Shop</h1>
<img src="http://legacy.lab.test:10080/logo.png">
<form action="http://legacy.lab.test:10080/login" method="post"><input type="password" name="pw"></form>
<script src="https://cdn.polyfill.io/v3/polyfill.min.js"></script>
</body></html>
"""
LEGACY_JS = "/*! jQuery v1.8.3 jquery.com | jquery.org/license */\nwindow.legacy = true;\n"

MODERN_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Modern</title>
<script nonce="__NONCE__" src="/app.js"></script></head><body><h1>Hardened site</h1></body></html>
"""

LEGACY_CONF = """
worker_processes 1;
events {{ worker_connections 256; }}
http {{
  server_tokens on;
  access_log off;
  ssl_dhparam /lab/dh1024.pem;
  ssl_session_tickets on;
  server {{
    listen 10080;
    server_name legacy.{d};
    root /lab/www-legacy;
    add_header X-Powered-By "PHP/7.2.24";
    add_header Set-Cookie "PHPSESSID=abc123; path=/";
  }}
  server {{
    listen 10443 ssl;
    server_name legacy.{d};
    ssl_certificate /lab/certs/legacy.crt;
    ssl_certificate_key /lab/certs/legacy.key;
    ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers 'HIGH:MEDIUM:RC4:3DES:!aNULL:!eNULL:!PSK:!SRP';
    ssl_prefer_server_ciphers off;
    root /lab/www-legacy;
    add_header X-Powered-By "PHP/7.2.24";
    add_header X-XSS-Protection "1; mode=block";
    add_header Set-Cookie "PHPSESSID=abc123; path=/";
    add_header Set-Cookie "remember_token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoxfQ.; path=/; HttpOnly";
    add_header Access-Control-Allow-Origin $http_origin;
    add_header Access-Control-Allow-Credentials true;
  }}
  server {{
    listen 10444 ssl;
    server_name expired.{d};
    ssl_certificate /lab/certs/expired.crt;
    ssl_certificate_key /lab/certs/expired.key;
    ssl_protocols TLSv1.2;
    ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384';
    root /lab/www-legacy;
  }}
  server {{
    listen 10445 ssl;
    server_name wronghost.{d};
    ssl_certificate /lab/certs/wronghost.crt;
    ssl_certificate_key /lab/certs/wronghost.key;
    ssl_protocols TLSv1.2;
    ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384';
    root /lab/www-legacy;
  }}
  server {{
    listen 10446 ssl;
    server_name selfsigned.{d};
    ssl_certificate /lab/certs/selfsigned.crt;
    ssl_certificate_key /lab/certs/selfsigned.key;
    ssl_protocols TLSv1.2;
    ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384';
    root /lab/www-legacy;
  }}
  server {{
    listen 10447 ssl;
    server_name incomplete.{d};
    ssl_certificate /lab/certs/incomplete.crt;
    ssl_certificate_key /lab/certs/incomplete.key;
    ssl_protocols TLSv1.2;
    ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384';
    root /lab/www-legacy;
  }}
  server {{
    listen 10448 ssl;
    server_name sha1.{d};
    ssl_certificate /lab/certs/sha1.crt;
    ssl_certificate_key /lab/certs/sha1.key;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers 'AES128-SHA:DES-CBC3-SHA';
    root /lab/www-legacy;
  }}
}}
"""

MODERN_CONF = """
worker_processes 1;
events {{ worker_connections 256; }}
http {{
  server_tokens off;
  access_log off;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
  ssl_prefer_server_ciphers off;
  ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1:secp384r1;
  ssl_session_tickets off;
  server {{
    listen 9080;
    server_name modern.{d};
    return 301 https://modern.{d}:9443$request_uri;
  }}
  server {{
    listen 18080;
    server_name ca.{d};
    root /lab/aia;
    default_type application/pkix-cert;
  }}
  server {{
    listen 9443 ssl;
    http2 on;
    server_name modern.{d};
    ssl_certificate /lab/certs/modern.crt;
    ssl_certificate_key /lab/certs/modern.key;
    ssl_certificate /lab/certs/modern_rsa.crt;
    ssl_certificate_key /lab/certs/modern_rsa.key;
    root /lab/www-modern;
    sub_filter_once off;
    sub_filter '__NONCE__' $request_id;
    sub_filter_types text/html;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'nonce-$request_id' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; require-trusted-types-for 'script'; upgrade-insecure-requests" always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Cross-Origin-Opener-Policy same-origin always;
    add_header Cross-Origin-Resource-Policy same-origin always;
    add_header Set-Cookie "__Host-session=r4nd0m; Path=/; Secure; HttpOnly; SameSite=Lax" always;
    location = /.well-known/security.txt {{
      default_type text/plain;
      return 200 "Contact: mailto:security@{d}\\nExpires: {expires}\\nPreferred-Languages: en\\n";
    }}
  }}
}}
"""


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


def prepare() -> None:
    GEN.mkdir(parents=True, exist_ok=True)
    certs = GEN / "certs"
    pki.build_range_pki(certs, DOMAIN, aia_url=f"http://ca.{DOMAIN}:18080/intermediate.der")
    (GEN / "aia").mkdir(exist_ok=True)
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    inter = x509.load_pem_x509_certificate((certs / "intermediate.pem").read_bytes())
    (GEN / "aia" / "intermediate.der").write_bytes(inter.public_bytes(serialization.Encoding.DER))
    if not (GEN / "dh1024.pem").exists():
        _run(["openssl", "dhparam", "-out", str(GEN / "dh1024.pem"), "1024"])
    for name, page, extra in (("www-legacy", LEGACY_PAGE, {"js/legacy.js": LEGACY_JS}),
                              ("www-modern", MODERN_PAGE, {"app.js": "console.log('ok');\n"})):
        d = GEN / name
        (d / "js").mkdir(parents=True, exist_ok=True)
        (d / "index.html").write_text(page)
        for rel, text in extra.items():
            (d / rel).write_text(text)
    import datetime as dt

    expires = (dt.datetime.now(dt.UTC) + dt.timedelta(days=180)).strftime("%Y-%m-%dT%H:%M:%SZ")
    (GEN / "legacy.conf").write_text(LEGACY_CONF.format(d=DOMAIN))
    (GEN / "modern.conf").write_text(MODERN_CONF.format(d=DOMAIN, expires=expires))
    os.chmod(GEN, 0o755)
    for p in GEN.rglob("*"):
        os.chmod(p, 0o755 if p.is_dir() else 0o644)


def up() -> None:
    prepare()
    down(quiet=True)
    for name, image, conf in (("sw-lab-legacy", LEGACY_IMAGE, "legacy.conf"), ("sw-lab-modern", MODERN_IMAGE, "modern.conf")):
        _run(["docker", "run", "-d", "--name", name, "--network", "host", "-v", f"{GEN}:/lab:ro",
              image, "nginx", "-g", "daemon off;", "-c", f"/lab/{conf}"])
    time.sleep(1.5)
    for name in ("sw-lab-legacy", "sw-lab-modern"):
        state = _run(["docker", "inspect", "-f", "{{.State.Running}}", name]).stdout.strip()
        if state != "true":
            logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
            raise SystemExit(f"{name} failed to start:\n{logs.stderr}")


def down(quiet: bool = False) -> None:
    for name in ("sw-lab-legacy", "sw-lab-modern"):
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


TARGETS = [
    # (label, host, https port, http port)
    ("modern", f"modern.{DOMAIN}", 9443, 9080),
    ("legacy", f"legacy.{DOMAIN}", 10443, 10080),
    ("expired", f"expired.{DOMAIN}", 10444, 0),
    ("wronghost", f"wronghost.{DOMAIN}", 10445, 0),
    ("selfsigned", f"selfsigned.{DOMAIN}", 10446, 0),
    ("incomplete", f"incomplete.{DOMAIN}", 10447, 0),
    ("sha1", f"sha1.{DOMAIN}", 10448, 0),
]


def lab_network(dns_port: int):
    from sitewarden.net import Network

    return Network(allow_private=True, nameservers=["127.0.0.1"], dns_port=dns_port,
                   extra_roots=[(GEN / "certs" / "root.pem").read_bytes()], dns_timeout=2)


def scan_all() -> list[dict]:
    from sitewarden.report import html as html_report
    from sitewarden.scan import ScanOptions, run_scan

    resolver, anchors = world.build(domain=DOMAIN)
    port, stop = dnsserver.serve(resolver)
    RESULTS.mkdir(exist_ok=True)
    rows = []
    try:
        for label, host, https_port, http_port in TARGETS:
            net = lab_network(port)
            opts = ScanOptions(port=https_port, http_port=http_port, smtp=False, dnssec_anchors=anchors, timeout=4)
            report = run_scan(host, net, opts)
            (RESULTS / f"{label}.json").write_text(json.dumps(report, indent=2, default=str))
            (RESULTS / f"{label}.html").write_text(html_report.render(report))
            rows.append(report)
            issues = [f for f in report["findings"] if f["severity"] in ("critical", "high")]
            print(f"{label:<11} {report['grade']:<3} {report['score']:>5}  {report['duration_ms'] / 1000:>5.1f}s  "
                  + "; ".join(f["title"] for f in issues[:4]))
    finally:
        stop()
    return rows


def main(argv: list[str]) -> int:
    cmd = argv[0] if argv else "scan"
    if cmd == "up":
        up()
        resolver, anchors = world.build(domain=DOMAIN)
        port, _stop = dnsserver.serve(resolver)
        print(f"Range is up. DNS on 127.0.0.1:{port}. Example:\n"
              f"  sitewarden scan modern.{DOMAIN} --port 9443 --http-port 9080 --dns 127.0.0.1 --dns-port {port} "
              f"--ca-file {GEN / 'certs' / 'root.pem'} --allow-private\nCtrl-C to stop DNS.")
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            return 0
    if cmd == "down":
        down()
        return 0
    if cmd == "scan":
        up()
        try:
            scan_all()
        finally:
            down()
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
