"""Command-line interface: `sitewarden scan`, `sitewarden serve`, `sitewarden update`."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .models import GRADES


def _network(args):
    from .net import Network

    net = Network.from_env(allow_private=getattr(args, "allow_private", False))
    if getattr(args, "dns", None):
        net.nameservers = [s.strip() for s in args.dns.split(",") if s.strip()]
    if getattr(args, "dns_port", None):
        net.dns_port = args.dns_port
    for item in getattr(args, "resolve", None) or []:
        host, _, ip = item.partition(":")
        if not host or not ip:
            raise SystemExit(f"--resolve expects host:ip (got {item!r})")
        net.overrides[host.lower()] = ip
    for path in getattr(args, "ca_file", None) or []:
        with open(path, "rb") as fh:
            net.extra_roots.append(fh.read())
    if getattr(args, "proxy", None):
        net.proxy = args.proxy
    return net


def cmd_scan(args) -> int:
    from .report import console, markdown
    from .report import html as html_report
    from .scan import ScanError, ScanOptions, run_scan

    net = _network(args)
    opts = ScanOptions(port=args.port, http_port=args.http_port, dns=not args.no_dns, email=not args.no_email,
                       smtp=not args.no_smtp, fetch_scripts=not args.no_scripts, revocation=not args.no_revocation,
                       tls=not args.no_tls)
    quiet = args.quiet or args.json == "-"

    def progress(stage, msg):
        if not quiet:
            print(f"\r\033[2K  … {msg}", end="", file=sys.stderr, flush=True)

    try:
        report = run_scan(args.target, net, opts, progress)
    except ScanError as exc:
        if not quiet:
            print("\r\033[2K", end="", file=sys.stderr)
        print(f"sitewarden: {exc}", file=sys.stderr)
        return 2
    if not quiet:
        print("\r\033[2K", end="", file=sys.stderr, flush=True)

    if args.json:
        data = json.dumps(report, indent=2, default=str)
        if args.json == "-":
            print(data)
        else:
            with open(args.json, "w", encoding="utf-8") as fh:
                fh.write(data)
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(markdown.render(report))
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(html_report.render(report))
    if args.json != "-":
        print(console.render(report, show_passed=args.verbose))
    if args.fail_under:
        if GRADES.index(report["grade"]) > GRADES.index(args.fail_under):
            print(f"sitewarden: grade {report['grade']} is below the required {args.fail_under}", file=sys.stderr)
            return 1
    return 0


def cmd_serve(args) -> int:
    import os

    import uvicorn

    if args.allow_private:
        os.environ["SITEWARDEN_ALLOW_PRIVATE"] = "1"
    if args.db:
        os.environ["SITEWARDEN_DB"] = args.db
    if args.trust_proxy:
        os.environ["SITEWARDEN_TRUST_PROXY"] = "1"
    uvicorn.run("sitewarden.web.app:create_app", factory=True, host=args.host, port=args.port,
                proxy_headers=args.trust_proxy,
                forwarded_allow_ips="*" if args.trust_proxy else None, log_level="info")
    return 0


def cmd_update(args) -> int:
    from .updater import update_all

    ok = update_all(verbose=True)
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sitewarden", description="Passive website security grading: TLS, "
                                "certificates, headers, cookies, content, DNS and email.")
    p.add_argument("--version", action="version", version=f"sitewarden {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a website and print its security grade")
    s.add_argument("target", help="domain or URL, e.g. example.com or https://example.com:8443/")
    s.add_argument("--json", metavar="FILE", help="write the full JSON report ('-' for stdout)")
    s.add_argument("--md", metavar="FILE", help="write a Markdown report")
    s.add_argument("--html", metavar="FILE", help="write a self-contained HTML report")
    s.add_argument("--fail-under", choices=GRADES, metavar="GRADE",
                   help="exit 1 if the grade is worse than this (A+, A, A-, B, C, D, E, F)")
    s.add_argument("-v", "--verbose", action="store_true", help="also list passed checks")
    s.add_argument("-q", "--quiet", action="store_true", help="no progress output")
    s.add_argument("--port", type=int, help="HTTPS port (default 443)")
    s.add_argument("--http-port", type=int, default=80, help="plain HTTP port to test redirects on (0 to skip)")
    s.add_argument("--no-tls", action="store_true", help="skip TLS and certificate checks")
    s.add_argument("--no-dns", action="store_true", help="skip DNS and email checks")
    s.add_argument("--no-email", action="store_true", help="skip email authentication checks")
    s.add_argument("--no-smtp", action="store_true", help="do not connect to mail servers on port 25")
    s.add_argument("--no-scripts", action="store_true", help="do not download scripts for library detection")
    s.add_argument("--no-revocation", action="store_true", help="skip OCSP/CRL revocation lookups")
    s.add_argument("--dns", metavar="IP[,IP]", help="DNS resolver(s) to use instead of the system's")
    s.add_argument("--dns-port", type=int, help=argparse.SUPPRESS)
    s.add_argument("--resolve", action="append", metavar="HOST:IP", help="pin a host to an address (repeatable)")
    s.add_argument("--ca-file", action="append", metavar="PEM", help="extra trusted root CA (repeatable)")
    s.add_argument("--allow-private", action="store_true", help="allow scanning private/internal addresses")
    s.add_argument("--proxy", metavar="URL", help="send HTTP checks through a CONNECT proxy (TLS checks are skipped)")
    s.set_defaults(func=cmd_scan)

    v = sub.add_parser("serve", help="run the web interface and JSON API")
    v.add_argument("--host", default="127.0.0.1")
    v.add_argument("--port", type=int, default=8080)
    v.add_argument("--db", help="SQLite database path (default ./sitewarden.db)")
    v.add_argument("--allow-private", action="store_true", help="allow scanning private addresses (lab use only)")
    v.add_argument("--trust-proxy", action="store_true", help="trust X-Forwarded-For from a reverse proxy")
    v.set_defaults(func=cmd_serve)

    u = sub.add_parser("update", help="refresh the HSTS preload list, Retire.js and PSL data")
    u.set_defaults(func=cmd_update)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
