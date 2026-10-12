"""security.txt (RFC 9116) discovery and validation."""

from __future__ import annotations

import datetime as dt

from ..models import Findings, Severity
from ..net import Network
from ..remediation import SNIPPETS
from .client import fetch


def parse_security_txt(text: str) -> dict:
    fields: dict[str, list[str]] = {}
    signed = "-----BEGIN PGP SIGNED MESSAGE-----" in text
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-----") or ":" not in line:
            continue
        k, _, v = line.partition(":")
        k = k.strip().lower()
        if " " in k:
            continue
        fields.setdefault(k, []).append(v.strip())
    return {"fields": fields, "signed": signed}


def check_security_txt(net: Network, host: str, now: dt.datetime | None = None, base: str | None = None) -> tuple[Findings, dict]:
    now = now or dt.datetime.now(dt.UTC)
    f = Findings("headers")
    found = None
    for path in ("/.well-known/security.txt", "/security.txt"):
        r = fetch(net, f"{base or 'https://' + host}{path}", max_body=64 * 1024, timeout=8, headers={"Accept": "text/plain"})
        ctype = (r.header("content-type") or "").lower()
        if r.ok and r.status == 200 and "html" not in ctype and b"<html" not in r.body[:500].lower():
            found = (path, r, ctype)
            break
    if not found:
        f.add("sectxt.missing", Severity.INFO, "No security.txt",
              "RFC 9116 security.txt tells researchers how to report vulnerabilities. Without it, reports often go "
              "to the wrong inbox or nowhere.", snippets=SNIPPETS["security_txt"],
              refs=["https://www.rfc-editor.org/rfc/rfc9116", "https://securitytxt.org/"])
        return f, {"present": False}
    path, r, ctype = found
    parsed = parse_security_txt(r.text())
    fields = parsed["fields"]
    facts = {"present": True, "path": path, "fields": fields, "signed": parsed["signed"]}
    problems = []
    if "contact" not in fields:
        problems.append("no Contact field (required)")
    expires = fields.get("expires", [None])[0]
    if not expires:
        problems.append("no Expires field (required)")
    else:
        try:
            exp = dt.datetime.fromisoformat(expires.replace("Z", "+00:00"))
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=dt.UTC)
            if exp < now:
                problems.append(f"expired on {expires}")
            elif (exp - now).days > 366:
                problems.append("Expires is more than a year away (RFC 9116 recommends under a year)")
        except ValueError:
            problems.append(f"Expires is not an ISO 8601 date: {expires}")
    if path != "/.well-known/security.txt":
        problems.append("served at /security.txt instead of /.well-known/security.txt")
    if "text/plain" not in ctype:
        problems.append(f"Content-Type is {ctype or 'missing'}, should be text/plain")
    if problems:
        f.add("sectxt.invalid", Severity.LOW, "security.txt has problems", "; ".join(problems) + ".",
              evidence=f"https://{host}{path}", snippets=SNIPPETS["security_txt"])
    else:
        f.ok("sectxt.present", "Valid security.txt", evidence=", ".join(fields.get("contact", [])[:2]))
    return f, facts
