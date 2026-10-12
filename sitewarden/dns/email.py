"""Email anti-spoofing: SPF (RFC 7208), DMARC (RFC 7489), DKIM keys, MTA-STS (RFC 8461), TLS-RPT, BIMI."""

from __future__ import annotations

import base64
import concurrent.futures as cf
import re
from dataclasses import dataclass, field

from ..models import Findings, Severity
from ..net import Network
from ..remediation import SNIPPETS

DKIM_SELECTORS = [
    "default", "dkim", "mail", "google", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2", "s1024",
    "s2048", "key1", "key2", "sig1", "smtp", "mandrill", "mxvault", "everlytickey1", "everlytickey2",
    "zoho", "zmail", "protonmail", "protonmail2", "protonmail3", "fm1", "fm2", "fm3", "mailjet", "mj",
    "cm", "dk", "hs1", "hs2", "mailo", "krs", "pic", "turbo-smtp", "sendgrid", "smtpapi", "intercom",
    "scph0123", "200608", "20230601", "20221208", "20210112", "2024", "2025", "2026", "ms", "amazonses",
]
SPF_LOOKUP_LIMIT = 10
SPF_VOID_LIMIT = 2


# ----------------------------------------------------------------------------- SPF


@dataclass
class SPFResult:
    record: str | None = None
    records: list[str] = field(default_factory=list)
    all_qualifier: str | None = None
    lookups: int = 0
    void_lookups: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    includes: list[str] = field(default_factory=list)
    tree: dict = field(default_factory=dict)


def _spf_records(net: Network, domain: str) -> tuple[list[str], str]:
    ans = net.query(domain, "TXT")
    recs = [r for r in ans.rrset if r.lower().startswith("v=spf1") and (len(r) == 6 or r[6] == " ")]
    return recs, ans.rcode


def evaluate_spf(net: Network, domain: str) -> SPFResult:
    res = SPFResult()
    recs, _ = _spf_records(net, domain)
    res.records = recs
    if not recs:
        return res
    if len(recs) > 1:
        res.errors.append(f"{len(recs)} SPF records published; RFC 7208 makes this a permanent error")
    res.record = recs[0]
    seen: set[str] = set()

    def walk(dom: str, record: str, depth: int) -> dict:
        node = {"domain": dom, "record": record, "children": []}
        if depth > 10:
            res.errors.append("include chain deeper than 10 levels")
            return node
        terms = record.split()[1:]
        redirect = None
        has_all = False
        for term in terms:
            t = term.lower()
            qual = t[0] if t[0] in "+-~?" else "+"
            mech = t[1:] if t[0] in "+-~?" else t
            if re.match(r"^[a-z][a-z0-9_.-]*=", mech):  # modifier (redirect=, exp=, unknown ones)
                key, _, val = mech.partition("=")
                if key == "redirect":
                    redirect = val
                continue
            name, _, arg = mech.partition(":")
            name = name.split("/")[0]
            if name == "all":
                has_all = True
                if depth == 0:
                    res.all_qualifier = qual
            elif name in ("include", "a", "mx", "ptr", "exists"):
                res.lookups += 1
                if name == "ptr":
                    res.warnings.append(f"'ptr' mechanism in {dom} is deprecated (RFC 7208 5.5) and slow")
                if name == "include":
                    if not arg:
                        res.errors.append(f"include without a domain in {dom}")
                        continue
                    if "%" in arg:
                        continue  # macro: cannot expand without a sender
                    res.includes.append(arg)
                    if arg in seen:
                        res.errors.append(f"include loop via {arg}")
                        continue
                    seen.add(arg)
                    sub, rcode = _spf_records(net, arg)
                    if not sub:
                        res.void_lookups += 1
                        res.errors.append(f"include:{arg} has no SPF record ({rcode}), a permanent error")
                        continue
                    node["children"].append(walk(arg, sub[0], depth + 1))
                elif name == "mx":
                    target = arg or dom
                    mx = net.query(target, "MX")
                    if not mx.rrset:
                        res.void_lookups += 1
                    elif len(mx.rrset) > 10:
                        res.errors.append(f"mx:{target} has more than 10 MX records")
                elif name == "a":
                    target = arg or dom
                    if "%" not in target and not net.query(target, "A").rrset and not net.query(target, "AAAA").rrset:
                        res.void_lookups += 1
            elif name in ("ip4", "ip6"):
                if not arg:
                    res.errors.append(f"{name} without an address in {dom}")
            elif name.startswith("v="):
                continue
            else:
                res.errors.append(f"unknown mechanism '{term}' in {dom}")
        if redirect and not has_all:
            res.lookups += 1
            sub, _ = _spf_records(net, redirect)
            if not sub:
                res.void_lookups += 1
                res.errors.append(f"redirect={redirect} has no SPF record")
            elif redirect not in seen:
                seen.add(redirect)
                child = walk(redirect, sub[0], depth + 1)
                node["children"].append(child)
                if depth == 0 and res.all_qualifier is None:
                    m = re.search(r"([+\-~?]?)all\b", sub[0].lower())
                    if m:
                        res.all_qualifier = m.group(1) or "+"
        return node

    res.tree = walk(domain, res.record, 0)
    if res.lookups > SPF_LOOKUP_LIMIT:
        res.errors.append(f"{res.lookups} DNS-querying terms exceed the limit of {SPF_LOOKUP_LIMIT}: receivers "
                          "return permerror and SPF fails for all mail")
    if res.void_lookups > SPF_VOID_LIMIT:
        res.errors.append(f"{res.void_lookups} void lookups exceed the limit of {SPF_VOID_LIMIT}")
    if len(res.record) > 450:
        res.warnings.append(f"SPF record is {len(res.record)} characters; responses over 512 bytes need TCP or EDNS")
    return res


# ----------------------------------------------------------------------------- DMARC


def parse_tags(record: str) -> dict[str, str]:
    tags = {}
    for part in record.split(";"):
        k, sep, v = part.strip().partition("=")
        if sep:
            tags[k.strip().lower()] = v.strip()
    return tags


def dmarc_record(net: Network, domain: str) -> tuple[list[str], str]:
    ans = net.query(f"_dmarc.{domain}", "TXT")
    return [r for r in ans.rrset if r.lower().replace(" ", "").startswith("v=dmarc1")], ans.rcode


# ----------------------------------------------------------------------------- DKIM


def dkim_key_bits(p: str) -> tuple[str, int | None]:
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    raw = base64.b64decode(re.sub(r"\s", "", p) + "==")
    try:
        key = load_der_public_key(raw)
    except ValueError:
        if len(raw) == 32:
            return "ed25519", 256
        return "unknown", None
    if isinstance(key, rsa.RSAPublicKey):
        return "rsa", key.key_size
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "ed25519", 256
    return type(key).__name__, None


def find_dkim(net: Network, domain: str, selectors: list[str] | None = None) -> list[dict]:
    sels = selectors or DKIM_SELECTORS

    def probe(sel):
        ans = net.query(f"{sel}._domainkey.{domain}", "TXT")
        recs = [r for r in ans.rrset if "p=" in r]
        if not recs:
            return None
        tags = parse_tags(recs[0])
        p = tags.get("p", "")
        out = {"selector": sel, "record": recs[0][:200], "testing": "y" in tags.get("t", "").split(":"),
               "revoked": p == ""}
        if p:
            out["key_type"], out["bits"] = dkim_key_bits(p)
        return out

    with cf.ThreadPoolExecutor(8) as pool:
        return [r for r in pool.map(probe, sels) if r]


# ----------------------------------------------------------------------------- MTA-STS


def parse_mta_sts_policy(text: str) -> dict:
    pol: dict = {"mx": []}
    for line in text.splitlines():
        k, sep, v = line.partition(":")
        if not sep:
            continue
        k, v = k.strip().lower(), v.strip()
        if k == "mx":
            pol["mx"].append(v.lower())
        else:
            pol[k] = v
    return pol


def mx_matches(pattern: str, host: str) -> bool:
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) and host.count(".") == pattern.count(".")
    return pattern == host


# ----------------------------------------------------------------------------- orchestration


def analyze(net: Network, domain: str, mx_hosts: list[str], null_mx: bool) -> tuple[Findings, dict]:
    f = Findings("email")
    facts: dict = {"domain": domain, "mx": mx_hosts, "null_mx": null_mx}
    sends_mail = bool(mx_hosts)

    # --- SPF ---
    spf = evaluate_spf(net, domain)
    facts["spf"] = {"record": spf.record, "all": spf.all_qualifier, "lookups": spf.lookups,
                    "void_lookups": spf.void_lookups, "errors": spf.errors, "warnings": spf.warnings,
                    "includes": spf.includes, "tree": spf.tree}
    if not spf.records:
        f.add("spf.missing", Severity.HIGH if sends_mail else Severity.MEDIUM, "No SPF record",
              "Receivers cannot tell which servers may send mail as @" + domain + ", which makes spoofing easier. "
              + ("" if sends_mail else "For a domain that sends no mail, publish 'v=spf1 -all'."),
              fix="Publish an SPF record listing your mail providers and ending in -all or ~all.",
              snippets=SNIPPETS["null_mx" if not sends_mail else "spf"], tags=["CWE-290"])
    else:
        if spf.errors:
            f.add("spf.error", Severity.HIGH, "SPF record is broken (permerror)",
                  "Receivers treat a permerror like no SPF at all, and DMARC loses its SPF alignment path. "
                  + " ".join(spf.errors[:3]), evidence=spf.record, snippets=SNIPPETS["spf"])
        q = spf.all_qualifier
        if q == "+":
            f.add("spf.pass_all", Severity.CRITICAL, "SPF authorises every server on the internet (+all)",
                  "'+all' tells receivers that any host may send as this domain, which is worse than no record.",
                  evidence=spf.record, cap="C", tags=["CWE-290"])
        elif q == "?":
            f.add("spf.neutral", Severity.MEDIUM, "SPF ends in ?all (neutral)",
                  "Neutral gives receivers no instruction about unlisted senders.", evidence=spf.record)
        elif q is None:
            f.add("spf.no_all", Severity.MEDIUM, "SPF has no 'all' mechanism",
                  "Without -all or ~all, unlisted senders get a neutral result.", evidence=spf.record)
        elif not spf.errors:
            f.ok("spf.valid", f"SPF record valid ({'-all hard fail' if q == '-' else '~all soft fail'}, "
                 f"{spf.lookups}/10 lookups)", evidence=spf.record)
        if 8 <= spf.lookups <= SPF_LOOKUP_LIMIT:
            f.add("spf.lookups_near_limit", Severity.LOW, f"SPF uses {spf.lookups} of 10 allowed DNS lookups",
                  "One more include from a provider pushes the record into permerror.")
        for w in spf.warnings:
            f.add("spf.warning", Severity.LOW, "SPF warning", w)

    # --- DMARC ---
    recs, _ = dmarc_record(net, domain)
    if not recs:
        f.add("dmarc.missing", Severity.HIGH, "No DMARC policy",
              "Without DMARC, receivers apply no consistent policy to mail that fails SPF/DKIM, so the domain can be "
              "spoofed in phishing. Gmail and Yahoo require DMARC from bulk senders since 2024.",
              snippets=SNIPPETS["dmarc"], tags=["CWE-290"],
              refs=["https://www.rfc-editor.org/rfc/rfc7489", "https://support.google.com/a/answer/81126"])
        facts["dmarc"] = None
    else:
        tags = parse_tags(recs[0])
        facts["dmarc"] = {"record": recs[0], "tags": tags}
        policy = tags.get("p", "").lower()
        if len(recs) > 1:
            f.add("dmarc.multiple", Severity.HIGH, "Multiple DMARC records (all are ignored)", evidence=" | ".join(recs))
        if policy not in ("none", "quarantine", "reject"):
            f.add("dmarc.invalid", Severity.HIGH, "DMARC record has no valid p= policy",
                  "Receivers discard a record without a valid policy.", evidence=recs[0], snippets=SNIPPETS["dmarc"])
        elif policy == "none":
            f.add("dmarc.none", Severity.MEDIUM, "DMARC is in monitoring mode (p=none)",
                  "Spoofed mail is still delivered. Once reports show legitimate senders pass, move to quarantine and "
                  "then reject.", evidence=recs[0], snippets=SNIPPETS["dmarc"])
        else:
            pct = tags.get("pct", "100")
            if pct.isdigit() and int(pct) < 100:
                f.add("dmarc.pct", Severity.LOW, f"DMARC applies to only {pct}% of failing mail", evidence=recs[0])
            f.ok("dmarc.enforced", f"DMARC enforced (p={policy})", evidence=recs[0])
            sp = tags.get("sp", "").lower()
            if sp == "none":
                f.add("dmarc.sp_none", Severity.LOW, "Subdomains are exempt from DMARC (sp=none)",
                      "Attackers can spoof any.subdomain." + domain + ".", evidence=recs[0])
        rua = tags.get("rua", "")
        if not rua:
            f.add("dmarc.no_rua", Severity.LOW, "DMARC aggregate reports are not requested (no rua=)",
                  "Without reports you cannot see who sends mail as your domain or whether legitimate mail fails.")
        else:
            for uri in [u.strip() for u in rua.split(",")]:
                m = re.match(r"mailto:[^@]+@([^!?\s]+)", uri, re.I)
                if not m:
                    continue
                rdom = m.group(1).lower().rstrip(".")
                if rdom == domain or rdom.endswith("." + domain):
                    continue
                auth = net.query(f"{domain}._report._dmarc.{rdom}", "TXT")
                if not any(r.lower().startswith("v=dmarc1") for r in auth.rrset):
                    f.add("dmarc.external_rua", Severity.LOW, f"Report destination {rdom} has not authorised reports",
                          f"RFC 7489 7.1 requires {domain}._report._dmarc.{rdom} to exist; receivers drop reports otherwise.")

    # --- DKIM ---
    keys = find_dkim(net, domain) if sends_mail else []
    facts["dkim"] = keys
    if sends_mail:
        if not keys:
            f.add("dkim.not_found", Severity.INFO, "No DKIM key found under common selectors",
                  "DKIM selectors cannot be listed through DNS, so this does not prove DKIM is missing. Check a "
                  "received message's DKIM-Signature header for the selector (s=).")
        for k in keys:
            if k.get("revoked"):
                continue
            bits = k.get("bits")
            if k.get("key_type") == "rsa" and bits and bits < 1024:
                f.add("dkim.weak", Severity.HIGH, f"DKIM key '{k['selector']}' is only {bits}-bit RSA",
                      "Keys this small can be factored, letting anyone sign mail as the domain. Receivers ignore them.")
            elif k.get("key_type") == "rsa" and bits and bits < 2048:
                f.add("dkim.1024", Severity.LOW, f"DKIM key '{k['selector']}' is 1024-bit RSA",
                      "1024-bit keys are still accepted but below current guidance (RFC 8301 recommends 2048).")
            else:
                f.ok("dkim.key", f"DKIM key '{k['selector']}' ({k.get('key_type')} {bits or ''})".rstrip())
            if k.get("testing"):
                f.add("dkim.testing", Severity.INFO, f"DKIM selector '{k['selector']}' is in test mode (t=y)")

    # --- MTA-STS / TLS-RPT ---
    if sends_mail:
        sts = net.query(f"_mta-sts.{domain}", "TXT")
        sts_recs = [r for r in sts.rrset if r.lower().startswith("v=stsv1")]
        facts["mta_sts"] = None
        if not sts_recs:
            f.add("mtasts.missing", Severity.LOW, "No MTA-STS policy",
                  "SMTP encryption between mail servers is opportunistic: a network attacker can strip STARTTLS and "
                  "read mail in transit. MTA-STS makes sending servers insist on valid TLS.",
                  snippets=SNIPPETS["mta_sts"], refs=["https://www.rfc-editor.org/rfc/rfc8461"])
        else:
            from ..http.client import fetch

            r = fetch(net, f"https://mta-sts.{domain}/.well-known/mta-sts.txt", max_body=64 * 1024, timeout=8,
                      verify=True, headers={"Accept": "text/plain"})
            if not r.ok or r.status != 200:
                f.add("mtasts.policy_unreachable", Severity.MEDIUM, "MTA-STS policy file cannot be fetched",
                      "The DNS record exists but https://mta-sts." + domain + "/.well-known/mta-sts.txt failed, so "
                      "senders ignore the policy. It must be served over HTTPS with a valid certificate.",
                      evidence=r.error or f"HTTP {r.status}")
            else:
                pol = parse_mta_sts_policy(r.text())
                facts["mta_sts"] = pol
                mode = pol.get("mode", "").lower()
                unmatched = [h for h in mx_hosts if not any(mx_matches(p, h) for p in pol["mx"])]
                if unmatched and mode == "enforce":
                    f.add("mtasts.mx_mismatch", Severity.HIGH, "MTA-STS policy does not cover every MX host",
                          "Senders that enforce the policy will refuse to deliver to these MX hosts.",
                          evidence="Not matched: " + ", ".join(unmatched))
                if mode == "enforce":
                    f.ok("mtasts.enforce", "MTA-STS enforced", evidence=", ".join(pol["mx"]))
                elif mode == "testing":
                    f.add("mtasts.testing", Severity.LOW, "MTA-STS is in testing mode",
                          "Failures are reported but mail is still delivered without TLS.")
                else:
                    f.add("mtasts.none", Severity.LOW, f"MTA-STS mode is '{mode or 'missing'}'")
        rpt = net.query(f"_smtp._tls.{domain}", "TXT")
        if any(r.lower().startswith("v=tlsrptv1") for r in rpt.rrset):
            f.ok("tlsrpt.present", "SMTP TLS reporting (TLS-RPT) configured")
        else:
            f.add("tlsrpt.missing", Severity.INFO, "No SMTP TLS reporting (TLS-RPT)",
                  "TLS-RPT sends daily reports about TLS failures delivering to your mail servers.",
                  snippets=SNIPPETS["tlsrpt"])
        bimi = net.query(f"default._bimi.{domain}", "TXT")
        if any(r.lower().startswith("v=bimi1") for r in bimi.rrset):
            f.ok("bimi.present", "BIMI brand logo published")
    elif null_mx:
        f.ok("mx.null", "Null MX published (domain accepts no mail, RFC 7505)")
    else:
        if spf.all_qualifier == "-" and facts.get("dmarc") and facts["dmarc"]["tags"].get("p", "").lower() == "reject":
            f.ok("email.parked", "Non-mail domain is locked down (SPF -all and DMARC reject)")
        else:
            f.add("email.no_mx", Severity.INFO, "Domain has no MX record",
                  "If it never sends mail, publish a null MX, 'v=spf1 -all' and a p=reject DMARC record so nobody "
                  "can spoof it.", snippets=SNIPPETS["null_mx"])
    return f, facts
