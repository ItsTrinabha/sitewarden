"""DNSSEC, CAA, takeover and email checks against the signed lab DNS server."""

import pytest

from sitewarden.dns import dnssec, domain, email


@pytest.mark.parametrize("zone,status", [
    ("lab.test", "secure"), ("weak.test", "insecure"), ("bogus.test", "bogus"), ("island.test", "island"),
])
def test_dnssec_statuses(lab_net, lab_dns, zone, status):
    _, anchors = lab_dns
    res = dnssec.validate_chain(lab_net, zone, anchors=anchors)
    assert res.status == status, res.detail


def test_dnssec_wrong_anchor_is_bogus(lab_net):
    # the real IANA root key cannot validate the lab root
    res = dnssec.validate_chain(lab_net, "lab.test")
    assert res.status != "secure"


def test_domain_findings(lab_net, lab_dns):
    _, anchors = lab_dns
    f, facts = domain.analyze(lab_net, "modern.lab.test", dnssec_anchors=anchors)
    assert facts["dnssec"]["status"] == "secure"
    assert facts["caa"]["records"]
    assert not [x for x in f if x.severity.value in ("critical", "high")]


def test_dangling_cname(lab_net, lab_dns):
    _, anchors = lab_dns
    f, _ = domain.analyze(lab_net, "old.lab.test", dnssec_anchors=anchors)
    assert any(x.severity.value == "critical" and "herokuapp" in (x.detail + (x.evidence or "")) for x in f)


def test_bogus_domain_is_flagged(lab_net, lab_dns):
    _, anchors = lab_dns
    f, facts = domain.analyze(lab_net, "bogus.test", dnssec_anchors=anchors)
    assert facts["dnssec"]["status"] == "bogus"
    assert any(x.severity.value in ("critical", "high") for x in f)


def test_good_email(lab_net):
    mf, mfacts, mx, null_mx = domain.mail_servers(lab_net, "lab.test", check_smtp=False)
    assert mx == ["mail.lab.test"] and not null_mx
    f, facts = email.analyze(lab_net, "lab.test", mx, null_mx)
    serious = [x.title for x in f if x.severity.value in ("critical", "high")]
    assert not serious
    assert facts["spf"]["all"] == "-"
    assert any(d.get("bits") == 2048 for d in facts.get("dkim", []))


def test_weak_email(lab_net):
    _, _, mx, null_mx = domain.mail_servers(lab_net, "weak.test", check_smtp=False)
    f, facts = email.analyze(lab_net, "weak.test", mx, null_mx)
    titles = " | ".join(x.title for x in f)
    sev = {x.severity.value for x in f}
    assert "critical" in sev  # +all lets anyone send as the domain
    assert "p=none" in titles or "monitor" in titles.lower()
    assert "1024" in titles


def test_spf_lookup_counting(lab_net):
    res = email.evaluate_spf(lab_net, "weak.test")
    assert res.all_qualifier == "+"
    assert res.lookups >= 3
    assert res.void_lookups >= 1


def test_mx_pattern():
    assert email.mx_matches("*.mail.example.com", "a.mail.example.com")
    assert not email.mx_matches("*.mail.example.com", "a.b.mail.example.com")
    assert email.mx_matches("mx.example.com", "MX.example.com.")


def test_mta_sts_policy_parse():
    p = email.parse_mta_sts_policy("version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.example.net\nmax_age: 604800\n")
    assert p["mode"] == "enforce" and len(p["mx"]) == 2 and int(p["max_age"]) == 604800


def test_resolver_without_soa_is_treated_as_unavailable(lab_net, monkeypatch):
    """A filtering resolver that answers A but not SOA/TXT must not produce false email findings."""
    real = lab_net.query

    def filtered(name, rdtype):
        ans = real(name, rdtype)
        if rdtype != "A":
            ans.rrset = []
        return ans

    monkeypatch.setattr(lab_net, "query", filtered)
    f, facts = domain.analyze(lab_net, "modern.lab.test")
    assert facts.get("dns_unavailable")
    assert all(x.severity.value in ("info", "pass") for x in f)
