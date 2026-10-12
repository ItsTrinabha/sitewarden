# Security policy

Please report vulnerabilities in Sitewarden privately by email to the maintainers (see the project page) rather than in a public issue. You will get an acknowledgement within a few days.

## Design notes for a public deployment

- **SSRF:** every host name is resolved once, the address is checked against private, loopback, link-local, CGNAT, multicast and reserved ranges, and the connection is pinned to that address. The same applies to redirects, AIA certificate downloads, OCSP/CRL responders, MTA-STS policies and mail servers. `--allow-private` / `SITEWARDEN_ALLOW_PRIVATE=1` turns this off and must never be set on a public instance.
- **Passive only:** Sitewarden sends ordinary TLS handshakes, GET requests, one CORS preflight-style GET with an `Origin` from the reserved `.invalid` domain, and DNS queries. It sends no exploit payloads and does not test Heartbleed, ROBOT or application-level flaws.
- **Abuse limits:** per-client hourly rate limit, a result cache, a cooldown on forced rescans, a cap on concurrent scans, the public scanner only tests port 443.
- **Web UI hardening:** strict CSP with Trusted Types (`require-trusted-types-for 'script'`), no inline scripts or styles, the UI builds the DOM without `innerHTML`, HSTS, COOP/COEP/CORP, `frame-ancestors 'none'`. Exported HTML reports are served with a sandboxing CSP.
