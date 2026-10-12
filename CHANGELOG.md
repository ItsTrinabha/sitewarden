# Changelog

## 1.0.0 (2026-10-12)

First release.

- Raw TLS scanner: SSL 2.0 to TLS 1.3, full cipher suite enumeration and server preference, key exchange groups including post-quantum X25519MLKEM768, downgrade protection, renegotiation, compression, EMS, heartbeat, SNI.
- Certificate chain validation against the Mozilla root store, AIA chasing, OCSP and CRL revocation, Certificate Transparency, Must-Staple, CA/B Forum lifetime rule.
- HTTP: HTTPS redirects, HSTS and preload status, a strict-CSP evaluator, CORS, clickjacking, cross-origin isolation, cookie security, mixed content, SRI, compromised CDNs, vulnerable JavaScript libraries (Retire.js data), end-of-life server software, security.txt.
- DNS: DNSSEC chain validation from the root trust anchor, CAA (cross-checked with the issuing CA), dangling CNAME takeover risk, name server diversity, IPv6.
- Email: SPF (lookup and void limits), DMARC, DKIM key strength, MTA-STS, TLS-RPT, BIMI, STARTTLS and DANE on the mail servers.
- Grading with letter grades, caps and A+ rules; Mozilla, NIST SP 800-52r2, PCI DSS 4.0, OWASP headers and bulk-sender compliance checks; config snippets for nginx, Apache, Caddy and more.
- CLI, web app with live progress, JSON/Markdown/HTML exports, SVG badges, GitHub Action, Docker image.
