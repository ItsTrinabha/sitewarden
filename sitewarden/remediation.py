"""Copy-paste configuration fixes, keyed by remediation topic and server type."""

MOZ_INTERMEDIATE_OPENSSL = (
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
)

SNIPPETS: dict[str, dict[str, str]] = {
    "protocols": {
        "nginx": "ssl_protocols TLSv1.2 TLSv1.3;",
        "apache": "SSLProtocol -all +TLSv1.2 +TLSv1.3",
        "caddy": "tls {\n    protocols tls1.2 tls1.3\n}",
        "haproxy": "ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets",
        "iis": "# PowerShell (reboot required)\nNew-Item 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server' -Force |\n  New-ItemProperty -Name Enabled -Value 0 -PropertyType DWord -Force\n# repeat for 'TLS 1.1', 'SSL 3.0', 'SSL 2.0'",
    },
    "ciphers": {
        "nginx": f"ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers {MOZ_INTERMEDIATE_OPENSSL};\nssl_prefer_server_ciphers off;",
        "apache": f"SSLProtocol -all +TLSv1.2 +TLSv1.3\nSSLCipherSuite {MOZ_INTERMEDIATE_OPENSSL}\nSSLHonorCipherOrder off",
        "caddy": "# Caddy's defaults already match Mozilla Intermediate; remove custom 'ciphers' lines.",
        "haproxy": f"ssl-default-bind-ciphers {MOZ_INTERMEDIATE_OPENSSL}\nssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
    },
    "dhparam": {
        "nginx": "# RFC 7919 ffdhe2048 group\ncurl https://ssl-config.mozilla.org/ffdhe2048.txt > /etc/nginx/dhparam.pem\nssl_dhparam /etc/nginx/dhparam.pem;",
        "apache": "SSLOpenSSLConfCmd DHParameters /etc/ssl/ffdhe2048.pem",
    },
    "pq": {
        "nginx": "# nginx built against OpenSSL 3.5+\nssl_ecdh_curve X25519MLKEM768:X25519:prime256v1:secp384r1;",
        "apache": "SSLOpenSSLConfCmd Curves X25519MLKEM768:X25519:prime256v1:secp384r1",
        "caddy": "# Caddy 2.10+ (Go 1.24+) enables X25519MLKEM768 by default.",
    },
    "fullchain": {
        "nginx": "ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;  # not cert.pem\nssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;",
        "apache": "SSLCertificateFile /etc/letsencrypt/live/example.com/fullchain.pem\nSSLCertificateKeyFile /etc/letsencrypt/live/example.com/privkey.pem",
    },
    "ocsp_stapling": {
        "nginx": "ssl_stapling on;\nssl_stapling_verify on;\nssl_trusted_certificate /etc/letsencrypt/live/example.com/chain.pem;\nresolver 1.1.1.1 9.9.9.9 valid=300s;",
        "apache": "SSLUseStapling On\nSSLStaplingCache \"shmcb:logs/ssl_stapling(32768)\"",
    },
    "https_redirect": {
        "nginx": "server {\n    listen 80;\n    listen [::]:80;\n    server_name example.com www.example.com;\n    return 301 https://$host$request_uri;\n}",
        "apache": "<VirtualHost *:80>\n    ServerName example.com\n    Redirect permanent / https://example.com/\n</VirtualHost>",
        "caddy": "# Caddy redirects HTTP to HTTPS automatically for site addresses with a domain name.",
        "cloudflare": "SSL/TLS -> Edge Certificates -> Always Use HTTPS: On",
    },
    "hsts": {
        "nginx": 'add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;',
        "apache": 'Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"',
        "caddy": 'header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"',
        "express": "app.use(helmet.hsts({ maxAge: 63072000, includeSubDomains: true, preload: true }));",
        "cloudflare": "SSL/TLS -> Edge Certificates -> HTTP Strict Transport Security (HSTS): enable, max-age 12 months, include subdomains, preload",
    },
    "csp": {
        "nginx": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'nonce-$request_id' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'; form-action 'self'; upgrade-insecure-requests\" always;",
        "apache": "Header always set Content-Security-Policy \"default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'; form-action 'self'; upgrade-insecure-requests\"",
        "caddy": "header Content-Security-Policy \"default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'; form-action 'self'\"",
        "express": "app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: [\"'self'\"], objectSrc: [\"'none'\"], baseUri: [\"'none'\"], frameAncestors: [\"'self'\"] } }));",
    },
    "frame": {
        "nginx": "add_header Content-Security-Policy \"frame-ancestors 'self'\" always;\nadd_header X-Frame-Options SAMEORIGIN always;",
        "apache": "Header always set X-Frame-Options SAMEORIGIN\nHeader always append Content-Security-Policy \"frame-ancestors 'self'\"",
        "caddy": "header X-Frame-Options SAMEORIGIN",
        "express": "app.use(helmet.frameguard({ action: 'sameorigin' }));",
    },
    "nosniff": {
        "nginx": "add_header X-Content-Type-Options nosniff always;",
        "apache": "Header always set X-Content-Type-Options nosniff",
        "caddy": "header X-Content-Type-Options nosniff",
        "express": "app.use(helmet.noSniff());",
    },
    "referrer": {
        "nginx": "add_header Referrer-Policy strict-origin-when-cross-origin always;",
        "apache": "Header always set Referrer-Policy strict-origin-when-cross-origin",
        "caddy": "header Referrer-Policy strict-origin-when-cross-origin",
        "express": "app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));",
    },
    "permissions": {
        "nginx": "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()\" always;",
        "apache": "Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=(), payment=(), usb=()\"",
        "caddy": "header Permissions-Policy \"camera=(), microphone=(), geolocation=(), payment=(), usb=()\"",
    },
    "isolation": {
        "nginx": "add_header Cross-Origin-Opener-Policy same-origin always;\nadd_header Cross-Origin-Resource-Policy same-site always;",
        "apache": "Header always set Cross-Origin-Opener-Policy same-origin\nHeader always set Cross-Origin-Resource-Policy same-site",
        "caddy": "header Cross-Origin-Opener-Policy same-origin\nheader Cross-Origin-Resource-Policy same-site",
        "express": "app.use(helmet.crossOriginOpenerPolicy()); app.use(helmet.crossOriginResourcePolicy({ policy: 'same-site' }));",
    },
    "server_tokens": {
        "nginx": "server_tokens off;\nproxy_hide_header X-Powered-By;",
        "apache": "ServerTokens Prod\nServerSignature Off\nHeader always unset X-Powered-By",
        "php": "; php.ini\nexpose_php = Off",
        "express": "app.disable('x-powered-by');",
        "iis": "<system.webServer>\n  <security><requestFiltering removeServerHeader=\"true\" /></security>\n  <httpProtocol><customHeaders><remove name=\"X-Powered-By\" /></customHeaders></httpProtocol>\n</system.webServer>",
    },
    "cookies": {
        "nginx": "proxy_cookie_flags ~ secure httponly samesite=lax;  # nginx 1.19.3+",
        "apache": "Header always edit Set-Cookie ^(.*)$ \"$1; Secure; HttpOnly; SameSite=Lax\"",
        "express": "app.use(session({ cookie: { secure: true, httpOnly: true, sameSite: 'lax' } }));",
        "php": "session.cookie_secure = 1\nsession.cookie_httponly = 1\nsession.cookie_samesite = \"Lax\"",
        "django": "SESSION_COOKIE_SECURE = True\nCSRF_COOKIE_SECURE = True\nSESSION_COOKIE_SAMESITE = 'Lax'",
    },
    "cors": {
        "nginx": "# Reflect only known origins\nmap $http_origin $cors_ok { default \"\"; \"https://app.example.com\" $http_origin; }\nadd_header Access-Control-Allow-Origin $cors_ok always;\nadd_header Vary Origin always;",
        "express": "app.use(cors({ origin: ['https://app.example.com'], credentials: true }));",
    },
    "sri": {
        "html": "<script src=\"https://cdn.example.com/lib.min.js\"\n        integrity=\"sha384-<base64 hash>\"\n        crossorigin=\"anonymous\"></script>\n<!-- hash: openssl dgst -sha384 -binary lib.min.js | openssl base64 -A -->",
    },
    "security_txt": {
        "file": "# /.well-known/security.txt (RFC 9116)\nContact: mailto:security@example.com\nExpires: 2027-12-31T23:59:59Z\nPreferred-Languages: en\nCanonical: https://example.com/.well-known/security.txt\nPolicy: https://example.com/security-policy",
    },
    "spf": {
        "dns": "example.com.  TXT  \"v=spf1 include:_spf.google.com -all\"\n; domain that sends no mail at all:\nexample.com.  TXT  \"v=spf1 -all\"",
    },
    "dmarc": {
        "dns": "_dmarc.example.com.  TXT  \"v=DMARC1; p=reject; rua=mailto:dmarc@example.com; adkim=s; aspf=s\"\n; roll out gradually: p=none -> p=quarantine; pct=25 -> p=reject",
    },
    "null_mx": {
        "dns": "example.com.  MX   0 .            ; RFC 7505 'this domain accepts no mail'\nexample.com.  TXT  \"v=spf1 -all\"\n_dmarc.example.com.  TXT  \"v=DMARC1; p=reject\"",
    },
    "mta_sts": {
        "dns": "_mta-sts.example.com.  TXT  \"v=STSv1; id=20261012T000000\"",
        "policy": "# https://mta-sts.example.com/.well-known/mta-sts.txt\nversion: STSv1\nmode: enforce\nmx: mx1.example.com\nmax_age: 1209600",
    },
    "tlsrpt": {
        "dns": "_smtp._tls.example.com.  TXT  \"v=TLSRPTv1; rua=mailto:tlsrpt@example.com\"",
    },
    "caa": {
        "dns": "example.com.  CAA  0 issue \"letsencrypt.org\"\nexample.com.  CAA  0 issuewild \";\"\nexample.com.  CAA  0 iodef \"mailto:security@example.com\"",
    },
    "dnssec": {
        "cloudflare": "DNS -> Settings -> DNSSEC -> Enable, then add the DS record at your registrar.",
        "route53": "aws route53 enable-hosted-zone-dnssec --hosted-zone-id <ZONE_ID>  # after creating a KSK",
        "bind": "dnssec-policy default;\ninline-signing yes;",
    },
}
