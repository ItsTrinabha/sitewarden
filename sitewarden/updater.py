"""`sitewarden update`: refresh bundled threat and policy data from their upstream sources."""

from __future__ import annotations

import gzip
import json
import os
import pathlib
import re
import urllib.request

SOURCES = {
    "retirejs-repository.json": "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json",
    "public_suffix_list.dat.gz": "https://publicsuffix.org/list/public_suffix_list.dat",
    "hsts-preload.txt.gz": "https://raw.githubusercontent.com/chromium/chromium/main/net/http/transport_security_state_static.json",
    "mozilla-guidelines.json": "https://ssl-config.mozilla.org/guidelines/latest.json",
}
FALLBACKS = {
    "public_suffix_list.dat.gz": "https://raw.githubusercontent.com/publicsuffix/list/main/public_suffix_list.dat",
}


def cache_dir() -> pathlib.Path:
    d = pathlib.Path(os.environ.get("SITEWARDEN_DATA_DIR") or pathlib.Path.home() / ".cache" / "sitewarden")
    d.mkdir(parents=True, exist_ok=True)
    return d


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "sitewarden-updater"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def _convert(name: str, raw: bytes) -> bytes:
    if name == "retirejs-repository.json" or name == "mozilla-guidelines.json":
        json.loads(raw)  # validate
        return raw
    if name == "public_suffix_list.dat.gz":
        if b"===BEGIN ICANN DOMAINS===" not in raw:
            raise ValueError("not a public suffix list")
        return gzip.compress(raw, 9)
    if name == "hsts-preload.txt.gz":
        text = re.sub(r"^\s*//.*$", "", raw.decode("utf-8"), flags=re.M)
        data = json.loads(text)
        lines = sorted(f"{e['name'].lower()} {'i' if e.get('include_subdomains') else 'e'}"
                       for e in data["entries"] if e.get("mode") == "force-https")
        if len(lines) < 1000:
            raise ValueError("preload list suspiciously small")
        return gzip.compress(("\n".join(lines) + "\n").encode(), 9)
    return raw


def update_all(verbose: bool = False) -> bool:
    out = cache_dir()
    ok = True
    for name, url in SOURCES.items():
        for candidate in [url] + ([FALLBACKS[name]] if name in FALLBACKS else []):
            try:
                data = _convert(name, _get(candidate))
            except Exception as exc:  # network errors, bad data
                if verbose:
                    print(f"  ✘ {name}: {candidate}: {exc}")
                continue
            tmp = out / (name + ".tmp")
            tmp.write_bytes(data)
            tmp.replace(out / name)
            if verbose:
                print(f"  ✔ {name} ({len(data) // 1024} KiB) from {candidate}")
            break
        else:
            ok = False
    if verbose:
        print(f"Data directory: {out}")
    return ok
