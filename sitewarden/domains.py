"""Public Suffix List and HSTS preload list lookups (bundled data, refreshable with `sitewarden update`)."""

from __future__ import annotations

import gzip
import os
import pathlib
from functools import lru_cache
from importlib import resources


def data_path(name: str) -> pathlib.Path:
    """User-refreshed copies in SITEWARDEN_DATA_DIR win over the bundled snapshot."""
    override = os.environ.get("SITEWARDEN_DATA_DIR") or str(pathlib.Path.home() / ".cache" / "sitewarden")
    p = pathlib.Path(override) / name
    if p.exists():
        return p
    return pathlib.Path(str(resources.files("sitewarden.data").joinpath(name)))


@lru_cache(maxsize=1)
def _psl() -> tuple[frozenset, frozenset, frozenset]:
    rules, wild, exc = set(), set(), set()
    with gzip.open(data_path("public_suffix_list.dat.gz"), "rt", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            rule = line.split()[0].lower()
            try:
                rule = rule.encode("idna").decode("ascii") if not rule.startswith(("*", "!")) else rule
            except UnicodeError:
                pass
            if rule.startswith("!"):
                exc.add(rule[1:])
            elif rule.startswith("*."):
                wild.add(rule[2:])
            else:
                rules.add(rule)
    return frozenset(rules), frozenset(wild), frozenset(exc)


def public_suffix(host: str) -> str:
    rules, wild, exc = _psl()
    labels = host.lower().rstrip(".").split(".")
    for i in range(len(labels)):
        cand = ".".join(labels[i:])
        if cand in exc:
            return ".".join(labels[i + 1:])
        if cand in rules:
            return cand
        parent = ".".join(labels[i + 1:])
        if parent and parent in wild:
            return cand
    return labels[-1]


def registrable_domain(host: str) -> str:
    """eTLD+1, e.g. www.bbc.co.uk -> bbc.co.uk."""
    host = host.lower().rstrip(".")
    suffix = public_suffix(host)
    if host == suffix:
        return host
    rest = host[: -len(suffix) - 1]
    return rest.split(".")[-1] + "." + suffix


@lru_cache(maxsize=1)
def _preload() -> dict[str, bool]:
    out: dict[str, bool] = {}
    with gzip.open(data_path("hsts-preload.txt.gz"), "rt", encoding="utf-8") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) == 2:
                out[parts[0]] = parts[1] == "i"
    return out


def hsts_preloaded(host: str) -> tuple[bool, str | None]:
    """(preloaded, matching entry). A parent entry counts only if it includes subdomains."""
    entries = _preload()
    labels = host.lower().rstrip(".").split(".")
    for i in range(len(labels)):
        cand = ".".join(labels[i:])
        if cand in entries and (i == 0 or entries[cand]):
            return True, cand
    return False, None
