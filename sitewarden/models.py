"""Core result types shared by every check module."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    PASS = "pass"

    @property
    def rank(self) -> int:
        return ["pass", "info", "low", "medium", "high", "critical"].index(self.value)


CATEGORIES = {
    "tls": "TLS protocols & ciphers",
    "certificate": "Certificate",
    "headers": "HTTP security headers",
    "cookies": "Cookies",
    "content": "Page content & scripts",
    "dns": "DNS & domain",
    "email": "Email authentication",
}

GRADES = ["A+", "A", "A-", "B", "C", "D", "E", "F"]


@dataclass
class Finding:
    id: str
    category: str
    severity: Severity
    title: str
    detail: str = ""
    evidence: str | None = None
    fix: str | None = None
    snippets: dict[str, str] = field(default_factory=dict)
    refs: list[str] = field(default_factory=list)
    cap: str | None = None  # the best overall grade possible while this finding stands
    tags: list[str] = field(default_factory=list)  # e.g. CWE-319, PCI-DSS 4.2.1

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


def worse_grade(a: str | None, b: str | None) -> str | None:
    if a is None:
        return b
    if b is None:
        return a
    return a if GRADES.index(a) > GRADES.index(b) else b


class Findings(list):
    """A list of Finding with small helpers for the check modules."""

    def __init__(self, category: str):
        super().__init__()
        self.category = category

    def add(self, id: str, severity: Severity, title: str, detail: str = "", **kw) -> Finding:
        f = Finding(id=id, category=kw.pop("category", self.category), severity=severity, title=title,
                    detail=detail, **kw)
        self.append(f)
        return f

    def ok(self, id: str, title: str, detail: str = "", **kw) -> Finding:
        return self.add(id, Severity.PASS, title, detail, **kw)
