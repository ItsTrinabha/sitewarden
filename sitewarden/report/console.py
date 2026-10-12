"""Terminal report with ANSI colours (disabled automatically when not a TTY)."""

from __future__ import annotations

import os
import shutil
import sys
import textwrap

SEV_ORDER = ["critical", "high", "medium", "low", "info", "pass"]
SEV_COLOR = {"critical": "1;37;41", "high": "1;31", "medium": "1;33", "low": "36", "info": "2", "pass": "32"}
SEV_LABEL = {"critical": "CRIT", "high": "HIGH", "medium": "MED ", "low": "LOW ", "info": "INFO", "pass": "PASS"}
GRADE_COLOR = {"A+": "1;32", "A": "1;32", "A-": "1;32", "B": "1;33", "C": "1;33", "D": "1;31", "E": "1;31", "F": "1;37;41"}


def _use_color(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


def render(report: dict, *, show_passed: bool = False, stream=None) -> str:
    stream = stream or sys.stdout
    color = _use_color(stream)
    width = min(shutil.get_terminal_size((100, 20)).columns, 110)

    def c(code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if color else text

    out = []
    g = report.get("grade", "?")
    out.append("")
    out.append(f"  {c('1', 'Sitewarden')} {report.get('version', '')}  ·  {report['target']}"
               + (f":{report['port']}" if report.get("port", 443) != 443 else "")
               + (f"  ({report['ip']})" if report.get("ip") else ""))
    out.append("")
    out.append(f"  Grade  {c(GRADE_COLOR.get(g, '1'), f' {g} ')}   score {report.get('score')}/100   "
               f"scanned in {report.get('duration_ms', 0) / 1000:.1f}s")
    if report.get("capped_by"):
        out.append(c("2", "  Grade capped by: " + "; ".join(report["capped_by"])))
    out.append("")
    for info in report.get("categories", {}).values():
        if info.get("skipped"):
            line = f"  {info['label']:<28} {c('2', 'skipped')}"
        else:
            bar_len = int((info["score"] or 0) / 5)
            bar = "█" * bar_len + "░" * (20 - bar_len)
            grade_txt = c(GRADE_COLOR.get(info["grade"], "1"), f"{info['grade']:<2}")
            line = f"  {info['label']:<28} {grade_txt} {bar} {info['score']:>3}"
        out.append(line)
    out.append("")

    findings = report.get("findings", [])
    for sev in SEV_ORDER:
        if sev == "pass" and not show_passed:
            continue
        group = [f for f in findings if f["severity"] == sev]
        if not group:
            continue
        for f in group:
            tag = c(SEV_COLOR[sev], f"[{SEV_LABEL[sev]}]")
            out.append(f"  {tag} {f['title']}  {c('2', f['category'])}")
            if sev in ("critical", "high", "medium") or (sev == "low" and show_passed):
                body = f.get("detail") or ""
                for line in textwrap.wrap(body, width - 10):
                    out.append("         " + line)
                if f.get("evidence"):
                    for line in textwrap.wrap("Evidence: " + f["evidence"], width - 10)[:3]:
                        out.append("         " + c("2", line))
                if f.get("fix"):
                    for line in textwrap.wrap("Fix: " + f["fix"], width - 10):
                        out.append("         " + c("32", line))
    s = report.get("summary", {})
    out.append("")
    out.append("  " + "  ".join(f"{c(SEV_COLOR[k], SEV_LABEL[k].strip())} {s.get(k, 0)}" for k in SEV_ORDER))
    comp = report.get("compliance", {})
    if comp:
        out.append("")
        for v in comp.values():
            mark = c("32", "✔") if v["compliant"] else c("31", "✘")
            extra = "" if v["compliant"] else c("2", "  " + "; ".join(v["problems"][:2]))
            out.append(f"  {mark} {v['name']}{extra}")
    for note in report.get("notes", []):
        out.append(c("2", "  note: " + note))
    for k, v in report.get("errors", {}).items():
        out.append(c("31", f"  error in {k}: {v}"))
    out.append("")
    return "\n".join(out)
