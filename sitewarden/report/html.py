"""Self-contained HTML report: the web UI's renderer with the report embedded as JSON."""

from __future__ import annotations

import html
import json
from importlib import resources


def render(report: dict) -> str:
    static = resources.files("sitewarden.web").joinpath("static")
    css = static.joinpath("app.css").read_text(encoding="utf-8")
    js = static.joinpath("app.js").read_text(encoding="utf-8")
    data = json.dumps(report).replace("</", "<\\/")
    title = html.escape(f"{report.get('target')} · {report.get('grade')} · Sitewarden report")
    return f"""<!doctype html>
<html lang="en" data-standalone="1">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>{css}</style>
</head>
<body>
<div id="app"></div>
<script type="application/json" id="report-data">{data}</script>
<script>{js}</script>
</body>
</html>
"""
