"""Web interface and JSON API (FastAPI)."""

from __future__ import annotations

import asyncio
import concurrent.futures as cf
import hashlib
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from collections import defaultdict, deque
from importlib import resources
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

from .. import __version__
from ..net import Network
from ..report import html as html_report
from ..report import markdown
from ..scan import ScanError, ScanOptions, normalize_target, run_scan

STATIC = Path(str(resources.files("sitewarden.web").joinpath("static")))


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


MAX_CONCURRENT = _env_int("SITEWARDEN_MAX_CONCURRENT", 4)
RATE_PER_HOUR = _env_int("SITEWARDEN_RATE_LIMIT", 20)
CACHE_SECONDS = _env_int("SITEWARDEN_CACHE_SECONDS", 900)
RESCAN_COOLDOWN = _env_int("SITEWARDEN_RESCAN_COOLDOWN", 120)
ALLOW_PRIVATE = os.environ.get("SITEWARDEN_ALLOW_PRIVATE") == "1"
TRUST_PROXY = os.environ.get("SITEWARDEN_TRUST_PROXY") == "1"

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
        "font-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; "
        "object-src 'none'; require-trusted-types-for 'script'; trusted-types 'none'; upgrade-insecure-requests"
    ),
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "X-Permitted-Cross-Domain-Policies": "none",
}


# --------------------------------------------------------------------------- storage


class Store:
    def __init__(self, path: str):
        self.path = path
        self._local = threading.local()
        with self._conn() as c:
            c.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created REAL NOT NULL,
                    finished REAL,
                    grade TEXT,
                    score REAL,
                    hidden INTEGER NOT NULL DEFAULT 0,
                    error TEXT,
                    report TEXT
                );
                CREATE INDEX IF NOT EXISTS scans_target ON scans(target, created);
                CREATE INDEX IF NOT EXISTS scans_recent ON scans(status, hidden, finished);
            """)

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def create(self, scan_id: str, target: str, hidden: bool) -> None:
        with self._conn() as c:
            c.execute("INSERT INTO scans(id, target, status, created, hidden) VALUES (?,?,?,?,?)",
                      (scan_id, target, "queued", time.time(), int(hidden)))

    def update(self, scan_id: str, **fields) -> None:
        cols = ", ".join(f"{k}=?" for k in fields)
        with self._conn() as c:
            c.execute(f"UPDATE scans SET {cols} WHERE id=?", (*fields.values(), scan_id))

    def get(self, scan_id: str) -> sqlite3.Row | None:
        return self._conn().execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()

    def latest_for(self, target: str, max_age: float | None = None, statuses=("done",)) -> sqlite3.Row | None:
        q = f"SELECT * FROM scans WHERE target=? AND status IN ({','.join('?' * len(statuses))})"
        args: list = [target, *statuses]
        if max_age is not None:
            q += " AND created>=?"
            args.append(time.time() - max_age)
        q += " ORDER BY created DESC LIMIT 1"
        return self._conn().execute(q, args).fetchone()

    def recent(self, limit: int = 12) -> list[dict]:
        rows = self._conn().execute(
            "SELECT id, target, grade, score, finished FROM scans WHERE status='done' AND hidden=0 "
            "AND id IN (SELECT id FROM scans s2 WHERE s2.target=scans.target ORDER BY created DESC LIMIT 1) "
            "ORDER BY finished DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> dict:
        row = self._conn().execute("SELECT COUNT(*) n, COUNT(DISTINCT target) t FROM scans WHERE status='done'").fetchone()
        return {"scans": row["n"], "sites": row["t"]}


# --------------------------------------------------------------------------- rate limiting


class ScanRequest(BaseModel):
    target: str = Field(..., max_length=300)
    hidden: bool = False
    force: bool = False


class RateLimiter:
    def __init__(self, per_hour: int):
        self.per_hour = per_hour
        self.hits: dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str) -> tuple[bool, int]:
        now = time.time()
        with self.lock:
            q = self.hits[key]
            while q and now - q[0] > 3600:
                q.popleft()
            if len(q) >= self.per_hour:
                return False, int(3600 - (now - q[0])) + 1
            q.append(now)
            return True, 0


# --------------------------------------------------------------------------- scan jobs


class Jobs:
    def __init__(self, store: Store, net_factory=None, options=None):
        self.store = store
        self.net_factory = net_factory or (lambda: Network.from_env(allow_private=ALLOW_PRIVATE))
        self.options = options or ScanOptions()
        self.pool = cf.ThreadPoolExecutor(MAX_CONCURRENT, thread_name_prefix="scan")
        self.events: dict[str, list[dict]] = {}
        self.lock = threading.Lock()
        self.inflight: dict[str, str] = {}  # target -> scan id

    def submit(self, target: str, hidden: bool) -> str:
        with self.lock:
            if target in self.inflight:
                return self.inflight[target]
            scan_id = secrets.token_urlsafe(12)
            self.store.create(scan_id, target, hidden)
            self.events[scan_id] = []
            self.inflight[target] = scan_id
        self.pool.submit(self._run, scan_id, target)
        return scan_id

    def _emit(self, scan_id: str, stage: str, message: str) -> None:
        with self.lock:
            evs = self.events.setdefault(scan_id, [])
            evs.append({"stage": stage, "message": message, "t": round(time.time(), 2)})
            del evs[:-200]

    def progress(self, scan_id: str) -> list[dict]:
        with self.lock:
            return list(self.events.get(scan_id, []))

    def _run(self, scan_id: str, target: str) -> None:
        self.store.update(scan_id, status="running")
        net = self.net_factory()
        try:
            opts = self.options(target) if callable(self.options) else self.options
            report = run_scan(target, net, opts, lambda st, msg: self._emit(scan_id, st, msg))
            report["id"] = scan_id
            self.store.update(scan_id, status="done", finished=time.time(), grade=report["grade"],
                              score=report["score"], report=json.dumps(report, default=str))
            self._emit(scan_id, "done", f"Grade {report['grade']}")
        except ScanError as exc:
            self.store.update(scan_id, status="error", finished=time.time(), error=str(exc))
            self._emit(scan_id, "error", str(exc))
        except Exception as exc:  # never leave a scan stuck in "running"
            self.store.update(scan_id, status="error", finished=time.time(),
                              error=f"Internal error: {exc.__class__.__name__}")
            self._emit(scan_id, "error", "Internal error")
        finally:
            with self.lock:
                if self.inflight.get(target) == scan_id:
                    del self.inflight[target]


# --------------------------------------------------------------------------- app


def create_app(db_path: str | None = None, *, net_factory=None, scan_options=None) -> FastAPI:
    """The web app. ``net_factory`` and ``scan_options`` (options, or a function of the target that
    returns them) let tests and the lab point scans at local servers."""
    store = Store(db_path or os.environ.get("SITEWARDEN_DB", "sitewarden.db"))
    jobs = Jobs(store, net_factory, scan_options)
    limiter = RateLimiter(RATE_PER_HOUR)
    app = FastAPI(title="Sitewarden", version=__version__, docs_url="/api/docs", redoc_url=None,
                  openapi_url="/api/openapi.json")
    app.state.store = store
    app.state.jobs = jobs

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if request.url.path.startswith("/api/docs"):
            # Swagger UI needs its CDN assets and an inline bootstrap script.
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; "
                "frame-ancestors 'none'; object-src 'none'; base-uri 'none'")
            del response.headers["Cross-Origin-Embedder-Policy"]
        if request.url.path.startswith("/badge/"):
            response.headers["Cross-Origin-Resource-Policy"] = "cross-origin"
        return response

    def client_key(request: Request) -> str:
        ip = request.client.host if request.client else "unknown"
        if TRUST_PROXY:
            fwd = request.headers.get("x-forwarded-for")
            if fwd:
                ip = fwd.split(",")[0].strip()
        return hashlib.sha256(ip.encode()).hexdigest()[:16]

    @app.post("/api/scans", status_code=202)
    def start_scan(req: ScanRequest, request: Request):
        try:
            host, port = normalize_target(req.target)
        except ScanError as exc:
            raise HTTPException(400, str(exc)) from exc
        if port not in (None, 443):
            raise HTTPException(400, "The public scanner only tests port 443. Use the CLI for other ports.")
        if not req.force:
            cached = store.latest_for(host, CACHE_SECONDS)
            if cached:
                return {"id": cached["id"], "status": "done", "cached": True}
        else:
            recent = store.latest_for(host, RESCAN_COOLDOWN, statuses=("done", "running", "queued"))
            if recent:
                return {"id": recent["id"], "status": recent["status"], "cached": True}
        ok, retry = limiter.allow(client_key(request))
        if not ok:
            raise HTTPException(429, f"Too many scans from your address. Try again in {retry // 60 + 1} minutes.",
                                headers={"Retry-After": str(retry)})
        scan_id = jobs.submit(host, req.hidden)
        return {"id": scan_id, "status": "queued", "cached": False}

    def _row_or_404(scan_id: str):
        if not re.fullmatch(r"[A-Za-z0-9_-]{8,40}", scan_id):
            raise HTTPException(404, "Unknown scan")
        row = store.get(scan_id)
        if row is None:
            raise HTTPException(404, "Unknown scan")
        return row

    @app.get("/api/scans/{scan_id}")
    def get_scan(scan_id: str):
        row = _row_or_404(scan_id)
        out = {"id": row["id"], "target": row["target"], "status": row["status"], "created": row["created"],
               "finished": row["finished"], "grade": row["grade"], "score": row["score"], "error": row["error"],
               "progress": jobs.progress(scan_id)}
        if row["status"] == "done" and row["report"]:
            out["report"] = json.loads(row["report"])
        return out

    @app.get("/api/scans/{scan_id}/events")
    async def scan_events(scan_id: str):
        _row_or_404(scan_id)

        async def stream():
            sent = 0
            for _ in range(1800):  # at most ~15 minutes
                evs = jobs.progress(scan_id)
                for ev in evs[sent:]:
                    yield f"data: {json.dumps(ev)}\n\n"
                sent = len(evs)
                row = store.get(scan_id)
                if row["status"] in ("done", "error"):
                    yield f"event: end\ndata: {json.dumps({'status': row['status']})}\n\n"
                    return
                await asyncio.sleep(0.5)

        return StreamingResponse(stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

    @app.get("/api/scans/{scan_id}/report.{fmt}")
    def export(scan_id: str, fmt: str):
        row = _row_or_404(scan_id)
        if row["status"] != "done":
            raise HTTPException(409, "Scan not finished")
        report = json.loads(row["report"])
        name = f"sitewarden-{row['target']}"
        if fmt == "json":
            return Response(json.dumps(report, indent=2), media_type="application/json",
                            headers={"Content-Disposition": f'attachment; filename="{name}.json"'})
        if fmt == "md":
            return PlainTextResponse(markdown.render(report), media_type="text/markdown; charset=utf-8",
                                     headers={"Content-Disposition": f'attachment; filename="{name}.md"'})
        if fmt == "html":
            return HTMLResponse(html_report.render(report),
                                headers={"Content-Disposition": f'attachment; filename="{name}.html"',
                                         "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                                         "script-src 'unsafe-inline'; img-src data:; sandbox allow-scripts"})
        raise HTTPException(404, "Unknown format")

    @app.get("/api/recent")
    def recent():
        return {"recent": store.recent(), "stats": store.stats()}

    @app.get("/api/health")
    def health():
        return {"ok": True, "version": __version__}

    @app.get("/badge/{target}.svg")
    def badge(target: str):
        try:
            host, _ = normalize_target(target)
        except ScanError:
            raise HTTPException(404, "Unknown target") from None
        row = store.latest_for(host)
        g = row["grade"] if row else "?"
        return Response(_badge_svg(g), media_type="image/svg+xml", headers={"Cache-Control": "max-age=3600"})

    @app.get("/.well-known/security.txt")
    def security_txt():
        contact = os.environ.get("SITEWARDEN_SECURITY_CONTACT", "mailto:security@example.com")
        expires = time.strftime("%Y-%m-%dT00:00:00Z", time.gmtime(time.time() + 180 * 86400))
        return PlainTextResponse(f"Contact: {contact}\nExpires: {expires}\nPreferred-Languages: en\n")

    @app.get("/robots.txt")
    def robots():
        return PlainTextResponse("User-agent: *\nDisallow: /api/\nDisallow: /scan/\n")

    @app.get("/static/{path:path}")
    def static(path: str):
        file = (STATIC / path).resolve()
        if not file.is_relative_to(STATIC.resolve()) or not file.is_file():
            raise HTTPException(404)
        return FileResponse(file, headers={"Cache-Control": "public, max-age=3600"})

    @app.get("/favicon.svg")
    def favicon():
        return FileResponse(STATIC / "favicon.svg", headers={"Cache-Control": "public, max-age=86400"})

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        if path.startswith("api/"):
            raise HTTPException(404)
        return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code, headers=exc.headers)

    return app


GRADE_COLORS = {"A+": "#1a7f37", "A": "#2da44e", "A-": "#4ac26b", "B": "#9a6700", "C": "#bc4c00",
                "D": "#cf222e", "E": "#a40e26", "F": "#82071e", "?": "#6e7781"}


def _badge_svg(grade: str) -> str:
    color = GRADE_COLORS.get(grade, "#6e7781")
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="112" height="20" role="img" aria-label="security: {grade}">
<title>security: {grade}</title>
<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
<clipPath id="r"><rect width="112" height="20" rx="3" fill="#fff"/></clipPath>
<g clip-path="url(#r)"><rect width="80" height="20" fill="#24292f"/><rect x="80" width="32" height="20" fill="{color}"/><rect width="112" height="20" fill="url(#s)"/></g>
<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
<text x="40" y="14">sitewarden</text><text x="96" y="14" font-weight="bold">{grade}</text></g>
</svg>"""

