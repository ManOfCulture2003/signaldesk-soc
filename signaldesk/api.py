"""Loopback-only, single-user UI. No external log transmission."""
import hmac
from pathlib import Path
import secrets

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .detections import RULES
from .events import MAX_BYTES
from .store import Conflict, Store
from .access import LocalAccess, BodyLimit
from .paths import data_directory

STATIC = Path(__file__).parent / "static"


class Triage(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    version: int = Field(ge=1)
    status: str
    disposition: str = ""
    owner: str = Field(default="", max_length=100)
    note: str = Field(min_length=1, max_length=4000)


def create_app(db_path=None, access_key=None):
    app = FastAPI(title="SignalDesk SOC", version="0.1.0", docs_url=None, redoc_url=None)
    store = Store(db_path or data_directory() / "signaldesk.sqlite")
    token = secrets.token_urlsafe(32)
    app.state.store = store

    @app.middleware("http")
    async def local_guard(request, call_next):
        # Custom header blocks cross-origin form submissions; token is never persisted.
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            if not hmac.compare_digest(request.headers.get("X-SignalDesk-Token", "").encode(), token.encode()):
                return JSONResponse({"detail": "Missing or invalid local session token"}, status_code=403)
            origin = request.headers.get("origin")
            if origin and origin != str(request.base_url).rstrip("/"):
                return JSONResponse({"detail": "Cross-origin mutation rejected"}, status_code=403)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        return response

    app.add_middleware(BodyLimit)
    app.state.access = LocalAccess("signaldesk", STATIC, access_key)
    app.middleware("http")(app.state.access.guard)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "[::1]"])

    @app.get("/healthz")
    def readiness():
        return {"status": "ok"}

    @app.exception_handler(ValueError)
    async def invalid(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=409 if isinstance(exc, Conflict) else 400)

    @app.exception_handler(KeyError)
    async def missing(request, exc):
        return JSONResponse({"detail": "Case not found"}, status_code=404)

    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/")
    def home():
        return FileResponse(STATIC / "index.html")

    @app.get("/api/session")
    def session():
        return {"token": token}

    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": "0.1.0", "mode": "local_single_user"}

    @app.get("/api/stats")
    def stats():
        return store.stats()

    @app.get("/api/rules")
    def rules():
        return RULES

    @app.get("/api/events")
    def events(host: str = "", kind: str = "", user: str = "", src_ip: str = "",
               limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
        return store.events(host=host, kind=kind, user=user, src_ip=src_ip, limit=limit, offset=offset)

    @app.post("/api/import")
    async def ingest(request: Request, format: str = "ndjson"):
        payload = bytearray()
        async for chunk in request.stream():
            payload.extend(chunk)
            if len(payload) > MAX_BYTES:
                raise HTTPException(413, "Import exceeds 5 MiB")
        # SQLite work is synchronous; run it outside the event loop.
        from starlette.concurrency import run_in_threadpool
        return await run_in_threadpool(store.ingest, bytes(payload), format)

    @app.post("/api/detect")
    def detection():
        return store.run_detection()

    @app.post("/api/collect/windows")
    def collect_windows():
        from .windows import collect
        return collect(store)

    @app.get("/api/alerts")
    def alerts():
        return store.alerts()

    @app.get("/api/alerts/{alert_id}")
    def detail(alert_id: str):
        return store.case(alert_id)

    @app.post("/api/alerts/{alert_id}/triage")
    def triage(alert_id: str, change: Triage):
        return store.triage(alert_id, **change.model_dump())

    @app.get("/api/alerts/{alert_id}/export")
    def export(alert_id: str):
        return JSONResponse(store.case(alert_id), headers={"Content-Disposition": 'attachment; filename="signaldesk-case.json"'})

    return app
