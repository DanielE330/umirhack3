from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import sessionmaker

from .config import Settings, get_settings
from .db import init_db, make_engine
from .hub import Hub
from .orchestrator import Orchestrator
from .routers import agent_api, events, machines, profiles, traps
from .routers import auth as auth_router
from .routers import users as users_router
from .security import Vault

STATIC = Path(__file__).parent / "static"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(title="HoneyForge", docs_url="/docs" if settings.docs_enabled else None,
                  redoc_url=None, openapi_url="/openapi.json" if settings.docs_enabled else None)

    engine = make_engine(settings.database_url)
    init_db(engine)
    app.state.settings = settings
    app.state.vault = Vault(settings.secret_key)
    app.state.hub = Hub()
    app.state.orchestrator = Orchestrator(settings)
    app.state.session_factory = sessionmaker(engine, expire_on_commit=False)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        else:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
        return response

    @app.exception_handler(Exception)
    async def unhandled(_: Request, __: Exception):
        return JSONResponse({"detail": "Внутренняя ошибка"}, status_code=500)  # без деталей наружу

    app.include_router(auth_router.router)
    app.include_router(users_router.router)
    app.include_router(profiles.router)
    app.include_router(traps.router)
    app.include_router(machines.router)
    app.include_router(events.router)
    app.include_router(agent_api.router)

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    if STATIC.is_dir():
        app.mount("/static", StaticFiles(directory=STATIC), name="static")

        @app.get("/", include_in_schema=False)
        def index():
            return FileResponse(STATIC / "index.html")

        @app.get("/favicon.ico", include_in_schema=False)
        def favicon():
            return FileResponse(STATIC / "favicon.ico")

    return app
