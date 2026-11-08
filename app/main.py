from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select

from app.api import router as api_router
from app.config import get_settings
from app.database import Base, SessionLocal, engine, migrate_schema
from app.models import User
from app.router_control.adapters import build_router_controller
from app.security import hash_password
from app.services.discovery import DiscoveryService
from app.services.diagnostics import NetworkDiagnosticsService
from app.services.maintenance import purge_expired_metadata
from app.services.router_health import RouterHealthService
from app.services.traffic import TrafficCollector
from app.services.speedtest import SpeedTestService

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)
settings = get_settings()
BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=BASE_DIR / "templates")


def bootstrap_database() -> None:
    if settings.environment == "production":
        if settings.secret_key == "development-only-change-me" or settings.secret_key.startswith("replace-with"):
            raise RuntimeError("Set HNM_SECRET_KEY before starting in production")
        if not settings.admin_password or settings.admin_password.startswith("replace-with"):
            raise RuntimeError("Set HNM_ADMIN_PASSWORD before starting in production")
    Base.metadata.create_all(bind=engine)
    migrate_schema()
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.username == settings.admin_username)) is not None:
            return
        password = settings.admin_password
        if not password:
            logger.warning("No administrator exists. Complete first-time setup from this computer.")
            return
        db.add(User(username=settings.admin_username, password_hash=hash_password(password)))
        db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    bootstrap_database()
    app.state.router_controller = build_router_controller(settings)
    app.state.traffic_collector = TrafficCollector(settings)
    app.state.scheduler = BackgroundScheduler(daemon=True)
    if settings.discovery_enabled:
        service = DiscoveryService(settings)
        app.state.scheduler.add_job(
            service.run,
            "interval",
            seconds=settings.discovery_interval_seconds,
            id="network-discovery",
            max_instances=1,
            coalesce=True,
        )
    if settings.diagnostics_enabled:
        diagnostics = NetworkDiagnosticsService(settings)
        app.state.scheduler.add_job(
            diagnostics.run,
            "interval",
            seconds=settings.diagnostics_interval_seconds,
            next_run_time=datetime.now(timezone.utc) + timedelta(seconds=5),
            id="network-diagnostics",
            max_instances=1,
            coalesce=True,
        )
    if settings.speedtest_enabled and settings.speedtest_scheduled:
        app.state.scheduler.add_job(
            SpeedTestService(settings).run,
            "interval",
            seconds=settings.speedtest_interval_seconds,
            next_run_time=datetime.now(timezone.utc) + timedelta(minutes=2),
            id="internet-speed-test",
            max_instances=1,
            coalesce=True,
        )
    if settings.router_adapter == "huawei_ont" and settings.router_health_enabled:
        app.state.scheduler.add_job(
            RouterHealthService(settings, app.state.router_controller).run,
            "interval",
            seconds=settings.router_health_interval_seconds,
            next_run_time=datetime.now(timezone.utc) + timedelta(seconds=30),
            id="router-health",
            max_instances=1,
            coalesce=True,
        )
    app.state.scheduler.add_job(
        purge_expired_metadata,
        "interval",
        hours=24,
        args=[settings],
        id="metadata-retention",
        max_instances=1,
        coalesce=True,
    )
    app.state.scheduler.start()
    app.state.traffic_collector.start()
    yield
    app.state.traffic_collector.stop()
    if app.state.scheduler.running:
        app.state.scheduler.shutdown(wait=False)


app = FastAPI(title=settings.app_name, version="0.5.0", lifespan=lifespan)
app.include_router(api_router)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; frame-ancestors 'none'"
    )
    return response


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="dashboard.html", context={"app_name": settings.app_name})


@app.get("/manifest.webmanifest", include_in_schema=False)
def manifest():
    return FileResponse(BASE_DIR / "static" / "manifest.webmanifest", media_type="application/manifest+json")


@app.get("/service-worker.js", include_in_schema=False)
def service_worker():
    return FileResponse(BASE_DIR / "static" / "service-worker.js", media_type="application/javascript")
