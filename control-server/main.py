from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import FileResponse

from core.config import get_settings
from core.database import engine
from db.models import Base

# API routes
from api.routes import agents, leads, scans, itflow
from api.routes import agents, leads, scans, itflow, agent_download

# Web UI routes
from web.routes import ui

settings = get_settings()


# =============================================================
# Lifespan
# =============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Runs once on startup and once on shutdown.
    Startup: confirm database connectivity.
    Shutdown: dispose of the connection pool cleanly.
    """
    # Startup
    print(f"FirstLook Control Server starting...")
    print(f"Database: {settings.database_url.split('@')[-1]}")  # Log host only, not credentials
    print(f"Base URL: {settings.firstlook_base_url}")

    if settings.itflow_url:
        print(f"ITflow:   {settings.itflow_url}")
    else:
        print(f"ITflow:   not configured")

    yield

    # Shutdown
    print("FirstLook Control Server shutting down...")
    engine.dispose()


# =============================================================
# App
# =============================================================

app = FastAPI(
    title="FirstLook",
    description="Open source network discovery for MSPs.",
    version="0.1.0",
    lifespan=lifespan,
    # Disable the default /docs and /redoc in production
    # by setting docs_url and redoc_url to None.
    # Leave enabled during development.
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)


# =============================================================
# Static Files
# =============================================================

app.mount(
    "/static",
    StaticFiles(directory="web/static"),
    name="static",
)

@app.get("/agent/install.sh", include_in_schema=False)
def serve_install_script():
    """Serve the agent install script."""
    script_path = Path(__file__).parent / "web" / "static" / "agent" / "install.sh"
    return FileResponse(
        path=script_path,
        media_type="text/x-shellscript",
        filename="install.sh",
    )

# =============================================================
# API Routes
# =============================================================
# All API routes are prefixed with /api so they are clearly
# separated from the web UI routes.

app.include_router(
    leads.router,
    prefix="/api/clients",
    tags=["Clients"],
)

app.include_router(
    agents.router,
    prefix="/api/agents",
    tags=["Agents"],
)

app.include_router(
    scans.router,
    prefix="/api/scans",
    tags=["Scans"],
)

app.include_router(
    itflow.router,
    prefix="/api/itflow",
    tags=["ITflow"],
)

app.include_router(
    agent_download.router,
    prefix="/agent",
    tags=["Agent Download"],
)

# =============================================================
# Web UI Routes
# =============================================================

app.include_router(ui.router)


# =============================================================
# Health Check
# =============================================================

@app.get("/health", tags=["Health"], include_in_schema=False)
def health_check():
    """
    Simple liveness check used by Docker Compose and
    any upstream load balancer or monitoring tool.
    """
    return {"status": "ok", "version": "0.1.0"}
