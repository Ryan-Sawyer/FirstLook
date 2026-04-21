import io
import tarfile
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Response, status
from fastapi.responses import StreamingResponse
from typing import Optional
from sqlalchemy.orm import Session

from core.database import get_db
from core.security import verify_token
from db.models import Agent, AgentStatus

router = APIRouter()

# Path to the agent source directory, relative to the control server root.
# In production this is baked into the Docker image at build time.
AGENT_DIR = Path("/app/agent")


# =============================================================
# GET /agent/install.sh
# =============================================================
# Served as a static file via FastAPI's StaticFiles mount.
# No auth required — the token is embedded in the curl command
# by the prep page and passed as a CLI arg to install.sh.
# (Registered in main.py via app.mount("/static", ...))


# =============================================================
# GET /agent/download
# =============================================================

@router.get(
    "/download",
    summary="Download the agent archive — called by install.sh",
    response_class=StreamingResponse,
)
def download_agent(
    authorization: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    """
    Streams a tar.gz of the agent source directory.

    Authentication:
        Expects a Bearer token in the Authorization header.
        The token is matched against all pending/active agents.
        This means the install script can authenticate before
        the agent has registered — the token was issued at prep time.

    Returns:
        A streaming tar.gz download of the agent/ directory.
    """
    # ── Auth ──────────────────────────────────────────────────
    plain_token = _extract_bearer_token(authorization)

    agent = _find_agent_by_token(db, plain_token)
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # ── Verify agent dir exists ───────────────────────────────
    if not AGENT_DIR.exists() or not AGENT_DIR.is_dir():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Agent source directory not found on server",
        )

    # ── Build tar.gz in memory ────────────────────────────────
    #archive = _build_archive(AGENT_DIR)

    #filename = "firstlook-agent.tar.gz"

    #return StreamingResponse(
    #    content=iter([archive.getvalue()]),
    #    media_type="application/gzip",
    #    headers={
    #        "Content-Disposition": f"attachment; filename={filename}",
    #        "Content-Length": str(size),
    #    },
    #)

    # Build archive
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for file_path in sorted(AGENT_DIR.rglob("*")):
            if not file_path.is_file():
                continue
            name = file_path.name
            # Skip unwanted files
            if name in {".gitignore", ".DS_Store"}:
                continue
            if file_path.suffix in {".pyc", ".pyo"}:
                continue
            # Skip any path containing these directory names
            parts = file_path.relative_to(AGENT_DIR).parts
            if any(p in {"__pycache__", "venv", ".git"} for p in parts):
                continue
            arcname = file_path.relative_to(AGENT_DIR)
            tar.add(file_path, arcname=str(arcname))

    size = buffer.tell()
    buffer.seek(0)
    data = buffer.read()

    print(f"[DOWNLOAD] Serving agent archive — {size} bytes, {len(data)} read")

    return Response(
        content=data,
        media_type="application/gzip",
        headers={
            "Content-Disposition": "attachment; filename=firstlook-agent.tar.gz",
        },
    )

# =============================================================
# Helpers
# =============================================================

def _extract_bearer_token(authorization: str | None) -> str:
    """
    Extract the plain-text token from an Authorization header.

    Args:
        authorization: Raw Authorization header value.

    Returns:
        Plain-text token string.

    Raises:
        HTTPException: If the header is missing or malformed.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header is required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header must be: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return parts[1].strip()


def _find_agent_by_token(db: Session, plain_token: str) -> Agent | None:
    """
    Find an agent whose stored token hash matches the given plain token.

    We query all pending and active agents for this server and check
    each hash — there will never be enough agents for this to be slow.
    Token hashing is SHA-256 so comparison is fast.

    Args:
        db:             Database session.
        plain_token:    Plain-text token from the Authorization header.

    Returns:
        Matching Agent instance, or None if no match found.
    """
    candidates = db.query(Agent).filter(
        Agent.status.in_([AgentStatus.pending, AgentStatus.active])
    ).all()

    for agent in candidates:
        if verify_token(plain_token, agent.api_token_hash):
            return agent

    return None


def _build_archive(agent_dir: Path) -> io.BytesIO:
    """
    Build an in-memory tar.gz archive of the agent directory.

    Excludes:
        - __pycache__ directories
        - .pyc files
        - .env files
        - Any existing venv or .git directories

    Args:
        agent_dir: Path to the agent source directory.

    Returns:
        BytesIO buffer containing the tar.gz archive.
    """
    EXCLUDE_DIRS  = {"__pycache__", "venv", ".git", ".mypy_cache", ".pytest_cache"}
    EXCLUDE_EXTS  = {".pyc", ".pyo", ".env"}
    EXCLUDE_FILES = {".gitignore", ".DS_Store"}

    def _should_exclude(path: Path) -> bool:
        if path.name in EXCLUDE_DIRS and path.is_dir():
            return True
        if path.name in EXCLUDE_FILES:
            return True
        if path.suffix in EXCLUDE_EXTS:
            return True
        # Exclude any parent named in EXCLUDE_DIRS
        for part in path.parts:
            if part in EXCLUDE_DIRS:
                return True
        return False

    buffer = io.BytesIO()

    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for file_path in sorted(agent_dir.rglob("*")):
            if _should_exclude(file_path):
                continue
            if not file_path.is_file():
                continue

            # Archive name is relative to agent_dir
            # e.g. agent/core/config.py → core/config.py
            arcname = file_path.relative_to(agent_dir)
            tar.add(file_path, arcname=arcname)

    size = buffer.tel()
    buffer.seek(0)
    return buffer, size
