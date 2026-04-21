from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from .config import get_settings

settings = get_settings()

# =============================================================
# Engine
# =============================================================

engine = create_engine(
    settings.database_url,
    # Pool settings suited to a lightweight self-hosted deployment.
    # Increase pool_size if you expect higher concurrency in future.
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,   # Verify connections are alive before using them.
                          # Prevents errors after the DB restarts or idles.
    pool_recycle=1800,    # Recycle connections after 30 minutes to avoid
                          # stale connection issues with PostgreSQL.
)

# =============================================================
# Session Factory
# =============================================================

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,   # We manage transactions explicitly.
    autoflush=False,    # We flush manually before commits.
    expire_on_commit=False,  # Keep objects accessible after commit
                             # without needing to re-query.
)

# =============================================================
# Dependency
# =============================================================

def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that yields a database session per request
    and ensures it is always closed when the request is done,
    even if an exception occurs.

    Usage in a route:
        from core.database import get_db
        from sqlalchemy.orm import Session
        from fastapi import Depends

        @router.get("/example")
        def example(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
