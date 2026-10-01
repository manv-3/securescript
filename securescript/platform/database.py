"""
SecureScript Platform — Async Database Engine & Session Factory.

Provides:
- Async SQLAlchemy engine (PostgreSQL via asyncpg, or SQLite via aiosqlite for local dev)
- AsyncSessionLocal: scoped session factory
- Base: declarative ORM base class
- get_db(): FastAPI dependency for per-request DB sessions
- init_db(): creates all tables (for development / testing without Alembic)
"""

from __future__ import annotations

import os
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

# ---------------------------------------------------------------------------
# Connection URL
# ---------------------------------------------------------------------------
_RAW_URL = os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///./securescript.db")

# Render.com and many providers give postgres:// — SQLAlchemy needs postgresql+asyncpg://
if _RAW_URL.startswith("postgres://"):
    _RAW_URL = _RAW_URL.replace("postgres://", "postgresql+asyncpg://", 1)
elif _RAW_URL.startswith("postgresql://") and "+asyncpg" not in _RAW_URL:
    _RAW_URL = _RAW_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

# Local dev safety: if asyncpg is not available (e.g. Python 3.14 pre-release),
# fall back to SQLite regardless of DATABASE_URL setting.
if "postgresql" in _RAW_URL or "postgres" in _RAW_URL:
    try:
        import asyncpg  # noqa: F401
    except ImportError:
        print(
            "[DB] asyncpg not available on this Python version — "
            "falling back to SQLite for local development. "
            "Use Python ≤3.13 or Docker for PostgreSQL support."
        )
        _RAW_URL = "sqlite+aiosqlite:///./securescript.db"

DATABASE_URL: str = _RAW_URL

# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
_connect_args: dict = {}
if DATABASE_URL.startswith("sqlite"):
    # aiosqlite requires check_same_thread=False
    _connect_args = {"check_same_thread": False}

engine: AsyncEngine = create_async_engine(
    DATABASE_URL,
    echo=False,           # set True for SQL debug output
    future=True,
    connect_args=_connect_args,
)

# ---------------------------------------------------------------------------
# Session Factory
# ---------------------------------------------------------------------------
AsyncSessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


# ---------------------------------------------------------------------------
# ORM Declarative Base
# ---------------------------------------------------------------------------
class Base(DeclarativeBase):
    """Shared declarative base for all SecureScript ORM models."""
    pass


# ---------------------------------------------------------------------------
# FastAPI Dependency
# ---------------------------------------------------------------------------
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Yields an async database session per request, ensuring it is closed after use.

    Usage::

        @router.get("/example")
        async def handler(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ---------------------------------------------------------------------------
# Development Helper — Create All Tables
# ---------------------------------------------------------------------------
async def init_db() -> None:
    """
    Creates all ORM-mapped tables in the database.

    Should only be used in development/testing. In production, use
    ``alembic upgrade head`` instead.
    """
    # Import models here to ensure they are registered on Base.metadata
    from securescript.platform import models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
