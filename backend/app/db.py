"""Async persistence layer. SQLite for the single-host slice; the SQLAlchemy 2.x
models port to Postgres by swapping the URL (CT_DATABASE_URL) — no ORM changes."""
from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy import MetaData
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

# Deterministic constraint names so Alembic batch migrations (SQLite) work cleanly.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class Database:
    def __init__(self, url: str):
        connect_args = {"timeout": 30} if url.startswith("sqlite") else {}
        self.engine = create_async_engine(url, future=True, connect_args=connect_args)
        self.sessionmaker = async_sessionmaker(self.engine, expire_on_commit=False,
                                               class_=AsyncSession)

    async def create_all(self) -> None:
        # No Alembic yet (SQLite slice); create tables idempotently.
        from . import models_db  # noqa: F401 — register mappers
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def dispose(self) -> None:
        await self.engine.dispose()

    async def session(self) -> AsyncIterator[AsyncSession]:
        async with self.sessionmaker() as s:
            yield s
