"""Alembic async environment. Schema source of truth for Postgres (and SQLite)."""
import asyncio
import os
import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

# make `app` importable when running `alembic` from backend/
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db import Base  # noqa: E402
from app import models_db  # noqa: E402,F401  (register mappers)

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# URL precedence: CT_DATABASE_URL env -> alembic.ini -> local sqlite default
_url = os.environ.get("CT_DATABASE_URL") or config.get_main_option("sqlalchemy.url")
if not _url or _url.startswith("driver://"):
    _url = "sqlite+aiosqlite:///./data/capture_tool.db"
config.set_main_option("sqlalchemy.url", _url)

target_metadata = Base.metadata


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata,
                      render_as_batch=connection.dialect.name == "sqlite")
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    engine = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.", poolclass=pool.NullPool)
    async with engine.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await engine.dispose()


def run_migrations_offline() -> None:
    context.configure(url=_url, target_metadata=target_metadata, literal_binds=True,
                      dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_async_migrations())
