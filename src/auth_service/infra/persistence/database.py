"""Database configuration and session management."""

from sqlalchemy.ext.asyncio.session import AsyncSession


from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from auth_service.infra.config import PostgresSettings


class Base(DeclarativeBase):
    """Base class for all ORM models."""

    pass


class Database:
    """Database connection manager."""

    def __init__(self, settings: PostgresSettings) -> None:
        self._settings = settings
        self._engine = create_async_engine(
            settings.database_url,
            echo=settings.debug,
            future=True,
        )
        self._session_factory = async_sessionmaker[AsyncSession](
            self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
            autocommit=False,
        )

    async def create_tables(self) -> None:
        """Create all tables."""
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def drop_tables(self) -> None:
        """Drop all tables."""
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

    def get_session(self) -> AsyncSession:
        """Get database session."""
        return self._session_factory()

    async def close(self) -> None:
        """Close database connection."""
        await self._engine.dispose()
