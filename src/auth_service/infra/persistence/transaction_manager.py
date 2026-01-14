"""SQLAlchemy implementation of TransactionManager."""

from sqlalchemy.ext.asyncio import AsyncSession

from auth_service.domain.ports import TransactionManager


class SQLAlchemyTransactionManager(TransactionManager):
    """SQLAlchemy implementation of TransactionManager."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def commit(self) -> None:
        """Commit the current transaction."""
        await self._session.commit()

    async def rollback(self) -> None:
        """Rollback the current transaction."""
        await self._session.rollback()
