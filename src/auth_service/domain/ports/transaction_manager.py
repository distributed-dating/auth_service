from typing import Protocol


class TransactionManager(Protocol):
    """Port for managing database transactions."""

    async def commit(self) -> None:
        """Commit the current transaction."""
        ...

    async def rollback(self) -> None:
        """Rollback the current transaction."""
        ...
