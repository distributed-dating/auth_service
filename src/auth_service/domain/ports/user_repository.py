from typing import Protocol

from auth_service.domain.models import User
from auth_service.domain.value_objects.user import UserId, UserLogin


class UserRepository(Protocol):
    """Port for user operations."""

    async def add(self, user: User) -> None:
        """Add a new user."""
        ...

    async def get_by_id(self, user_id: UserId) -> User | None:
        """Get user by ID."""
        ...

    async def get_by_login(self, login: UserLogin) -> User | None:
        """Get user by login."""
        ...

    async def update(self, user: User) -> None:
        """Update user data."""
        ...

    async def exists_by_login(self, login: UserLogin) -> bool:
        """Check if user exists by login."""
        ...
