from typing import Protocol

from auth_service.domain.models import RefreshToken
from auth_service.domain.value_objects.user import UserId


class TokenRepository(Protocol):
    """Port for refresh token operations."""

    async def add(self, token: RefreshToken) -> None:
        """Save refresh token."""
        ...

    async def get_by_hash(self, token_hash: str) -> RefreshToken | None:
        """Get token by hash."""
        ...

    async def get_active_by_user_id(
        self, user_id: UserId
    ) -> list[RefreshToken]:
        """Get all active tokens for a user."""
        ...

    async def revoke(self, token: RefreshToken) -> None:
        """Revoke token."""
        ...

    async def revoke_all_by_user_id(self, user_id: UserId) -> None:
        """Revoke all user tokens (logout everywhere)."""
        ...

    async def delete_expired(self) -> int:
        """Delete expired tokens. Returns the number of deleted tokens."""
        ...
