from typing import Protocol

from auth_service.domain.models import RefreshToken
from auth_service.domain.value_objects.user import UserId


class TokenRepository(Protocol):
    """Порт для работы с refresh токенами."""

    async def add(self, token: RefreshToken) -> None:
        """Сохранить refresh токен."""
        ...

    async def get_by_hash(self, token_hash: str) -> RefreshToken | None:
        """Получить токен по хешу."""
        ...

    async def get_active_by_user_id(self, user_id: UserId) -> list[RefreshToken]:
        """Получить все активные токены пользователя."""
        ...

    async def revoke(self, token: RefreshToken) -> None:
        """Отозвать токен."""
        ...

    async def revoke_all_by_user_id(self, user_id: UserId) -> None:
        """Отозвать все токены пользователя (logout everywhere)."""
        ...

    async def delete_expired(self) -> int:
        """Удалить истекшие токены. Возвращает количество удалённых."""
        ...
