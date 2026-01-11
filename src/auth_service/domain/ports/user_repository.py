from typing import Protocol

from auth_service.domain.models import User
from auth_service.domain.value_objects.user import UserId, UserLogin


class UserRepository(Protocol):
    """Порт для работы с пользователями."""

    async def add(self, user: User) -> None:
        """Добавить нового пользователя."""
        ...

    async def get_by_id(self, user_id: UserId) -> User | None:
        """Получить пользователя по ID."""
        ...

    async def get_by_login(self, login: UserLogin) -> User | None:
        """Получить пользователя по логину."""
        ...

    async def update(self, user: User) -> None:
        """Обновить данные пользователя."""
        ...

    async def exists_by_login(self, login: UserLogin) -> bool:
        """Проверить существование пользователя по логину."""
        ...
