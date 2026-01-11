from typing import Protocol

from auth_service.domain.value_objects.user import UserPassword, HashedPassword


class PasswordHasher(Protocol):
    """Порт для хеширования паролей."""

    def hash(self, password: UserPassword) -> HashedPassword:
        """Захешировать пароль."""
        ...

    def verify(self, password: UserPassword, hashed: HashedPassword) -> bool:
        """Проверить пароль против хеша."""
        ...
