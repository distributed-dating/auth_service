from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4

from auth_service.domain.value_objects.user import UserId, UserLogin, HashedPassword


@dataclass
class User:
    """User Aggregate Root."""

    id: UserId
    login: UserLogin
    hashed_password: HashedPassword
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True

    @classmethod
    def create(
        cls,
        login: UserLogin,
        hashed_password: HashedPassword,
    ) -> "User":
        """Фабричный метод для создания нового пользователя."""
        now = datetime.now(timezone.utc)
        return cls(
            id=UserId(uuid4()),
            login=login,
            hashed_password=hashed_password,
            created_at=now,
            updated_at=now,
        )

    def change_password(self, new_hashed_password: HashedPassword) -> None:
        """Изменить пароль пользователя."""
        self.hashed_password = new_hashed_password
        self.updated_at = datetime.now(timezone.utc)

    def deactivate(self) -> None:
        """Деактивировать пользователя."""
        self.is_active = False
        self.updated_at = datetime.now(timezone.utc)

    def activate(self) -> None:
        """Активировать пользователя."""
        self.is_active = True
        self.updated_at = datetime.now(timezone.utc)
