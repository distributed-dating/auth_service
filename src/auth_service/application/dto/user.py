from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from auth_service.domain.models import User


@dataclass(frozen=True)
class UserDTO:
    """DTO для передачи данных пользователя."""

    id: UUID
    login: str
    is_active: bool
    created_at: datetime

    @classmethod
    def from_domain(cls, user: User) -> "UserDTO":
        return cls(
            id=user.id.value,
            login=user.login.value,
            is_active=user.is_active,
            created_at=user.created_at,
        )
