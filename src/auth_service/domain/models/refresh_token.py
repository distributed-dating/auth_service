from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID, uuid4

from auth_service.domain.value_objects.user import UserId


@dataclass
class RefreshToken:
    """
    Refresh Token Entity.

    Хранится в БД для возможности отзыва токенов.
    """

    id: UUID
    user_id: UserId
    token_hash: str  # Хеш refresh токена (не сам токен!)
    expires_at: datetime
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    revoked_at: datetime | None = None

    @classmethod
    def create(
        cls,
        user_id: UserId,
        token_hash: str,
        expires_at: datetime,
    ) -> "RefreshToken":
        return cls(
            id=uuid4(),
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
        )

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def is_valid(self) -> bool:
        return not self.is_revoked and not self.is_expired

    def revoke(self) -> None:
        """Отозвать токен."""
        if self.revoked_at is None:
            self.revoked_at = datetime.now(timezone.utc)
