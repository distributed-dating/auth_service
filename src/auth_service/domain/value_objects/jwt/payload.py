from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

from auth_service.domain.value_objects.jwt.token import TokenType


@dataclass(frozen=True, slots=True)
class TokenPayload:
    """Payload JWT токена (claims)."""

    sub: UUID  # subject (user_id)
    token_type: TokenType  # access или refresh
    exp: datetime  # expiration time
    iat: datetime  # issued at
    jti: str | None = None  # JWT ID (для refresh токенов, чтобы отзывать)

    @property
    def user_id(self) -> UUID:
        return self.sub

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.exp

    def is_access_token(self) -> bool:
        return self.token_type == TokenType.ACCESS

    def is_refresh_token(self) -> bool:
        return self.token_type == TokenType.REFRESH
