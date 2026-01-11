from typing import Protocol

from auth_service.domain.value_objects.user import UserId
from auth_service.domain.value_objects.jwt import TokenPair, TokenPayload


class JwtProvider(Protocol):
    """Порт для работы с JWT токенами."""

    def create_token_pair(self, user_id: UserId) -> TokenPair:
        """Создать пару access + refresh токенов."""
        ...

    def decode_access_token(self, token: str) -> TokenPayload:
        """
        Декодировать и валидировать access токен.

        Raises:
            InvalidTokenError: Если токен невалиден
            TokenExpiredError: Если токен истёк
        """
        ...

    def decode_refresh_token(self, token: str) -> TokenPayload:
        """
        Декодировать и валидировать refresh токен.

        Raises:
            InvalidTokenError: Если токен невалиден
            TokenExpiredError: Если токен истёк
        """
        ...

    def hash_token(self, token: str) -> str:
        """Получить хеш токена для хранения в БД."""
        ...
