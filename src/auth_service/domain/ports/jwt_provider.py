from typing import Protocol

from auth_service.domain.value_objects.user import UserId
from auth_service.domain.value_objects.token_vo import TokenPair, TokenPayload


class JwtProvider(Protocol):
    """Port for JWT token operations."""

    def create_token_pair(self, user_id: UserId) -> TokenPair:
        """Create a pair of access + refresh tokens."""
        ...

    def decode_access_token(self, token: str) -> TokenPayload:
        """
        Decode and validate access token.

        Raises:
            InvalidTokenError: If token is invalid
            TokenExpiredError: If token has expired
        """
        ...

    def decode_refresh_token(self, token: str) -> TokenPayload:
        """
        Decode and validate refresh token.

        Raises:
            InvalidTokenError: If token is invalid
            TokenExpiredError: If token has expired
        """
        ...

    def hash_token(self, token: str) -> str:
        """Get token hash for database storage."""
        ...
