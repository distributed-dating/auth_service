"""PyJWT implementation of JwtProvider."""

import hashlib
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import jwt

from auth_service.domain.exceptions import InvalidTokenError, TokenExpiredError
from auth_service.domain.ports import JwtProvider
from auth_service.domain.value_objects.token_vo import (
    AccessToken,
    RefreshTokenValue,
    TokenPair,
    TokenPayload,
    TokenType,
)
from auth_service.domain.value_objects.user import UserId


class PyJwtProvider(JwtProvider):
    """PyJWT implementation of JwtProvider."""

    def __init__(
        self,
        secret_key: str,
        access_token_ttl_minutes: int = 15,
        refresh_token_ttl_days: int = 7,
        algorithm: str = "HS256",
    ) -> None:
        self._secret_key = secret_key
        self._access_token_ttl = timedelta(minutes=access_token_ttl_minutes)
        self._refresh_token_ttl = timedelta(days=refresh_token_ttl_days)
        self._algorithm = algorithm

    def create_token_pair(self, user_id: UserId) -> TokenPair:
        """Create a pair of access + refresh tokens."""
        now = datetime.now(timezone.utc)

        # Access token
        access_payload = {
            "sub": str(user_id.value),
            "token_type": TokenType.ACCESS.value,
            "exp": now + self._access_token_ttl,
            "iat": now,
        }
        access_token_str = jwt.encode(
            access_payload,
            self._secret_key,
            algorithm=self._algorithm,
        )

        # Refresh token (with jti for tracking)
        jti = str(uuid4())
        refresh_payload = {
            "sub": str(user_id.value),
            "token_type": TokenType.REFRESH.value,
            "exp": now + self._refresh_token_ttl,
            "iat": now,
            "jti": jti,
        }
        refresh_token_str = jwt.encode(
            refresh_payload,
            self._secret_key,
            algorithm=self._algorithm,
        )

        return TokenPair(
            access_token=AccessToken(
                value=access_token_str,
                expires_at=now + self._access_token_ttl,
            ),
            refresh_token=RefreshTokenValue(
                value=refresh_token_str,
                expires_at=now + self._refresh_token_ttl,
            ),
        )

    def _decode_token(self, token: str) -> TokenPayload:
        """Decode and validate a JWT token."""
        try:
            payload = jwt.decode(
                token,
                self._secret_key,
                algorithms=[self._algorithm],
            )

            return TokenPayload(
                sub=UUID(payload["sub"]),
                token_type=TokenType(payload["token_type"]),
                exp=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
                iat=datetime.fromtimestamp(payload["iat"], tz=timezone.utc),
                jti=payload.get("jti"),
            )
        except jwt.ExpiredSignatureError:
            raise TokenExpiredError()
        except jwt.InvalidTokenError as e:
            raise InvalidTokenError(reason=str(e))

    def decode_access_token(self, token: str) -> TokenPayload:
        """Decode and validate access token."""
        return self._decode_token(token)

    def decode_refresh_token(self, token: str) -> TokenPayload:
        """Decode and validate refresh token."""
        return self._decode_token(token)

    def hash_token(self, token: str) -> str:
        """Hash token for database storage using SHA-256."""
        return hashlib.sha256(token.encode("utf-8")).hexdigest()
