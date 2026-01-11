import jwt
from datetime import datetime, timedelta, timezone
from uuid import UUID

from auth_service.domain.user import User


class JWTService:
    def __init__(self, secret_key: str, algorithm: str = "HS256"):
        self._secret_key = secret_key
        self._algorithm = algorithm

    def create_access_token(
        self, user: User, expires_delta: timedelta | None = None
    ) -> str:
        """Создаёт JWT access token для пользователя."""
        if expires_delta is None:
            expires_delta = timedelta(minutes=15)

        now = datetime.now(timezone.utc)
        expire = now + expires_delta
        claims = user.get_jwt_claims()
        claims.update({"exp": expire, "iat": now})

        return jwt.encode(claims, self._secret_key, algorithm=self._algorithm)

    def create_refresh_token(
        self, user: User, expires_delta: timedelta | None = None
    ) -> str:
        """Создаёт JWT refresh token для пользователя."""
        if expires_delta is None:
            expires_delta = timedelta(days=30)

        now = datetime.now(timezone.utc)
        expire = now + expires_delta
        claims = {"sub": str(user._id), "type": "refresh"}
        claims.update({"exp": expire, "iat": now})

        return jwt.encode(claims, self._secret_key, algorithm=self._algorithm)

    def verify_token(self, token: str) -> dict:
        """Проверяет и декодирует JWT токен."""
        try:
            payload = jwt.decode(
                token, self._secret_key, algorithms=[self._algorithm]
            )
            return payload

        except jwt.ExpiredSignatureError:
            raise ValueError("Token expired")

        except jwt.InvalidTokenError:
            raise ValueError("Invalid token")

    def get_user_id_from_token(self, token: str) -> UUID:
        """Извлекает ID пользователя из токена."""
        payload = self.verify_token(token)

        return UUID(payload["sub"])
