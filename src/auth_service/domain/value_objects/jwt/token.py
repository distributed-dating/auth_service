from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum


class TokenType(str, Enum):
    ACCESS = "access"
    REFRESH = "refresh"


@dataclass(frozen=True, slots=True)
class AccessToken:
    """Access JWT token for request authentication."""

    value: str
    expires_at: datetime

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class RefreshTokenValue:
    """Refresh JWT token for refreshing access token."""

    value: str
    expires_at: datetime

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at


@dataclass(frozen=True, slots=True)
class TokenPair:
    """Token pair issued during authentication."""

    access_token: AccessToken
    refresh_token: RefreshTokenValue
