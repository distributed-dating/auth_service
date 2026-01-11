from dataclasses import dataclass
from datetime import datetime

from auth_service.domain.value_objects.jwt import TokenPair


@dataclass(frozen=True)
class TokenPairDTO:
    """DTO для пары токенов."""

    access_token: str
    refresh_token: str
    access_token_expires_at: datetime
    refresh_token_expires_at: datetime

    @classmethod
    def from_domain(cls, pair: TokenPair) -> "TokenPairDTO":
        return cls(
            access_token=pair.access_token.value,
            refresh_token=pair.refresh_token.value,
            access_token_expires_at=pair.access_token.expires_at,
            refresh_token_expires_at=pair.refresh_token.expires_at,
        )
