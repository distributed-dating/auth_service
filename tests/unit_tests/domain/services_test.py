from datetime import datetime, timezone, timedelta
from uuid import uuid4

import pytest

from auth_service.domain.services.token_service import TokenService
from auth_service.domain.models import RefreshToken
from auth_service.domain.value_objects.user import UserId
from auth_service.domain.value_objects.jwt import (
    TokenType,
    TokenPair,
    TokenPayload,
    AccessToken,
    RefreshTokenValue,
)
from auth_service.domain.exceptions import (
    TokenRevokedError,
    InvalidTokenTypeError,
)


class FakeJwtProvider:
    """Fake implementation JwtProvider for tests."""

    def __init__(self) -> None:
        self.created_pairs: list[tuple[UserId, TokenPair]] = []

    def create_token_pair(self, user_id: UserId) -> TokenPair:
        """Creates fake token pair."""
        access = AccessToken(
            value=f"access_{user_id.value}_{uuid4().hex[:8]}",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        refresh = RefreshTokenValue(
            value=f"refresh_{user_id.value}_{uuid4().hex[:8]}",
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )
        pair = TokenPair(access_token=access, refresh_token=refresh)
        self.created_pairs.append((user_id, pair))
        return pair

    def decode_access_token(self, token: str) -> TokenPayload:
        """Decodes fake access token."""
        if token.startswith("access_"):
            parts = token.split("_")
            user_id = uuid4()  # In reality extracted from token
            return TokenPayload(
                sub=user_id,
                token_type=TokenType.ACCESS,
                exp=datetime.now(timezone.utc) + timedelta(hours=1),
                iat=datetime.now(timezone.utc),
            )
        if token.startswith("refresh_"):
            return TokenPayload(
                sub=uuid4(),
                token_type=TokenType.REFRESH,
                exp=datetime.now(timezone.utc) + timedelta(days=7),
                iat=datetime.now(timezone.utc),
            )
        raise ValueError("Invalid token format")

    def decode_refresh_token(self, token: str) -> TokenPayload:
        """Decodes fake refresh token."""
        if token.startswith("refresh_"):
            user_id = uuid4()
            return TokenPayload(
                sub=user_id,
                token_type=TokenType.REFRESH,
                exp=datetime.now(timezone.utc) + timedelta(days=7),
                iat=datetime.now(timezone.utc),
                jti=f"jti_{uuid4().hex[:8]}",
            )
        if token.startswith("access_"):
            return TokenPayload(
                sub=uuid4(),
                token_type=TokenType.ACCESS,
                exp=datetime.now(timezone.utc) + timedelta(hours=1),
                iat=datetime.now(timezone.utc),
            )
        raise ValueError("Invalid token format")

    def hash_token(self, token: str) -> str:
        """Returns token hash."""
        return f"hashed_{token}"


class FakeTokenRepository:
    """Fake implementation TokenRepository for tests."""

    def __init__(self) -> None:
        self.tokens: dict[str, RefreshToken] = {}
        self.revoked_all_calls: list[UserId] = []

    async def add(self, token: RefreshToken) -> None:
        """Saves token."""
        self.tokens[token.token_hash] = token

    async def get_by_hash(self, token_hash: str) -> RefreshToken | None:
        """Gets token by hash."""
        return self.tokens.get(token_hash)

    async def get_active_by_user_id(
        self, user_id: UserId
    ) -> list[RefreshToken]:
        """Gets active user tokens."""
        return [
            t
            for t in self.tokens.values()
            if t.user_id == user_id and t.is_valid
        ]

    async def revoke(self, token: RefreshToken) -> None:
        """Revokes token."""
        if token.token_hash in self.tokens:
            self.tokens[token.token_hash] = token

    async def revoke_all_by_user_id(self, user_id: UserId) -> None:
        """Revokes all user tokens."""
        self.revoked_all_calls.append(user_id)
        for token in self.tokens.values():
            if token.user_id == user_id:
                token.revoke()

    async def delete_expired(self) -> int:
        """Deletes expired tokens."""
        expired = [h for h, t in self.tokens.items() if t.is_expired]
        for h in expired:
            del self.tokens[h]
        return len(expired)


class TestTokenService:
    """Tests for TokenService."""

    @pytest.fixture
    def jwt_provider(self) -> FakeJwtProvider:
        """Fixture for FakeJwtProvider."""
        return FakeJwtProvider()

    @pytest.fixture
    def token_repository(self) -> FakeTokenRepository:
        """Fixture for FakeTokenRepository."""
        return FakeTokenRepository()

    @pytest.fixture
    def token_service(
        self,
        jwt_provider: FakeJwtProvider,
        token_repository: FakeTokenRepository,
    ) -> TokenService:
        """Fixture for TokenService."""
        return TokenService(
            jwt_provider=jwt_provider,
            token_repository=token_repository,
        )

    @pytest.fixture
    def user_id(self) -> UserId:
        """Fixture for UserId."""
        return UserId(value=uuid4())

    @pytest.mark.asyncio
    async def test_issue_tokens_creates_token_pair(
        self,
        token_service: TokenService,
        jwt_provider: FakeJwtProvider,
        user_id: UserId,
    ) -> None:
        """issue_tokens creates token pair."""
        token_pair = await token_service.issue_tokens(user_id)

        assert token_pair.access_token is not None
        assert token_pair.refresh_token is not None
        assert len(jwt_provider.created_pairs) == 1

    @pytest.mark.asyncio
    async def test_issue_tokens_saves_refresh_token(
        self,
        token_service: TokenService,
        token_repository: FakeTokenRepository,
        user_id: UserId,
    ) -> None:
        """issue_tokens saves refresh token in repository."""
        token_pair = await token_service.issue_tokens(user_id)

        expected_hash = f"hashed_{token_pair.refresh_token.value}"
        assert expected_hash in token_repository.tokens

    @pytest.mark.asyncio
    async def test_revoke_token_marks_as_revoked(
        self,
        token_service: TokenService,
        token_repository: FakeTokenRepository,
        user_id: UserId,
    ) -> None:
        """revoke_token revokes token."""
        token_pair = await token_service.issue_tokens(user_id)
        refresh_token = token_pair.refresh_token.value

        await token_service.revoke_token(refresh_token)

        expected_hash = f"hashed_{refresh_token}"
        stored = token_repository.tokens[expected_hash]
        assert stored.is_revoked is True

    @pytest.mark.asyncio
    async def test_revoke_all_user_tokens(
        self,
        token_service: TokenService,
        token_repository: FakeTokenRepository,
        user_id: UserId,
    ) -> None:
        """revoke_all_user_tokens revokes all user tokens."""
        await token_service.revoke_all_user_tokens(user_id)

        assert user_id in token_repository.revoked_all_calls

    @pytest.mark.asyncio
    async def test_validate_access_token_returns_payload(
        self,
        token_service: TokenService,
        jwt_provider: FakeJwtProvider,
    ) -> None:
        """validate_access_token returns payload for valid token."""
        access_token = "access_test_token"

        payload = token_service.validate_access_token(access_token)

        assert payload.is_access_token()

    @pytest.mark.asyncio
    async def test_validate_access_token_rejects_refresh_token(
        self,
        token_service: TokenService,
    ) -> None:
        """validate_access_token rejects refresh token."""
        refresh_token = "refresh_test_token"

        with pytest.raises(InvalidTokenTypeError) as exc_info:
            token_service.validate_access_token(refresh_token)

        assert exc_info.value.expected == "access"
        assert exc_info.value.actual == "refresh"


class TestTokenServiceRefreshTokens:
    """Tests for TokenService.refresh_tokens."""

    @pytest.fixture
    def user_id(self) -> UserId:
        """Fixture for UserId."""
        return UserId(value=uuid4())

    @pytest.mark.asyncio
    async def test_refresh_tokens_with_access_token_raises_error(self) -> None:
        """refresh_tokens with access token raises error."""
        jwt_provider = FakeJwtProvider()
        token_repository = FakeTokenRepository()
        token_service = TokenService(jwt_provider, token_repository)

        access_token = "access_test_token"

        with pytest.raises(InvalidTokenTypeError):
            await token_service.refresh_tokens(access_token)

    @pytest.mark.asyncio
    async def test_refresh_tokens_with_unknown_token_raises_revoked(
        self,
    ) -> None:
        """refresh_tokens with unknown token raises TokenRevokedError."""
        jwt_provider = FakeJwtProvider()
        token_repository = FakeTokenRepository()
        token_service = TokenService(jwt_provider, token_repository)

        unknown_token = "refresh_unknown_token"

        with pytest.raises(TokenRevokedError):
            await token_service.refresh_tokens(unknown_token)
