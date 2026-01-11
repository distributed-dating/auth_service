"""Tests for application DTOs."""

from datetime import datetime, timezone, timedelta
from uuid import uuid4

import pytest

from auth_service.application.dto import UserDTO, TokenPairDTO
from auth_service.domain import User, UserLogin, HashedPassword, AccessToken, RefreshTokenValue, TokenPair


class TestUserDTO:
    """Tests for UserDTO."""

    @pytest.fixture
    def user(self) -> User:
        """Create a test user."""
        return User.create(
            login=UserLogin("testuser"),
            hashed_password=HashedPassword(
                "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4baN7f3v1f1h1Q1."
            ),
        )

    def test_from_domain(self, user: User) -> None:
        """Should create DTO from domain model."""
        dto = UserDTO.from_domain(user)

        assert dto.id == user.id.value
        assert dto.login == user.login.value
        assert dto.is_active == user.is_active
        assert dto.created_at == user.created_at

    def test_is_frozen(self, user: User) -> None:
        """DTO should be immutable."""
        dto = UserDTO.from_domain(user)

        with pytest.raises(AttributeError):
            dto.login = "newlogin"  # type: ignore


class TestTokenPairDTO:
    """Tests for TokenPairDTO."""

    @pytest.fixture
    def token_pair(self) -> TokenPair:
        """Create a test token pair."""
        now = datetime.now(timezone.utc)
        return TokenPair(
            access_token=AccessToken(
                value="access.token.value",
                expires_at=now + timedelta(minutes=15),
            ),
            refresh_token=RefreshTokenValue(
                value="refresh.token.value",
                expires_at=now + timedelta(days=7),
            ),
        )

    def test_from_domain(self, token_pair: TokenPair) -> None:
        """Should create DTO from domain value object."""
        dto = TokenPairDTO.from_domain(token_pair)

        assert dto.access_token == token_pair.access_token.value
        assert dto.refresh_token == token_pair.refresh_token.value
        assert dto.access_token_expires_at == token_pair.access_token.expires_at
        assert dto.refresh_token_expires_at == token_pair.refresh_token.expires_at

    def test_is_frozen(self, token_pair: TokenPair) -> None:
        """DTO should be immutable."""
        dto = TokenPairDTO.from_domain(token_pair)

        with pytest.raises(AttributeError):
            dto.access_token = "new.token"  # type: ignore
