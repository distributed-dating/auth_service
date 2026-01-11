"""Unit тесты для Domain Models."""

from datetime import datetime, timezone, timedelta
from uuid import uuid4

import pytest

from auth_service.domain.models import User, RefreshToken
from auth_service.domain.value_objects.user import UserId, UserLogin, HashedPassword


class TestUser:
    """Тесты для User Aggregate Root."""

    @pytest.fixture
    def valid_login(self) -> UserLogin:
        """Фикстура для валидного логина."""
        return UserLogin(value="testuser")

    @pytest.fixture
    def valid_hashed_password(self) -> HashedPassword:
        """Фикстура для валидного хешированного пароля."""
        return HashedPassword(value="$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4baN7f3v1f1h1Q1.")

    def test_create_user(
        self, valid_login: UserLogin, valid_hashed_password: HashedPassword
    ) -> None:
        """Создание пользователя через фабричный метод."""
        user = User.create(login=valid_login, hashed_password=valid_hashed_password)

        assert user.login == valid_login
        assert user.hashed_password == valid_hashed_password
        assert user.is_active is True
        assert isinstance(user.id, UserId)
        assert isinstance(user.created_at, datetime)
        assert isinstance(user.updated_at, datetime)

    def test_create_user_generates_unique_ids(
        self, valid_login: UserLogin, valid_hashed_password: HashedPassword
    ) -> None:
        """Каждый новый пользователь получает уникальный ID."""
        user1 = User.create(login=valid_login, hashed_password=valid_hashed_password)
        user2 = User.create(login=valid_login, hashed_password=valid_hashed_password)

        assert user1.id != user2.id

    def test_create_user_sets_timestamps(
        self, valid_login: UserLogin, valid_hashed_password: HashedPassword
    ) -> None:
        """При создании пользователя устанавливаются временные метки."""
        before = datetime.now(timezone.utc)
        user = User.create(login=valid_login, hashed_password=valid_hashed_password)
        after = datetime.now(timezone.utc)

        assert before <= user.created_at <= after
        assert user.created_at == user.updated_at

    def test_change_password(
        self, valid_login: UserLogin, valid_hashed_password: HashedPassword
    ) -> None:
        """Смена пароля обновляет hashed_password и updated_at."""
        user = User.create(login=valid_login, hashed_password=valid_hashed_password)
        old_updated_at = user.updated_at

        new_password = HashedPassword(
            value="$2b$12$NewHashValue123456789012345678901234567890123456789012"
        )
        user.change_password(new_password)

        assert user.hashed_password == new_password
        assert user.updated_at >= old_updated_at

    def test_deactivate_user(
        self, valid_login: UserLogin, valid_hashed_password: HashedPassword
    ) -> None:
        """Деактивация пользователя."""
        user = User.create(login=valid_login, hashed_password=valid_hashed_password)
        assert user.is_active is True

        user.deactivate()

        assert user.is_active is False

    def test_activate_user(
        self, valid_login: UserLogin, valid_hashed_password: HashedPassword
    ) -> None:
        """Активация пользователя."""
        user = User.create(login=valid_login, hashed_password=valid_hashed_password)
        user.deactivate()
        assert user.is_active is False

        user.activate()

        assert user.is_active is True

    def test_deactivate_updates_timestamp(
        self, valid_login: UserLogin, valid_hashed_password: HashedPassword
    ) -> None:
        """Деактивация обновляет updated_at."""
        user = User.create(login=valid_login, hashed_password=valid_hashed_password)
        old_updated_at = user.updated_at

        user.deactivate()

        assert user.updated_at >= old_updated_at


class TestRefreshToken:
    """Тесты для RefreshToken Entity."""

    @pytest.fixture
    def user_id(self) -> UserId:
        """Фикстура для UserId."""
        return UserId(value=uuid4())

    @pytest.fixture
    def token_hash(self) -> str:
        """Фикстура для хеша токена."""
        return "hashed_refresh_token_value_12345"

    @pytest.fixture
    def future_expiry(self) -> datetime:
        """Фикстура для будущей даты истечения."""
        return datetime.now(timezone.utc) + timedelta(days=7)

    @pytest.fixture
    def past_expiry(self) -> datetime:
        """Фикстура для прошедшей даты истечения."""
        return datetime.now(timezone.utc) - timedelta(days=1)

    def test_create_refresh_token(
        self, user_id: UserId, token_hash: str, future_expiry: datetime
    ) -> None:
        """Создание refresh токена через фабричный метод."""
        token = RefreshToken.create(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=future_expiry,
        )

        assert token.user_id == user_id
        assert token.token_hash == token_hash
        assert token.expires_at == future_expiry
        assert token.revoked_at is None
        assert isinstance(token.created_at, datetime)

    def test_token_is_valid_when_not_expired_and_not_revoked(
        self, user_id: UserId, token_hash: str, future_expiry: datetime
    ) -> None:
        """Токен валиден, если не истёк и не отозван."""
        token = RefreshToken.create(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=future_expiry,
        )

        assert token.is_valid is True
        assert token.is_expired is False
        assert token.is_revoked is False

    def test_token_is_invalid_when_expired(
        self, user_id: UserId, token_hash: str, past_expiry: datetime
    ) -> None:
        """Истёкший токен невалиден."""
        token = RefreshToken.create(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=past_expiry,
        )

        assert token.is_valid is False
        assert token.is_expired is True

    def test_revoke_token(
        self, user_id: UserId, token_hash: str, future_expiry: datetime
    ) -> None:
        """Отзыв токена."""
        token = RefreshToken.create(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=future_expiry,
        )
        assert token.is_revoked is False

        token.revoke()

        assert token.is_revoked is True
        assert token.is_valid is False
        assert token.revoked_at is not None

    def test_revoke_already_revoked_token_is_idempotent(
        self, user_id: UserId, token_hash: str, future_expiry: datetime
    ) -> None:
        """Повторный отзыв токена не меняет revoked_at."""
        token = RefreshToken.create(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=future_expiry,
        )
        token.revoke()
        first_revoked_at = token.revoked_at

        token.revoke()

        assert token.revoked_at == first_revoked_at

    def test_create_generates_unique_ids(
        self, user_id: UserId, token_hash: str, future_expiry: datetime
    ) -> None:
        """Каждый новый токен получает уникальный ID."""
        token1 = RefreshToken.create(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=future_expiry,
        )
        token2 = RefreshToken.create(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=future_expiry,
        )

        assert token1.id != token2.id
