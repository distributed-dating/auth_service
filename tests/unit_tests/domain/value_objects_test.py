"""Unit тесты для Value Objects."""

from datetime import datetime, timezone, timedelta
from uuid import uuid4

import pytest

from auth_service.domain.value_objects.user import (
    UserId,
    UserLogin,
    UserPassword,
    HashedPassword,
)
from auth_service.domain.value_objects.jwt import (
    TokenType,
    AccessToken,
    RefreshTokenValue,
    TokenPair,
    TokenPayload,
)
from auth_service.domain.exceptions import UserLoginError, UserPasswordError


class TestUserId:
    """Тесты для UserId Value Object."""

    def test_create_valid_user_id(self) -> None:
        """Создание валидного UserId."""
        uid = uuid4()
        user_id = UserId(value=uid)

        assert user_id.value == uid

    def test_user_id_str(self) -> None:
        """__str__ возвращает строковое представление UUID."""
        uid = uuid4()
        user_id = UserId(value=uid)

        assert str(user_id) == str(uid)

    def test_user_id_hash(self) -> None:
        """UserId хешируемый."""
        uid = uuid4()
        user_id = UserId(value=uid)

        assert hash(user_id) == hash(uid)

    def test_user_id_equality(self) -> None:
        """Равенство UserId по значению."""
        uid = uuid4()
        user_id1 = UserId(value=uid)
        user_id2 = UserId(value=uid)

        assert user_id1 == user_id2

    def test_user_id_can_be_used_in_set(self) -> None:
        """UserId можно использовать в set."""
        uid = uuid4()
        user_id = UserId(value=uid)

        user_set = {user_id}
        assert user_id in user_set


class TestUserLogin:
    """Тесты для UserLogin Value Object."""

    def test_create_valid_login(self) -> None:
        """Создание валидного логина."""
        login = UserLogin(value="testuser")

        assert login.value == "testuser"

    def test_create_valid_login_min_length(self) -> None:
        """Создание логина минимальной длины."""
        login = UserLogin(value="abc")

        assert login.value == "abc"

    def test_create_valid_login_max_length(self) -> None:
        """Создание логина максимальной длины."""
        login = UserLogin(value="a" * 15)

        assert login.value == "a" * 15

    def test_create_valid_login_alphanumeric(self) -> None:
        """Создание логина с буквами и цифрами."""
        login = UserLogin(value="user123")

        assert login.value == "user123"

    def test_create_empty_login_raises_error(self) -> None:
        """Пустой логин вызывает ошибку."""
        with pytest.raises(UserLoginError) as exc_info:
            UserLogin(value="")

        assert "login must not be empty" in str(exc_info.value)

    def test_create_login_too_short_raises_error(self) -> None:
        """Логин короче 3 символов вызывает ошибку."""
        with pytest.raises(UserLoginError) as exc_info:
            UserLogin(value="ab")

        assert "login is too short" in str(exc_info.value)

    def test_create_login_too_long_raises_error(self) -> None:
        """Логин длиннее 15 символов вызывает ошибку."""
        with pytest.raises(UserLoginError) as exc_info:
            UserLogin(value="a" * 16)

        assert "login is too long" in str(exc_info.value)

    def test_create_login_with_special_chars_raises_error(self) -> None:
        """Логин со специальными символами вызывает ошибку."""
        with pytest.raises(UserLoginError) as exc_info:
            UserLogin(value="user@test")

        assert "login must be alphanumeric" in str(exc_info.value)

    def test_create_login_with_spaces_raises_error(self) -> None:
        """Логин с пробелами вызывает ошибку."""
        with pytest.raises(UserLoginError) as exc_info:
            UserLogin(value="user test")

        assert "login must be alphanumeric" in str(exc_info.value)

    def test_login_is_frozen(self) -> None:
        """UserLogin неизменяемый."""
        login = UserLogin(value="testuser")

        with pytest.raises(AttributeError):
            login.value = "newvalue"  # type: ignore


class TestUserPassword:
    """Тесты для UserPassword Value Object."""

    def test_create_valid_password(self) -> None:
        """Создание валидного пароля."""
        password = UserPassword(value="TestPass1")

        assert password.value == "TestPass1"

    def test_create_valid_password_min_length(self) -> None:
        """Создание пароля минимальной длины (8 символов)."""
        password = UserPassword(value="Abcdefg1")

        assert password.value == "Abcdefg1"

    def test_create_valid_password_max_length(self) -> None:
        """Создание пароля максимальной длины (128 символов)."""
        password = UserPassword(value="Aa1" + "a" * 125)

        assert len(password.value) == 128

    def test_create_empty_password_raises_error(self) -> None:
        """Пустой пароль вызывает ошибку."""
        with pytest.raises(UserPasswordError) as exc_info:
            UserPassword(value="")

        assert "password must not be empty" in str(exc_info.value)

    def test_create_password_too_short_raises_error(self) -> None:
        """Пароль короче 8 символов вызывает ошибку."""
        with pytest.raises(UserPasswordError) as exc_info:
            UserPassword(value="Abc123")

        assert "password is too short" in str(exc_info.value)

    def test_create_password_too_long_raises_error(self) -> None:
        """Пароль длиннее 128 символов вызывает ошибку."""
        with pytest.raises(UserPasswordError) as exc_info:
            UserPassword(value="Aa1" + "a" * 126)

        assert "password is too long" in str(exc_info.value)

    def test_create_password_without_uppercase_raises_error(self) -> None:
        """Пароль без заглавных букв вызывает ошибку."""
        with pytest.raises(UserPasswordError) as exc_info:
            UserPassword(value="testpass1")

        assert "uppercase" in str(exc_info.value)

    def test_create_password_without_lowercase_raises_error(self) -> None:
        """Пароль без строчных букв вызывает ошибку."""
        with pytest.raises(UserPasswordError) as exc_info:
            UserPassword(value="TESTPASS1")

        assert "lowercase" in str(exc_info.value)

    def test_create_password_without_digit_raises_error(self) -> None:
        """Пароль без цифр вызывает ошибку."""
        with pytest.raises(UserPasswordError) as exc_info:
            UserPassword(value="TestPassword")

        assert "digit" in str(exc_info.value)

    def test_password_is_frozen(self) -> None:
        """UserPassword неизменяемый."""
        password = UserPassword(value="TestPass1")

        with pytest.raises(AttributeError):
            password.value = "NewPass1"  # type: ignore


class TestHashedPassword:
    """Тесты для HashedPassword Value Object."""

    def test_create_valid_bcrypt_hash(self) -> None:
        """Создание валидного bcrypt хеша."""
        hash_value = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4baN7f3v1f1h1Q1."
        hashed = HashedPassword(value=hash_value)

        assert hashed.value == hash_value

    def test_create_valid_argon2_hash(self) -> None:
        """Создание валидного argon2 хеша."""
        hash_value = "$argon2id$v=19$m=65536,t=3,p=4$somesalt$somehash"
        hashed = HashedPassword(value=hash_value)

        assert hashed.value == hash_value

    def test_create_empty_hash_raises_error(self) -> None:
        """Пустой хеш вызывает ошибку."""
        with pytest.raises(ValueError) as exc_info:
            HashedPassword(value="")

        assert "empty" in str(exc_info.value).lower()

    def test_create_invalid_hash_format_raises_error(self) -> None:
        """Неверный формат хеша вызывает ошибку."""
        with pytest.raises(ValueError) as exc_info:
            HashedPassword(value="invalid_hash_format")

        assert "format" in str(exc_info.value).lower()


class TestAccessToken:
    """Тесты для AccessToken Value Object."""

    def test_create_valid_token(self) -> None:
        """Создание валидного access токена."""
        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        token = AccessToken(value="jwt.token.here", expires_at=expires)

        assert token.value == "jwt.token.here"
        assert token.expires_at == expires

    def test_token_str(self) -> None:
        """__str__ возвращает значение токена."""
        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        token = AccessToken(value="jwt.token.here", expires_at=expires)

        assert str(token) == "jwt.token.here"

    def test_token_not_expired(self) -> None:
        """Токен с будущей датой не истёк."""
        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        token = AccessToken(value="jwt.token.here", expires_at=expires)

        assert not token.is_expired()

    def test_token_is_expired(self) -> None:
        """Токен с прошедшей датой истёк."""
        expires = datetime.now(timezone.utc) - timedelta(hours=1)
        token = AccessToken(value="jwt.token.here", expires_at=expires)

        assert token.is_expired()


class TestRefreshTokenValue:
    """Тесты для RefreshTokenValue Value Object."""

    def test_create_valid_token(self) -> None:
        """Создание валидного refresh токена."""
        expires = datetime.now(timezone.utc) + timedelta(days=7)
        token = RefreshTokenValue(value="refresh.token.here", expires_at=expires)

        assert token.value == "refresh.token.here"
        assert token.expires_at == expires

    def test_token_not_expired(self) -> None:
        """Токен с будущей датой не истёк."""
        expires = datetime.now(timezone.utc) + timedelta(days=7)
        token = RefreshTokenValue(value="refresh.token.here", expires_at=expires)

        assert not token.is_expired()

    def test_token_is_expired(self) -> None:
        """Токен с прошедшей датой истёк."""
        expires = datetime.now(timezone.utc) - timedelta(days=1)
        token = RefreshTokenValue(value="refresh.token.here", expires_at=expires)

        assert token.is_expired()


class TestTokenPair:
    """Тесты для TokenPair Value Object."""

    def test_create_token_pair(self) -> None:
        """Создание пары токенов."""
        access_expires = datetime.now(timezone.utc) + timedelta(hours=1)
        refresh_expires = datetime.now(timezone.utc) + timedelta(days=7)

        access = AccessToken(value="access.token", expires_at=access_expires)
        refresh = RefreshTokenValue(value="refresh.token", expires_at=refresh_expires)

        pair = TokenPair(access_token=access, refresh_token=refresh)

        assert pair.access_token == access
        assert pair.refresh_token == refresh


class TestTokenPayload:
    """Тесты для TokenPayload Value Object."""

    def test_create_access_payload(self) -> None:
        """Создание payload для access токена."""
        user_id = uuid4()
        now = datetime.now(timezone.utc)
        exp = now + timedelta(hours=1)

        payload = TokenPayload(
            sub=user_id,
            token_type=TokenType.ACCESS,
            exp=exp,
            iat=now,
        )

        assert payload.sub == user_id
        assert payload.user_id == user_id
        assert payload.token_type == TokenType.ACCESS
        assert payload.is_access_token()
        assert not payload.is_refresh_token()

    def test_create_refresh_payload(self) -> None:
        """Создание payload для refresh токена."""
        user_id = uuid4()
        now = datetime.now(timezone.utc)
        exp = now + timedelta(days=7)

        payload = TokenPayload(
            sub=user_id,
            token_type=TokenType.REFRESH,
            exp=exp,
            iat=now,
            jti="unique-token-id",
        )

        assert payload.is_refresh_token()
        assert not payload.is_access_token()
        assert payload.jti == "unique-token-id"

    def test_payload_not_expired(self) -> None:
        """Payload с будущей датой не истёк."""
        payload = TokenPayload(
            sub=uuid4(),
            token_type=TokenType.ACCESS,
            exp=datetime.now(timezone.utc) + timedelta(hours=1),
            iat=datetime.now(timezone.utc),
        )

        assert not payload.is_expired()

    def test_payload_is_expired(self) -> None:
        """Payload с прошедшей датой истёк."""
        payload = TokenPayload(
            sub=uuid4(),
            token_type=TokenType.ACCESS,
            exp=datetime.now(timezone.utc) - timedelta(hours=1),
            iat=datetime.now(timezone.utc) - timedelta(hours=2),
        )

        assert payload.is_expired()
