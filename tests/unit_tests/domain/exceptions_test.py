"""Unit тесты для Domain Exceptions."""

import pytest

from auth_service.domain.exceptions import (
    DomainError,
    UserLoginError,
    UserPasswordError,
    UserNotFoundError,
    UserAlreadyExistsError,
    UserInactiveError,
    TokenError,
    InvalidTokenError,
    TokenExpiredError,
    TokenRevokedError,
    InvalidTokenTypeError,
)


class TestDomainError:
    """Тесты для базового DomainError."""

    def test_is_exception(self) -> None:
        """DomainError является исключением."""
        error = DomainError()
        assert isinstance(error, Exception)

    def test_can_be_raised_and_caught(self) -> None:
        """DomainError можно выбросить и поймать."""
        with pytest.raises(DomainError):
            raise DomainError()


class TestUserLoginError:
    """Тесты для UserLoginError."""

    def test_inherits_from_domain_error(self) -> None:
        """UserLoginError наследует DomainError."""
        error = UserLoginError(login="test", msg="test message")
        assert isinstance(error, DomainError)

    def test_stores_login_and_message(self) -> None:
        """UserLoginError сохраняет логин и сообщение."""
        error = UserLoginError(login="testuser", msg="invalid login")
        
        assert error.login == "testuser"
        assert error.msg == "invalid login"

    def test_string_representation(self) -> None:
        """Строковое представление содержит информацию."""
        error = UserLoginError(login="testuser", msg="login is too short")
        
        assert "login is too short" in str(error)
        assert "testuser" in str(error)


class TestUserPasswordError:
    """Тесты для UserPasswordError."""

    def test_inherits_from_domain_error(self) -> None:
        """UserPasswordError наследует DomainError."""
        error = UserPasswordError(password="***", msg="test")
        assert isinstance(error, DomainError)

    def test_stores_message(self) -> None:
        """UserPasswordError сохраняет сообщение."""
        error = UserPasswordError(password="***", msg="password too weak")
        
        assert error.msg == "password too weak"


class TestUserNotFoundError:
    """Тесты для UserNotFoundError."""

    def test_inherits_from_domain_error(self) -> None:
        """UserNotFoundError наследует DomainError."""
        error = UserNotFoundError(identifier="user123")
        assert isinstance(error, DomainError)

    def test_stores_identifier(self) -> None:
        """UserNotFoundError сохраняет идентификатор."""
        error = UserNotFoundError(identifier="user123")
        
        assert error.identifier == "user123"
        assert "user123" in str(error)


class TestUserAlreadyExistsError:
    """Тесты для UserAlreadyExistsError."""

    def test_inherits_from_domain_error(self) -> None:
        """UserAlreadyExistsError наследует DomainError."""
        error = UserAlreadyExistsError(login="testuser")
        assert isinstance(error, DomainError)

    def test_stores_login(self) -> None:
        """UserAlreadyExistsError сохраняет логин."""
        error = UserAlreadyExistsError(login="testuser")
        
        assert error.login == "testuser"
        assert "testuser" in str(error)


class TestUserInactiveError:
    """Тесты для UserInactiveError."""

    def test_inherits_from_domain_error(self) -> None:
        """UserInactiveError наследует DomainError."""
        error = UserInactiveError(user_id="123")
        assert isinstance(error, DomainError)

    def test_stores_user_id(self) -> None:
        """UserInactiveError сохраняет user_id."""
        error = UserInactiveError(user_id="user-uuid-123")
        
        assert error.user_id == "user-uuid-123"


class TestTokenError:
    """Тесты для TokenError."""

    def test_inherits_from_domain_error(self) -> None:
        """TokenError наследует DomainError."""
        error = TokenError()
        assert isinstance(error, DomainError)


class TestInvalidTokenError:
    """Тесты для InvalidTokenError."""

    def test_inherits_from_token_error(self) -> None:
        """InvalidTokenError наследует TokenError."""
        error = InvalidTokenError()
        assert isinstance(error, TokenError)

    def test_default_reason(self) -> None:
        """InvalidTokenError имеет сообщение по умолчанию."""
        error = InvalidTokenError()
        
        assert "Invalid token" in str(error)

    def test_custom_reason(self) -> None:
        """InvalidTokenError принимает кастомное сообщение."""
        error = InvalidTokenError(reason="Signature verification failed")
        
        assert error.reason == "Signature verification failed"
        assert "Signature verification failed" in str(error)


class TestTokenExpiredError:
    """Тесты для TokenExpiredError."""

    def test_inherits_from_token_error(self) -> None:
        """TokenExpiredError наследует TokenError."""
        error = TokenExpiredError()
        assert isinstance(error, TokenError)

    def test_message(self) -> None:
        """TokenExpiredError имеет корректное сообщение."""
        error = TokenExpiredError()
        
        assert "expired" in str(error).lower()


class TestTokenRevokedError:
    """Тесты для TokenRevokedError."""

    def test_inherits_from_token_error(self) -> None:
        """TokenRevokedError наследует TokenError."""
        error = TokenRevokedError()
        assert isinstance(error, TokenError)

    def test_message(self) -> None:
        """TokenRevokedError имеет корректное сообщение."""
        error = TokenRevokedError()
        
        assert "revoked" in str(error).lower()


class TestInvalidTokenTypeError:
    """Тесты для InvalidTokenTypeError."""

    def test_inherits_from_token_error(self) -> None:
        """InvalidTokenTypeError наследует TokenError."""
        error = InvalidTokenTypeError(expected="access", actual="refresh")
        assert isinstance(error, TokenError)

    def test_stores_expected_and_actual(self) -> None:
        """InvalidTokenTypeError сохраняет expected и actual."""
        error = InvalidTokenTypeError(expected="access", actual="refresh")
        
        assert error.expected == "access"
        assert error.actual == "refresh"

    def test_message(self) -> None:
        """InvalidTokenTypeError содержит expected и actual в сообщении."""
        error = InvalidTokenTypeError(expected="access", actual="refresh")
        
        assert "access" in str(error)
        assert "refresh" in str(error)
