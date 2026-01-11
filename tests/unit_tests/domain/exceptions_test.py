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
    """Tests for base DomainError."""

    def test_is_exception(self) -> None:
        """DomainError is an exception."""
        error = DomainError()
        assert isinstance(error, Exception)

    def test_can_be_raised_and_caught(self) -> None:
        """DomainError can be raised and caught."""
        with pytest.raises(DomainError):
            raise DomainError()


class TestUserLoginError:
    """Tests for UserLoginError."""

    def test_inherits_from_domain_error(self) -> None:
        """UserLoginError inherits from DomainError."""
        error = UserLoginError(login="test", msg="test message")
        assert isinstance(error, DomainError)

    def test_stores_login_and_message(self) -> None:
        """UserLoginError stores login and message."""
        error = UserLoginError(login="testuser", msg="invalid login")

        assert error.login == "testuser"
        assert error.msg == "invalid login"

    def test_string_representation(self) -> None:
        """String representation contains information."""
        error = UserLoginError(login="testuser", msg="login is too short")

        assert "login is too short" in str(error)
        assert "testuser" in str(error)


class TestUserPasswordError:
    """Tests for UserPasswordError."""

    def test_inherits_from_domain_error(self) -> None:
        """UserPasswordError inherits from DomainError."""
        error = UserPasswordError(password="***", msg="test")
        assert isinstance(error, DomainError)

    def test_stores_message(self) -> None:
        """UserPasswordError stores message."""
        error = UserPasswordError(password="***", msg="password too weak")

        assert error.msg == "password too weak"


class TestUserNotFoundError:
    """Tests for UserNotFoundError."""

    def test_inherits_from_domain_error(self) -> None:
        """UserNotFoundError inherits from DomainError."""
        error = UserNotFoundError(identifier="user123")
        assert isinstance(error, DomainError)

    def test_stores_identifier(self) -> None:
        """UserNotFoundError stores identifier."""
        error = UserNotFoundError(identifier="user123")

        assert error.identifier == "user123"
        assert "user123" in str(error)


class TestUserAlreadyExistsError:
    """Tests for UserAlreadyExistsError."""

    def test_inherits_from_domain_error(self) -> None:
        """UserAlreadyExistsError inherits from DomainError."""
        error = UserAlreadyExistsError(login="testuser")
        assert isinstance(error, DomainError)

    def test_stores_login(self) -> None:
        """UserAlreadyExistsError stores login."""
        error = UserAlreadyExistsError(login="testuser")

        assert error.login == "testuser"
        assert "testuser" in str(error)


class TestUserInactiveError:
    """Tests for UserInactiveError."""

    def test_inherits_from_domain_error(self) -> None:
        """UserInactiveError inherits from DomainError."""
        error = UserInactiveError(user_id="123")
        assert isinstance(error, DomainError)

    def test_stores_user_id(self) -> None:
        """UserInactiveError stores user_id."""
        error = UserInactiveError(user_id="user-uuid-123")

        assert error.user_id == "user-uuid-123"


class TestTokenError:
    """Tests for TokenError."""

    def test_inherits_from_domain_error(self) -> None:
        """TokenError inherits from DomainError."""
        error = TokenError()
        assert isinstance(error, DomainError)


class TestInvalidTokenError:
    """Tests for InvalidTokenError."""

    def test_inherits_from_token_error(self) -> None:
        """InvalidTokenError inherits from TokenError."""
        error = InvalidTokenError()
        assert isinstance(error, TokenError)

    def test_default_reason(self) -> None:
        """InvalidTokenError has default message."""
        error = InvalidTokenError()

        assert "Invalid token" in str(error)

    def test_custom_reason(self) -> None:
        """InvalidTokenError accepts custom message."""
        error = InvalidTokenError(reason="Signature verification failed")

        assert error.reason == "Signature verification failed"
        assert "Signature verification failed" in str(error)


class TestTokenExpiredError:
    """Tests for TokenExpiredError."""

    def test_inherits_from_token_error(self) -> None:
        """TokenExpiredError inherits from TokenError."""
        error = TokenExpiredError()
        assert isinstance(error, TokenError)

    def test_message(self) -> None:
        """TokenExpiredError has correct message."""
        error = TokenExpiredError()

        assert "expired" in str(error).lower()


class TestTokenRevokedError:
    """Tests for TokenRevokedError."""

    def test_inherits_from_token_error(self) -> None:
        """TokenRevokedError inherits from TokenError."""
        error = TokenRevokedError()
        assert isinstance(error, TokenError)

    def test_message(self) -> None:
        """TokenRevokedError has correct message."""
        error = TokenRevokedError()

        assert "revoked" in str(error).lower()


class TestInvalidTokenTypeError:
    """Tests for InvalidTokenTypeError."""

    def test_inherits_from_token_error(self) -> None:
        """InvalidTokenTypeError inherits from TokenError."""
        error = InvalidTokenTypeError(expected="access", actual="refresh")
        assert isinstance(error, TokenError)

    def test_stores_expected_and_actual(self) -> None:
        """InvalidTokenTypeError stores expected and actual."""
        error = InvalidTokenTypeError(expected="access", actual="refresh")

        assert error.expected == "access"
        assert error.actual == "refresh"

    def test_message(self) -> None:
        """InvalidTokenTypeError contains expected and actual in message."""
        error = InvalidTokenTypeError(expected="access", actual="refresh")

        assert "access" in str(error)
        assert "refresh" in str(error)
