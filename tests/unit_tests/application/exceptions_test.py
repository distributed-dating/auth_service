"""Tests for application exceptions."""

import pytest

from auth_service.application.exceptions import (
    ApplicationError,
    InvalidCredentialsError,
    UserInactiveError,
)


class TestApplicationError:
    """Tests for base ApplicationError."""

    def test_is_exception(self) -> None:
        """ApplicationError should be an Exception."""
        assert issubclass(ApplicationError, Exception)

    def test_can_be_raised(self) -> None:
        """ApplicationError can be raised and caught."""
        with pytest.raises(ApplicationError):
            raise ApplicationError("test error")


class TestInvalidCredentialsError:
    """Tests for InvalidCredentialsError."""

    def test_inherits_from_application_error(self) -> None:
        """Should inherit from ApplicationError."""
        assert issubclass(InvalidCredentialsError, ApplicationError)

    def test_default_message(self) -> None:
        """Should have default message."""
        error = InvalidCredentialsError()
        assert str(error) == "Invalid login or password"


class TestUserInactiveError:
    """Tests for UserInactiveError."""

    def test_inherits_from_application_error(self) -> None:
        """Should inherit from ApplicationError."""
        assert issubclass(UserInactiveError, ApplicationError)

    def test_stores_user_id(self) -> None:
        """Should store user_id."""
        user_id = "123e4567-e89b-12d3-a456-426614174000"
        error = UserInactiveError(user_id)

        assert error.user_id == user_id
        assert user_id in str(error)
