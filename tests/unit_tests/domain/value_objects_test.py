"""Unit тесты для Value Objects."""

import pytest

from auth_service.domain.value_objects import UserLogin, UserPassword
from auth_service.domain.exceptions import UserLoginError, UserPasswordError


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

    def test_create_login_with_underscore_raises_error(self) -> None:
        """Логин с подчёркиванием вызывает ошибку."""
        with pytest.raises(UserLoginError) as exc_info:
            UserLogin(value="user_test")

        assert "login must be alphanumeric" in str(exc_info.value)


class TestUserPassword:
    """Тесты для UserPassword Value Object."""

    def test_create_valid_password(self) -> None:
        """Создание валидного пароля."""
        password = UserPassword(value="testpass123")

        assert password.value == "testpass123"

    def test_create_valid_password_min_length(self) -> None:
        """Создание пароля минимальной длины."""
        password = UserPassword(value="abc")

        assert password.value == "abc"

    def test_create_valid_password_max_length(self) -> None:
        """Создание пароля максимальной длины."""
        password = UserPassword(value="a" * 15)

        assert password.value == "a" * 15

    def test_create_valid_password_alphanumeric(self) -> None:
        """Создание пароля с буквами и цифрами."""
        password = UserPassword(value="pass1234")

        assert password.value == "pass1234"

    def test_create_empty_password_raises_error(self) -> None:
        """Пустой пароль вызывает ошибку."""
        with pytest.raises(UserPasswordError) as exc_info:
            UserPassword(value="")

        assert "password must not be empty" in str(exc_info.value)

    def test_create_password_too_short_raises_error(self) -> None:
        """Пароль короче 3 символов вызывает ошибку."""
        with pytest.raises(UserPasswordError) as exc_info:
            UserPassword(value="ab")

        assert "password is too short" in str(exc_info.value)

    def test_create_password_too_long_raises_error(self) -> None:
        """Пароль длиннее 15 символов вызывает ошибку."""
        with pytest.raises(UserPasswordError) as exc_info:
            UserPassword(value="a" * 16)

        assert "password is too long" in str(exc_info.value)

    def test_create_password_with_special_chars_raises_error(self) -> None:
        """Пароль со специальными символами вызывает ошибку."""
        with pytest.raises(UserPasswordError) as exc_info:
            UserPassword(value="pass@123")

        assert "password must be alphanumeric" in str(exc_info.value)

    def test_create_password_with_spaces_raises_error(self) -> None:
        """Пароль с пробелами вызывает ошибку."""
        with pytest.raises(UserPasswordError) as exc_info:
            UserPassword(value="pass 123")

        assert "password must be alphanumeric" in str(exc_info.value)

    def test_create_password_with_underscore_raises_error(self) -> None:
        """Пароль с подчёркиванием вызывает ошибку."""
        with pytest.raises(UserPasswordError) as exc_info:
            UserPassword(value="pass_123")

        assert "password must be alphanumeric" in str(exc_info.value)
