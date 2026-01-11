from .base_domain import DomainError


class UserNotFoundError(DomainError):
    """Пользователь не найден."""

    def __init__(self, identifier: str):
        self.identifier = identifier
        super().__init__(f"User not found: {identifier}")


class UserAlreadyExistsError(DomainError):
    """Пользователь с таким логином уже существует."""

    def __init__(self, login: str):
        self.login = login
        super().__init__(f"User already exists with login: {login}")


class UserInactiveError(DomainError):
    """Пользователь деактивирован."""

    def __init__(self, user_id: str):
        self.user_id = user_id
        super().__init__(f"User is inactive: {user_id}")
