from .base_domain import DomainError


class UserNotFoundError(DomainError):
    """User not found."""

    def __init__(self, identifier: str):
        self.identifier = identifier
        super().__init__(f"User not found: {identifier}")


class UserAlreadyExistsError(DomainError):
    """User with this login already exists."""

    def __init__(self, login: str):
        self.login = login
        super().__init__(f"User already exists with login: {login}")


class UserInactiveError(DomainError):
    """User is inactive."""

    def __init__(self, user_id: str):
        self.user_id = user_id
        super().__init__(f"User is inactive: {user_id}")
