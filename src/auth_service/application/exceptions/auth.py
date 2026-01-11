class ApplicationError(Exception):
    """Base exception for application layer."""

    pass


class InvalidCredentialsError(ApplicationError):
    """Invalid login or password."""

    def __init__(self) -> None:
        super().__init__("Invalid login or password")


class UserInactiveError(ApplicationError):
    """User account is deactivated."""

    def __init__(self, user_id: str) -> None:
        self.user_id = user_id
        super().__init__(f"User account is deactivated: {user_id}")
