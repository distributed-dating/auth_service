from .base_domain import DomainError


class TokenError(DomainError):
    """Базовая ошибка токена."""
    pass


class InvalidTokenError(TokenError):
    """Невалидный токен (неверная подпись, формат и т.д.)."""

    def __init__(self, reason: str = "Invalid token"):
        self.reason = reason
        super().__init__(reason)


class TokenExpiredError(TokenError):
    """Токен истёк."""

    def __init__(self):
        super().__init__("Token has expired")


class TokenRevokedError(TokenError):
    """Токен был отозван."""

    def __init__(self):
        super().__init__("Token has been revoked")


class InvalidTokenTypeError(TokenError):
    """Неверный тип токена (access вместо refresh или наоборот)."""

    def __init__(self, expected: str, actual: str):
        self.expected = expected
        self.actual = actual
        super().__init__(f"Expected {expected} token, got {actual}")
