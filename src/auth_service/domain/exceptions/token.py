from .base_domain import DomainError


class TokenError(DomainError):
    """Base token error."""

    pass


class InvalidTokenError(TokenError):
    """Invalid token (wrong signature, format, etc.)."""

    def __init__(self, reason: str = "Invalid token"):
        self.reason = reason
        super().__init__(reason)


class TokenExpiredError(TokenError):
    """Token has expired."""

    def __init__(self):
        super().__init__("Token has expired")


class TokenRevokedError(TokenError):
    """Token has been revoked."""

    def __init__(self):
        super().__init__("Token has been revoked")


class InvalidTokenTypeError(TokenError):
    """Invalid token type (access instead of refresh or vice versa)."""

    def __init__(self, expected: str, actual: str):
        self.expected = expected
        self.actual = actual
        super().__init__(f"Expected {expected} token, got {actual}")
