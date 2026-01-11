from dataclasses import dataclass


@dataclass(frozen=True, slots=True, kw_only=True)
class LogoutUserCommand:
    """Command for user logout."""

    refresh_token: str
