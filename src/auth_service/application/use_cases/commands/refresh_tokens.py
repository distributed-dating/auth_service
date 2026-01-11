from dataclasses import dataclass


@dataclass(frozen=True, slots=True, kw_only=True)
class RefreshTokensCommand:
    """Command for refreshing token pair."""

    refresh_token: str
