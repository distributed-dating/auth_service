from dataclasses import dataclass


@dataclass(frozen=True, slots=True, kw_only=True)
class VerifyTokenQuery:
    """Query for verifying access token."""

    access_token: str
