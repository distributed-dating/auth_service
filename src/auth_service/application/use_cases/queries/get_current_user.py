from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, slots=True, kw_only=True)
class GetCurrentUserQuery:
    """Query for getting current user data."""

    user_id: UUID
