"""User domain events."""

from dataclasses import dataclass, field
from uuid import UUID, uuid4

from auth_service.domain.events.base import DomainEvent


@dataclass(frozen=True)
class UserEvent(DomainEvent):
    """Base class for user-related domain events."""

    user_id: UUID = field(default_factory=uuid4)

    def to_dict(self) -> dict:
        """Serialize event to dictionary."""
        base = super().to_dict()
        base["user_id"] = str(self.user_id)
        return base


@dataclass(frozen=True)
class UserCreatedEvent(UserEvent):
    """
    Event published when a new user is registered.

    Contains user_id and login for downstream services
    that need to react to user registration.
    """

    login: str = ""

    @property
    def event_type(self) -> str:
        return "user.created"

    def to_dict(self) -> dict:
        """Serialize event to dictionary."""
        base = super().to_dict()
        base["login"] = self.login
        return base


@dataclass(frozen=True)
class UserActivatedEvent(UserEvent):
    """
    Event published when a user is activated.

    This can happen when an admin re-activates a previously
    deactivated user account.
    """

    @property
    def event_type(self) -> str:
        return "user.activated"


@dataclass(frozen=True)
class UserDeactivatedEvent(UserEvent):
    """
    Event published when a user is deactivated.

    This typically happens when an admin deactivates a user account,
    or when user requests account deactivation.
    """

    reason: str = ""

    @property
    def event_type(self) -> str:
        return "user.deactivated"

    def to_dict(self) -> dict:
        """Serialize event to dictionary."""
        base = super().to_dict()
        if self.reason:
            base["reason"] = self.reason
        return base
