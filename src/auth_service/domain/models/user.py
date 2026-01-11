"""User Aggregate Root."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4

from auth_service.domain.events.user import (
    UserCreatedEvent,
    UserActivatedEvent,
    UserDeactivatedEvent,
)
from auth_service.domain.value_objects.user import (
    UserId,
    UserLogin,
    HashedPassword,
)
from auth_service.domain.events.base import DomainEvent


@dataclass(kw_only=True)
class User:
    """
    User Aggregate Root.

    Represents a user in the authentication system.
    Manages user state and generates domain events for significant changes.
    """

    id: UserId
    login: UserLogin
    hashed_password: HashedPassword
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    updated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    is_active: bool = True

    # Domain events storage (not persisted)
    _domain_events: list["DomainEvent"] = field(
        default_factory=list,
        repr=False,
        compare=False,
    )

    @classmethod
    def create(
        cls,
        login: UserLogin,
        hashed_password: HashedPassword,
    ) -> "User":
        """
        Factory method for creating a new user.

        Automatically registers a UserCreatedEvent.

        Args:
            login: User's login (validated UserLogin value object)
            hashed_password: Hashed password (HashedPassword value object)

        Returns:
            New User instance with UserCreatedEvent registered.
        """
        now = datetime.now(timezone.utc)
        user = cls(
            id=UserId(uuid4()),
            login=login,
            hashed_password=hashed_password,
            created_at=now,
            updated_at=now,
        )
        # Register creation event
        user._register_event(
            UserCreatedEvent(
                user_id=user.id.value,
                login=login.value,
            )
        )
        return user

    def change_password(self, new_hashed_password: HashedPassword) -> None:
        """
        Change user password.

        Registers a UserPasswordChangedEvent.

        Args:
            new_hashed_password: New hashed password.
        """
        self.hashed_password = new_hashed_password
        self.updated_at = datetime.now(timezone.utc)

    def deactivate(self, reason: str = "") -> None:
        """
        Deactivate user.

        Idempotent operation - does nothing if already deactivated.
        Registers a UserDeactivatedEvent.

        Args:
            reason: Optional reason for deactivation.
        """
        if not self.is_active:
            return  # Idempotent

        self.is_active = False
        self.updated_at = datetime.now(timezone.utc)
        self._register_event(
            UserDeactivatedEvent(
                user_id=self.id.value,
                reason=reason,
            )
        )

    def activate(self) -> None:
        """
        Activate user.

        Idempotent operation - does nothing if already active.
        Registers a UserActivatedEvent.
        """
        if self.is_active:
            return  # Idempotent

        self.is_active = True
        self.updated_at = datetime.now(timezone.utc)
        self._register_event(UserActivatedEvent(user_id=self.id.value))

    def _register_event(self, event: "DomainEvent") -> None:
        """
        Register a domain event.

        Events are accumulated and should be published after
        the aggregate is persisted.

        Args:
            event: Domain event to register.
        """
        self._domain_events.append(event)

    def pull_events(self) -> list["DomainEvent"]:
        """
        Pull and clear all accumulated domain events.

        This method should be called after the aggregate is persisted
        to get events for publishing.

        Returns:
            List of accumulated domain events.
        """
        events = self._domain_events.copy()
        self._domain_events.clear()
        return events

    def peek_events(self) -> list["DomainEvent"]:
        """
        Peek at accumulated domain events without clearing them.

        Useful for testing or debugging.

        Returns:
            Copy of accumulated domain events.
        """
        return self._domain_events.copy()

    @property
    def has_pending_events(self) -> bool:
        """Check if there are pending domain events."""
        return len(self._domain_events) > 0
