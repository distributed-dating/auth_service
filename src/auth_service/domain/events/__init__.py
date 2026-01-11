"""Domain events module."""

__all__ = [
    "DomainEvent",
    "UserEvent",
    "UserCreatedEvent",
    "UserActivatedEvent",
    "UserDeactivatedEvent",
    "UserPasswordChangedEvent",
]

from .base import DomainEvent
from .user import (
    UserEvent,
    UserCreatedEvent,
    UserActivatedEvent,
    UserDeactivatedEvent,
)
