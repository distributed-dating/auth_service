"""Base classes for domain events."""

from abc import ABC
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID, uuid4


@dataclass(frozen=True)
class DomainEvent(ABC):
    """
    Base class for all domain events.

    Domain events represent something significant that happened in the domain.
    They are immutable and contain all information about what happened.
    """

    event_id: UUID = field(default_factory=uuid4)
    occurred_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @property
    def event_type(self) -> str:
        """
        Return the event type identifier.

        Override in subclasses to provide specific event type.
        Default implementation uses class name in snake_case format.
        """
        # Convert CamelCase to snake_case
        name = self.__class__.__name__
        result = []
        for i, char in enumerate(name):
            if char.isupper() and i > 0:
                result.append("_")
            result.append(char.lower())
        return "".join(result)

    def to_dict(self) -> dict:
        """
        Serialize event to dictionary for message queue publishing.

        Override in subclasses if custom serialization is needed.
        """
        return {
            "event_id": str(self.event_id),
            "event_type": self.event_type,
            "occurred_at": self.occurred_at.isoformat(),
        }
