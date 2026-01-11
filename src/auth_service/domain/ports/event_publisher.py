"""Port for publishing domain events to message queue."""

from typing import Protocol, Sequence

from auth_service.domain.events.base import DomainEvent


class EventPublisher(Protocol):
    """
    Port for publishing domain events.

    This interface defines how domain events are published to
    external message brokers (RabbitMQ, Kafka, etc.).

    The actual implementation lives in the infrastructure layer.
    """

    async def publish(self, event: DomainEvent) -> None:
        """
        Publish a single domain event.

        Args:
            event: The domain event to publish.
        """
        ...

    async def publish_many(self, events: Sequence[DomainEvent]) -> None:
        """
        Publish multiple domain events.

        Events are published in order. If publishing fails for an event,
        subsequent events may not be published (depends on implementation).

        Args:
            events: Sequence of domain events to publish.
        """
        ...
